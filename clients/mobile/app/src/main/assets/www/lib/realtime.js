/**
 * PWDSV 实时通知客户端（对接服务端 /notifications/hub）。
 *
 * 服务端使用 SignalR MessagePack 握手：
 *   1. 客户端连上 ws(s)://<host>/notifications/hub?access_token=<jwt>
 *   2. 发送文本帧：`{"protocol":"messagepack","version":1}\x1e`
 *   3. 服务端回 3 字节 `[0x7b, 0x7d, 0x1e]` 完成握手
 *   4. 后续密码/文件夹变更会下发包含 `ReceiveMessage` 的二进制帧，触发防抖增量同步
 */

import { buildWebSocketUrl } from "./api.js";

const HANDSHAKE = JSON.stringify({ protocol: "messagepack", version: 1 }) + "\x1e";
const TD = new TextDecoder("utf-8", { fatal: false });

export class RealtimeHub {
  /**
   * @param {{
   *   onSyncNeeded: () => void | Promise<void>,
   *   onForceLogout?: () => void | Promise<void>,
   *   WebSocketImpl?: typeof WebSocket,
   *   debounceMs?: number,
   * }} opts
   */
  constructor(opts) {
    this.onSyncNeeded = opts.onSyncNeeded;
    this.onForceLogout = opts.onForceLogout || null;
    this.WebSocketImpl = opts.WebSocketImpl || globalThis.WebSocket;
    this.debounceMs = opts.debounceMs ?? 600;

    this.ws = null;
    this.activeUrl = "";
    this.syncTimer = null;
    this.reconnectTimer = null;
    this.reconnectAttempts = 0;
    this.stopped = true;
    this.connectParams = null;
  }

  connect(serverUrl, accessToken) {
    if (!this.WebSocketImpl || !serverUrl || !accessToken) return;
    const targetUrl = buildWebSocketUrl(serverUrl, accessToken);
    if (!this.stopped && this.ws && this.activeUrl === targetUrl && this.ws.readyState <= 1) {
      return;
    }

    this.disconnect();
    this.stopped = false;
    this.connectParams = { serverUrl, accessToken };
    this.openSocket(targetUrl);
  }

  openSocket(targetUrl) {
    if (this.stopped) return;
    this.activeUrl = targetUrl;

    let socket;
    try {
      socket = new this.WebSocketImpl(targetUrl);
      socket.binaryType = "arraybuffer";
    } catch {
      this.scheduleReconnect();
      return;
    }

    this.ws = socket;

    socket.addEventListener("open", () => {
      this.reconnectAttempts = 0;
      try {
        socket.send(HANDSHAKE);
      } catch {
        /* 连接瞬间断开则交由 close 重试 */
      }
    });

    socket.addEventListener("message", (event) => {
      this.handleFrame(event.data);
    });

    socket.addEventListener("close", () => {
      if (this.ws === socket) this.ws = null;
      if (!this.stopped) this.scheduleReconnect();
    });

    socket.addEventListener("error", () => {
      /* close 事件会紧跟触发，统一在 close 里退避重连 */
    });
  }

  handleFrame(data) {
    if (!data) return;
    let bytes;
    if (data instanceof ArrayBuffer) {
      bytes = new Uint8Array(data);
    } else if (ArrayBuffer.isView(data)) {
      bytes = new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
    } else if (typeof data === "string") {
      bytes = new TextEncoder().encode(data);
    } else {
      return;
    }

    // 3 字节握手回包 `{}\x1e` 或极短 SignalR keepalive ping 直接忽略
    if (bytes.length <= 8) return;

    const text = TD.decode(bytes);
    if (!text.includes("ReceiveMessage")) return;

    // UpdateType::LogOut = 8，若收到服务端强制登出信号可立即锁库
    if (this.onForceLogout && text.includes("LogOut")) {
      this.onForceLogout();
      return;
    }

    this.triggerDebouncedSync();
  }

  triggerDebouncedSync() {
    if (this.syncTimer) clearTimeout(this.syncTimer);
    this.syncTimer = setTimeout(() => {
      this.syncTimer = null;
      Promise.resolve(this.onSyncNeeded?.()).catch(() => {});
    }, this.debounceMs);
  }

  scheduleReconnect() {
    if (this.stopped || !this.connectParams) return;
    if (this.reconnectTimer) clearTimeout(this.reconnectTimer);
    const delay = Math.min(30000, 1500 * 2 ** Math.min(this.reconnectAttempts, 4));
    this.reconnectAttempts++;
    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = null;
      if (!this.stopped && this.connectParams) {
        const url = buildWebSocketUrl(this.connectParams.serverUrl, this.connectParams.accessToken);
        this.openSocket(url);
      }
    }, delay);
  }

  disconnect() {
    this.stopped = true;
    this.connectParams = null;
    if (this.syncTimer) {
      clearTimeout(this.syncTimer);
      this.syncTimer = null;
    }
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    if (this.ws) {
      const s = this.ws;
      this.ws = null;
      try {
        s.close();
      } catch {
        /* 忽略关闭异常 */
      }
    }
  }
}
