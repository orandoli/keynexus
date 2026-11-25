# PWDSV Windows 桌面客户端 (Tauri v2)

专为 Windows 10/11 打造的轻量常驻密码守护客户端。安装包仅数 MB，与 PWDSV 服务端、Chrome/Edge 浏览器插件共用同一套零知识加密协议与实时同步通道。

## 核心能力

1. **打开指定桌面软件自动给密码提示（无抢焦点 HUD）**
   - 采用 Win32 `SetWinEventHook` 事件驱动监听前台应用启动（0% 轮询 CPU 开销）。
   - **Per-PID 会话去重防打扰**：软件启动时在右上角静默弹出一次密码提示卡，软件运行期间来回切换窗口**绝不重复弹窗**；关闭软件重开后自动恢复提示。
   - **无焦点抢占悬浮窗（`WS_EX_NOACTIVATE`）**：提示卡弹出时不会抢走原软件密码输入框的光标焦点。
2. **突破禁止粘贴的密码框 + 防 `Win+V` 剪贴板泄密**
   - **一键键入（Auto-Type）**：通过 Win32 `SendInput` 直接向目标窗口发送 Unicode 键盘流，支持「仅键入密码」或「账号 + Tab + 密码」。
   - **安全剪贴板**：复制密码时写入 `ExcludeClipboardContentFromMonitorProcessing` 与 `CanIncludeInClipboardHistory=0`，屏蔽系统 `Win+V` 历史记录与云剪贴板同步，默认 30 秒核对哈希后自动清空。
3. **主密码 + 本地短 PIN 快捷解锁**
   - 本地短 PIN 采用 **PBKDF2-HMAC-SHA256 (210,000 次) + AES-256-GCM + Windows DPAPI (`CryptProtectData`)** 双层加密保护；连续输错 5 次自动物理销毁本地快捷凭据。
4. **随时随地自己提交密码 & 可视化绑定运行中程序**
   - 新建/编辑密码时可直接从下拉框选择当前正在运行的 `.exe` 程序（可选附加窗口标题通配如 `*登录*`）。
   - 支持一键导入 Chrome / Edge / Bitwarden 导出的 CSV 密码表（全程本地加密后上传）。
   - **全局热键**：
     - `Ctrl + Alt + P`：立即识别当前前台程序并呼出右上角密码提示卡（未绑定时可一键为它新增密码）
     - `Ctrl + Alt + N`：呼出主窗口并为当前前台程序快速录入密码

---

## 构建与运行

```powershell
# 1. 若修改了 tools/extension/src/lib 下的共享加密模块，先同步一次：
powershell -NoProfile -ExecutionPolicy Bypass -File clients\desktop\sync-shared-libs.ps1

# 2. 运行单元测试与编译检查
cargo +stable test --manifest-path clients/desktop/src-tauri/Cargo.toml

# 3. 编译发布版可执行文件（产物位于 clients/desktop/src-tauri/target/release/pwdsv-desktop.exe）
cargo +stable build --release --manifest-path clients/desktop/src-tauri/Cargo.toml
```
