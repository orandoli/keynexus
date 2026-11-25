# PWDSV 生产环境一键编排（双网络模式 + 自动热备）

本目录提供开箱即用的三容器编排：
1. **`pwdsv`**：密码库核心服务（开启 `/notifications/hub` WebSocket 多端实时推送与客户端跨域支持）
2. **`caddy`**：自动 HTTPS 反向代理（支持 **公网域名正式证书** 与 **内网/Tailscale 自签证书** 两种模式）
3. **`backup`**：后台自动在线备份（默认每 24 小时调用 `/pwdsv backup` 将 SQLite 快照落盘至 `./backups/` 并保留 30 天）

---

## 第一步：一键生成 `.env` 与 `Caddyfile`

### 场景 A：你有公网域名（自动申请 Let's Encrypt 证书）

```powershell
# Windows
powershell -NoProfile -ExecutionPolicy Bypass -File tools\init-server.ps1 -Mode public -HostName vault.example.com
```

```bash
# Linux 服务器
bash tools/init-server.sh public vault.example.com
```

### 场景 B：纯局域网 IP 或 Tailscale 异地组网（自签可信根证书）

```powershell
# Windows
powershell -NoProfile -ExecutionPolicy Bypass -File tools\init-server.ps1 -Mode internal -HostName 100.88.1.2 -HttpsPort 8443
```

```bash
# Linux 服务器
bash tools/init-server.sh internal 100.88.1.2 8443
```

---

## 第二步：构建并启动

```bash
docker compose -f docker/production/compose.yaml up -d --build
```

> **内网模式信任根证书**：首次启动后执行
> `docker cp pwdsv-caddy:/data/caddy/pki/authorities/local/root.crt ./pwdsv-root.crt`，
> 在你的 Windows 电脑双击安装到「受信任的根证书颁发机构」，浏览器插件与 Windows 桌面客户端即可无警告直连。

---

## 第三步：注册个人账号并锁死公开注册

1. 打开 `https://你的域名或IP`（或直接在桌面客户端/浏览器网页库）注册你自己的主账号。
2. 编辑 `docker/production/.env`，将 `SIGNUPS_ALLOWED=true` 改为 `SIGNUPS_ALLOWED=false`，执行：
   ```bash
   docker compose -f docker/production/compose.yaml up -d
   ```
   从此你的密码服务器只归你自己使用。
