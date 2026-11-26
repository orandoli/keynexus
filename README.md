<p align="center">
  <img src="./resources/keynexus-logo.svg" alt="KeyNexus" width="380">
</p>

<p align="center">
  <b>KeyNexus</b> — 自托管的全栈零知识四端密码中枢（<b>Web 网页端 · Windows 桌面端 · Android 手机端 · Chrome / Edge 浏览器插件</b>）
</p>

<p align="center">
  <a href="https://github.com/orandoli/keynexus/releases/latest">下载最新四端发行版 (Releases)</a> ·
  <a href="https://github.com/orandoli/keynexus/actions">云端自动构建状态 (Actions)</a>
</p>

---

## 核心特性

1. **一核四端协同，清晰区分密码作用域（`pwdsvScope`）**
   - **`universal`（🌐 三端统一通用账户）**：同一套账号密码跨网页（`https://`）、电脑软件（`app://进程.exe`）、手机应用（`androidapp://包名`）互通共用，一端增改全端实时同步。
   - **`web`（🕸 网页端专属）** / **`desktop`（💻 电脑端专属）** / **`mobile`（📱 手机端专属）**：服务端原生存储、过滤并提供 `/api/pwdsv/scope-stats` 统计接口；各终端默认优先匹配当前端与通用密码，同时可随时切看全部条目。
2. **专属 Web 网页中枢与零知识注册管理**
   - 直接挂载于服务端首页 `/`，浏览器本地完成 PBKDF2 / Argon2id 密钥派生、随机 `userKey` 生成与 RSA-2048 密钥对加密，支持**零知识账号注册**（兼容两步验证注册及单步注册兜底）、四态工作台与同源四端安装包下载中心。
3. **独立 Authenticator 动态码竖栏（Web / Windows / Android）**
   - 三端均内置独立的 Authenticator 竖栏视图：圆环实时倒计时、`3+3` 大字号分格动态码、点击卡片一键复制、支持 `otpauth://` 一键解析与扫码导入。
4. **多格式文件识别 & AI 智能导密（支持自动模型检测）**
   - 支持 **CSV / Excel `.xlsx` / Word `.docx` / PDF / TXT / Markdown / JSON** 以及 **密码截图、手机拍照识图**。
   - **纯客户端直连 AI 模型**：内置 DeepSeek、通义千问、Google Gemini、OpenAI、Anthropic Claude、硅基流动、Kimi、本地 Ollama，以及任意自定义 OpenAI/Gemini/Claude 网关；填好 Base URL 与 API Key 后可**自动探测可用模型列表**并智能推荐文本与视觉模型。
   - 提取后先进入可编辑核对表与库内去重比对，确认后再在本地用 `userKey` 零知识加密导入。
5. **四端前端一键更新 & GitHub Actions 全自动云端发版**
   - 网页端、Windows 桌面端、Android 手机端与浏览器扩展支持填写 GitHub 仓库（`orandoli/keynexus`）或自托管 `/client-releases/latest.json` 检查新版与一键更新（桌面端与手机端支持 SHA-256 校验与原地安装更新）。
   - 推送任意 `v*` 标签（如 `v2.0.1`）即由 [release-all.yml](./.github/workflows/release-all.yml) 云端自动构建四端包、生成 `latest.json` 并发布为 Latest Release。
6. **全场景无感记录与智能填充**
   - **Chrome / Edge 插件**：支持普通表单、两步分步登录与改密跨页捕获提示；登录页自动显示输入框 `🔑` 角标与右上角一键填充条，自动计算填入 TOTP。
   - **Windows 桌面端（Tauri v2）**：Win32 前台进程监听 + 无焦点抢占悬浮提示卡（HUD），支持 `SendInput` 模拟键入、安全剪贴板与 Windows DPAPI + 短 PIN 秒开。
   - **Android 手机端（APK）**：接入系统级 `AutofillService` 自动填充与保存、指纹/面容生物识别解锁、Hardware Keystore 加密存储与扫码/拍照 AI 导密。

---

## 快速开始

### 1. 直接下载已发布的四端客户端

前往 **[Releases 页面](https://github.com/orandoli/keynexus/releases/latest)** 获取最新版本：
* `keynexus-windows-<ver>.exe`：Windows 桌面端
* `keynexus-android-<ver>.apk`：Android 手机端
* `keynexus-extension-<ver>.zip`：Chrome / Edge 浏览器扩展
* `keynexus-web-<ver>.zip`：可挂载至服务端 `/web-vault` 的网页端静态包
* `latest.json`：四端统一更新清单（含 SHA-256 校验值）

### 2. 服务端 Docker + Caddy 挂载部署

支持两种方式：
* **轻量镜像部署（推荐 1~2G 内存云主机）**：配合 `vaultwarden/server:latest` + Caddy，将 `keynexus-web-*.zip` 解压挂载到 `/web-vault`，将 `client-releases/` 挂载由 Caddy 提供 `/client-releases/*` 静态分发。
* **从源码构建部署**：
  ```powershell
  # 公网域名模式（自动申请 Let's Encrypt HTTPS）
  powershell -NoProfile -ExecutionPolicy Bypass -File tools\init-server.ps1 -Mode public -HostName vault.example.com

  # 内网 IP / Tailscale 模式（自动签发本地根证书）
  powershell -NoProfile -ExecutionPolicy Bypass -File tools\init-server.ps1 -Mode internal -HostName 100.88.1.2 -HttpsPort 8443

  # 同步网页端并启动容器
  powershell -NoProfile -ExecutionPolicy Bypass -File clients\web\sync-web-assets.ps1
  powershell -NoProfile -ExecutionPolicy Bypass -File tools\publish-client-releases.ps1
  docker compose -f docker/production/compose.yaml up -d --build
  ```

### 3. 本地打包与云端自动发版

* **浏览器插件**：打开 `chrome://extensions`（或 `edge://extensions`）→ 开启「开发者模式」→ 加载 `tools/extension/dist/pwdsv-extension`；重打包命令：
  ```powershell
  powershell -NoProfile -ExecutionPolicy Bypass -File tools\extension\build.ps1
  ```
* **Android 手机端**：本地命令行构建（详见 [clients/mobile/README.md](./clients/mobile/README.md)）：
  ```powershell
  powershell -NoProfile -ExecutionPolicy Bypass -File tools\setup-android-sdk.ps1
  ```
* **Windows 桌面端**（详见 [clients/desktop/README.md](./clients/desktop/README.md)）：
  ```powershell
  powershell -NoProfile -ExecutionPolicy Bypass -File clients\desktop\sync-shared-libs.ps1
  cargo +stable build --release --manifest-path clients/desktop/src-tauri/Cargo.toml
  ```
* **一键云端编译四端并发布 GitHub Release**：更新版本号后打标签并推送即可：
  ```bash
  git tag -a v2.0.2 -m "KeyNexus v2.0.2" && git push origin v2.0.2
  ```

---

## 目录结构

```text
src/                        # Rust 核心服务端（兼容 Bitwarden API + 四态 pwdsvScope 扩展）
packages/importer-core/     # 跨端共享：多格式文件提取 + 多协议 AI 提供商路由器 & 模型自动检测
clients/
├── web/                    # KeyNexus 浏览器网页中枢（挂载于 /，含零知识注册与四端下载中心）
├── desktop/                # Windows 桌面端（Tauri v2：Win32 监听 HUD + Authenticator + 自更新）
└── mobile/                 # Android 手机端（AutofillService + Keystore + Authenticator + 应用内更新）
tools/
├── extension/              # Chrome / Edge 浏览器插件（MV3）
├── publish-client-releases.ps1     # 同步网页端、打包四端产物并生成 data/client-releases/latest.json
├── sync-from-github-release.ps1    # 一键从 GitHub Releases 同步四端产物与网页包
├── init-server.ps1 / .sh   # 服务端双模式初始化脚本
└── setup-android-sdk.ps1   # Android 本地命令行编译脚本
docker/production/          # 生产级 Caddy HTTPS + 静态四端分发 + 自动备份编排
.github/workflows/          # release-all.yml 四端全自动云端编译发版工作流
```

---

## 自动化测试

```powershell
# 1. 多格式文件提取、AI 模型探测与多协议路由测试
node packages/importer-core/test/importer.test.mjs

# 2. 加解密原语、TOTP、跨端匹配、注册与更新检查 5 组全量测试
node tools/extension/test/run-all.mjs
```

---

## 许可证

遵循 **AGPL-3.0-only** 许可证（见 [`LICENSE.txt`](./LICENSE.txt) 与 [`NOTICE`](./NOTICE)）。
