<p align="center">
  <img src="./resources/pwdsv-logo.svg" alt="PWDSV" width="360">
</p>

<p align="center">
  自托管的全栈零知识密码系统：<b>Rust 服务端 + 浏览器插件 + Windows 桌面端 + Android 手机端 + 多格式 AI 导密</b>。
</p>

---

## 核心特性

1. **一核四端，清晰区分密码适用范围（`pwdsvScope`）**
   - **`universal`（🌐 三端统一通用账户）**：同一套账号密码跨网页（`https://`）、电脑软件（`app://进程.exe`）、手机应用（`androidapp://包名`）互通共用，一端改密全端实时同步生效。
   - **`web`（🕸 网页端专属）** / **`desktop`（💻 电脑端专属）** / **`mobile`（📱 手机端专属）**：服务端原生存储、过滤并提供 `/api/pwdsv/scope-stats` 统计接口；各终端默认优先提示「本端专属 + 三端通用」密码，同时可随时切看其他端。
2. **多格式文件识别 & 可自定义提供商的 AI 智能导密**
   - 支持 **CSV / Excel `.xlsx` / Word `.docx` / PDF / TXT / Markdown / JSON** 以及 **密码截图、手机相机拍摄手写密码本/路由器铭牌**。
   - **纯客户端本地直连模型 API（不经过 PWDSV 服务器）**：内置 DeepSeek、通义千问、Google Gemini、OpenAI、Claude、硅基流动、Kimi、本地 Ollama 预设，并支持**自由新增任意自定义模型提供商**（自定义协议、Base URL、请求头、文本与视觉模型）。
   - 解析后生成**本地可编辑预览核对表**，确认无误后在本地用 `userKey` 零知识加密，调用 `/api/ciphers/import` 批量上传服务器。
3. **全场景无感记录与智能提示**
   - **浏览器插件（Chrome / Edge）**：支持普通登录、两步分步登录与改密跨页面捕获提示；下次打开登录页自动在输入框显示 `🔑` 角标与右上角一键填充提示，自动算码填入 TOTP。
   - **Windows 桌面端（Tauri v2）**：常驻托盘，打开已绑定 `.exe` 程序时右上角弹出**无焦点抢占悬浮提示卡（HUD）**，支持 `SendInput` 模拟键入与防 `Win+V` 泄漏安全剪贴板，支持本地短 PIN 双层加密秒开。
   - **Android 手机端（APK）**：接入 Android 系统级 `AutofillService` 自动填充与新密码捕获保存，支持拍照/选文件 AI 导密与指纹/面容生物识别解锁。

---

## 快速开始

### 1. 服务端一键部署（公网域名 / 内网自签双模式 + 每日热备）

```powershell
# 公网域名模式（自动申请 Let's Encrypt HTTPS）
powershell -NoProfile -ExecutionPolicy Bypass -File tools\init-server.ps1 -Mode public -HostName vault.example.com

# 内网 IP / Tailscale 模式（自动签发本地根证书）
powershell -NoProfile -ExecutionPolicy Bypass -File tools\init-server.ps1 -Mode internal -HostName 100.88.1.2 -HttpsPort 8443

# 构建并启动
docker compose -f docker/production/compose.yaml up -d --build
```

详见 [docker/production/README.md](./docker/production/README.md)。

### 2. 浏览器插件（`tools/extension/`）

- `chrome://extensions` → 开启「开发者模式」→「加载已解压的扩展程序」→ 选 `tools/extension`。
- 打包 zip：`powershell -NoProfile -ExecutionPolicy Bypass -File tools\extension\build.ps1`（见 [tools/extension/README.md](./tools/extension/README.md)）。

### 3. Windows 桌面客户端（`clients/desktop/`）

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File clients\desktop\sync-shared-libs.ps1
cargo +stable build --release --manifest-path clients/desktop/src-tauri/Cargo.toml
.\clients\desktop\src-tauri\target\release\pwdsv-desktop.exe
```

详见 [clients/desktop/README.md](./clients/desktop/README.md)。

### 4. Android 手机客户端（`clients/mobile/`）

- **云端免环境打包 APK**：推送仓库后运行 GitHub Actions 工作流 `.github/workflows/build-android.yml` 下载 `pwdsv-android-apk`。
- **Windows 本地命令行一键编译 APK**（免装完整 Android Studio）：
  ```powershell
  powershell -NoProfile -ExecutionPolicy Bypass -File tools\setup-android-sdk.ps1
  ```
- 详见 [clients/mobile/README.md](./clients/mobile/README.md)。

---

## 目录结构

```text
src/                        # PWDSV Rust 服务端（兼容 Bitwarden API + 四态 pwdsvScope 扩展）
packages/importer-core/     # 跨端共享：多格式文件提取 (.xlsx/.docx/.pdf/图片) + 自定义 AI 提供商路由器
clients/
├── desktop/                # Windows 桌面客户端（Tauri v2：应用启动监听 HUD + AI 导密台 + DPAPI）
└── mobile/                 # Android 手机客户端（Kotlin AutofillService + Keystore + 拍照 AI 导密）
tools/
├── extension/              # Chrome / Edge 浏览器插件（MV3）
├── init-server.ps1 / .sh   # 服务端双模式初始化脚本
└── setup-android-sdk.ps1   # Android 本地轻量命令行编译脚本
docker/production/          # 生产级 Caddy HTTPS + SQLite 自动备份编排
```

---

## 自动化测试与校验

```powershell
# 1. 多格式文件提取与多模型协议路由测试 (.xlsx / .docx / .pdf / 自定义网关 / Gemini / Claude)
node packages/importer-core/test/importer.test.mjs

# 2. 浏览器插件与共享加密/协议层 5 组测试
node tools/extension/test/run-all.mjs

# 3. Windows 桌面端编译与 Rust 单元测试
cargo +stable test --manifest-path clients/desktop/src-tauri/Cargo.toml
```

---

## 许可证

沿用 **AGPL-3.0-only** 许可证（见 [`LICENSE.txt`](./LICENSE.txt) 与 [`NOTICE`](./NOTICE)）。
