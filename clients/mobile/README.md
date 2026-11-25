# PWDSV Android 手机客户端 (`clients/mobile/`)

PWDSV 的原生 Android 手机端工程（Kotlin + Jetpack WebViewAssetLoader + 系统级 `AutofillService`），与服务端、浏览器插件、Windows 桌面客户端共享同一套零知识加密内核与四态作用域协议。

## 核心特性

1. **四态密码切换与手机系统级自动填充（`PwdsvAutofillService`）**
   - 默认展示「📱 本机适用（手机专属 + 三端通用）」，顶部一键切看「🌐 三端通用 / 📱 手机专属 / 💻 电脑端 / 🕸 网页端 / 全部」。
   - 在系统设置启用 **PWDSV 密码自动填充** 后，打开任意手机 App 或浏览器登录框时直接在键盘候选栏弹出账号密码；在手机 App 内登录新账号后可自动捕获并提示保存。
2. **拍照识密码 & 多格式文件 AI 解析上传**
   - 支持 **直接调用摄像头拍照**（纸质手写密码本、电脑屏幕、路由器铭牌）或从手机文件管理器选择 **Excel `.xlsx` / Word `.docx` / PDF / CSV / TXT / JSON / 相册截图**。
   - **纯本机直连你配置的模型 API（不经过 PWDSV 服务器）**：内置 DeepSeek、通义千问、Gemini、OpenAI、Claude、硅基流动、Kimi、Ollama 模板，并支持**新增任意自定义模型提供商**（API Key 经 Android 硬件级 Keystore 加密存储）。
   - 解析后生成可视化核对卡片，支持逐条修改四态作用域后本地零知识加密批量上传服务器。
3. **本机安全防护**
   - 支持指纹 / 面容生物识别（`BiometricPrompt`）与本地短 PIN 秒开；复制密码使用 Android 13+ `EXTRA_IS_SENSITIVE` 隐私标记并在 30 秒后自动清空。

---

## 如何生成 APK 安装包

### 方式一：GitHub Actions 云端自动构建（免本机装 Android 环境）
推送代码后在仓库 Actions 页面运行 **Build PWDSV Android APK**（`.github/workflows/build-android.yml`），直接下载构建产物 `pwdsv-android-apk` 安装到手机。

### 方式二：Windows 本机一键拉取轻量 SDK 编译（无需安装完整 Android Studio）
```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools\setup-android-sdk.ps1
```
产物位于 `clients/mobile/app/build/outputs/apk/release/app-release.apk`。
