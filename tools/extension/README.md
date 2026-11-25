# PWDSV 浏览器插件 (v2.0)

PWDSV 的 Chrome / Edge 扩展（Manifest V3）。直连你自己的 PWDSV 服务器，与 Windows 桌面客户端、网页端实时互通：

- **自动记密码**：访问网站登录、注册、两步登录（先输账号点下一步再输密码）或改密码时，跨页面跳转后依然精准弹出「保存 / 更新已有密码」提示，旧密码自动归入历史记录
- **下次登录主动提示**：打开存有密码的网站，输入框右侧自动浮现 `🔑` 角标，页面右上角给出「一键填充」轻提示（支持 SPA 动态弹窗与同源 `<iframe>` 登录框）
- **随时自己提交与管理密码**：弹窗内置完整的「＋ 记密码 / 编辑 / 删除」功能，支持绑定网站网址与 `app://进程名.exe` 桌面应用规则
- **TOTP 自动填入与倒计时**：聚焦或弹出两步验证码框时直接算码填入，无需经过剪贴板
- **WebSocket 实时同步**：自动连接服务端 `/notifications/hub`，桌面端或网页端修改密码后秒级无感同步

---

## 安装与打包

### 方式一：开发者模式直接加载（自带正式品牌图标）

1. 打开 `chrome://extensions`，右上角开启「开发者模式」
2. 点击「加载已解压的扩展程序」，选择目录：`tools/extension`
3. 点击工具栏 PWDSV 图标 → 填入服务器地址（如 `https://vault.example.com`）、邮箱与主密码解锁

### 方式二：打包成 zip 分发

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools\extension\build.ps1
```

产物位于 `tools/extension/dist/`：
- `pwdsv-extension/`：可直接加载的干净目录
- `pwdsv-extension-2.0.0.zip`：标准扩展压缩包

---

## 自测

```powershell
node tools/extension/test/run-all.mjs
```

共覆盖 5 套自动化测试（91 项断言）：
1. `crypto.test.mjs`：Bitwarden 官方 SDK 向量（PBKDF2 / HKDF / AES-256-CBC-HMAC / Argon2id）与 RSA-OAEP (type 3/4) 组织密钥解包
2. `util.test.mjs`：RFC 6238 TOTP、域名匹配策略、桌面应用 `app://` 通配规则、密码生成器
3. `e2e.test.mjs`：完整协议往返（预登录 → 多方式 2FA → 同步解密 → 新建 → 改密保留历史密码 → 删除）
4. `background.test.mjs`：Service Worker 接线（跨站点全局搜索、分步跨页抓密、恶意跨域 iframe 拦截、WebSocket 实时推送同步）
5. `debug_argon2.mjs`：Argon2id 小参数块级对照
