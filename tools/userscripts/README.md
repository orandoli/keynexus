# 配套油猴脚本

这里放跟 PWDSV 配合使用的浏览器脚本，安装到 Chrome / Edge 的 Tampermonkey（油猴）里即可。

## totp-auto-paste.user.js

**TOTP Auto-Paste｜验证码自动填入** —— 聚焦验证码输入框时，自动把剪贴板里的 6 位 TOTP 填进去。

- 来源：GreasyFork #569887，作者 heliannuuthus，MIT 许可
- 上游：<https://github.com/heliannuuthus/blacksmith/tree/main/scripts/totp-auto-paste>
- 本地版本：原样分发，逻辑未改动

### 为什么要它

PWDSV 用的是 Bitwarden 客户端协议。在桌面端或浏览器插件里点「复制验证码」后，
TOTP 只进了系统剪贴板，到网页上还得手动 Ctrl+V。这个脚本把最后一步省掉：
点一下输入框，码自己进去。

### 和改名有没有关系

没有。它用 `@match *://*/*` 全站生效，判断依据是输入框的属性
（`autocomplete="one-time-code"`、`name*=totp`、`placeholder*=验证码` 等），
不认域名也不认页面品牌，所以项目从 Vaultwarden 改名成 PWDSV 之后不需要任何改动。

### 安装

1. 浏览器装 [Tampermonkey](https://www.tampermonkey.net/)（Chrome 应用商店可直接搜到）。
2. 打开 Tampermonkey 面板 →「实用工具」→「导入」→ 选这个 `.user.js` 文件；
   或者直接把文件拖进浏览器窗口，会自动弹出安装页。
3. 装完在「已安装脚本」里确认它处于启用状态。

### 使用前提

`navigator.clipboard.readText()` 需要页面处于聚焦状态并拿到剪贴板读取权限。
第一次触发时浏览器可能会问一次，允许即可；被拒绝时脚本静默跳过，不会报错、也不会清空输入框。

### 想改的话

选择器清单在文件顶部的 `SELECTORS` 数组里，按需加一条你自己的页面规则就行。
