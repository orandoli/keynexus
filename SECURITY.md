# 安全策略

## 报告漏洞

请不要为安全问题开公开 issue。

- 邮件：`security@your-domain.tld`（改成本项目实际使用的邮箱）
- 或使用 GitHub 的私有漏洞报告（Security → Report a vulnerability）

报告里尽量带上：

- 受影响的版本或 commit（`pwdsv --version` 的输出）
- 复现步骤，越具体越好（请求路径、参数、请求头）
- 实际影响，比如能否越权读取他人密码库、能否绕过两步验证
- 如果是依赖库的问题，附上对应的 CVE 编号

## 响应流程

| 阶段 | 目标时间 |
| --- | --- |
| 确认收到 | 3 个工作日内 |
| 初步评估与影响范围 | 7 个工作日内 |
| 修复或缓解方案 | 视严重程度，一般 30 天内 |

修复发布后会在这里致谢报告者（除非要求匿名）。

## 部署方需要注意的点

- **必须走 HTTPS**。Web 密码库依赖安全上下文，明文部署等于把主密码暴露在链路上。
- **`ADMIN_TOKEN` 用 Argon2 PHC 字符串**，用 `pwdsv hash` 生成，不要用明文；不开放后台就留空。
- **公网实例关掉注册**：`SIGNUPS_ALLOWED=false`，需要加人时用邀请。
- **反向代理要传对客户端 IP**，否则限流会把所有人当成同一个 IP：配 `IP_HEADER` 与 `IP_HEADER_TRUSTED_PROXIES`。
- **必须备份的是 `db.sqlite3` + `rsa_key` + `attachments/` + `sends/`**，`icon_cache/` 可以丢。
- **`rsa_key` 泄露等于所有已签发令牌可被伪造**，备份文件不要放在 Web 可访问目录。
