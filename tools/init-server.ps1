<#
.SYNOPSIS
  一键初始化 PWDSV 服务端配置（支持「公网域名 Let's Encrypt」与「内网/Tailscale 自签证书」双模式）。

.EXAMPLE
  # 模式 1：公网域名自动申请正式 HTTPS 证书
  powershell -NoProfile -ExecutionPolicy Bypass -File tools\init-server.ps1 -Mode public -HostName vault.example.com

  # 模式 2：局域网 IP 或 Tailscale 异地组网 IP（默认走 8443 端口 + Caddy 本地根证书）
  powershell -NoProfile -ExecutionPolicy Bypass -File tools\init-server.ps1 -Mode internal -HostName 100.88.1.2 -HttpsPort 8443
#>
[CmdletBinding()]
param(
    [ValidateSet("public", "internal")]
    [string]$Mode = "public",
    [Parameter(Mandatory = $true)]
    [string]$HostName,
    [int]$HttpPort = 80,
    [int]$HttpsPort = 443,
    [string]$AdminPassword = "",
    [bool]$AllowSignups = $true
)

$ErrorActionPreference = "Stop"
$scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
$repoRoot = (Resolve-Path (Join-Path $scriptDir "..")).Path
$prodDir = Join-Path $repoRoot "docker\production"

# 1. 若未指定管理员密码，自动生成 24 位随机高强度密码
if (-not $AdminPassword) {
    $chars = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#%^&*-_=+"
    $bytes = New-Object byte[] 24
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    $sb = New-Object System.Text.StringBuilder
    foreach ($b in $bytes) { [void]$sb.Append($chars[$b % $chars.Length]) }
    $AdminPassword = $sb.ToString()
}

# 2. 调用 tools\hash-admin.mjs 生成标准 Argon2id PHC 字符串 ($argon2id$v=19$m=19456,t=2,p=1$...)
$hashScript = Join-Path $scriptDir "hash-admin.mjs"
$env:PWDSV_INIT_ADMIN_PWD = $AdminPassword
try {
    $phc = & node $hashScript
    if ($LASTEXITCODE -ne 0 -or -not $phc.StartsWith('$argon2id$')) {
        throw "生成 Argon2id PHC 失败"
    }
} finally {
    Remove-Item Env:PWDSV_INIT_ADMIN_PWD -ErrorAction SilentlyContinue
}

# 3. 选择对应的 Caddyfile 模板
$sourceCaddy = if ($Mode -eq "public") {
    Join-Path $prodDir "Caddyfile.public"
} else {
    Join-Path $prodDir "Caddyfile.internal"
}
Copy-Item $sourceCaddy -Destination (Join-Path $prodDir "Caddyfile") -Force

$portSuffix = if ($HttpsPort -eq 443) { "" } else { ":$HttpsPort" }
$domainUrl = "https://$HostName$portSuffix"
$signupStr = if ($AllowSignups) { "true" } else { "false" }

$envContent = @(
    "# 自动生成于 $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') (模式: $Mode)",
    "DOMAIN=$domainUrl",
    "CADDY_HOST=$HostName",
    "HTTP_PORT=$HttpPort",
    "HTTPS_PORT=$HttpsPort",
    "SIGNUPS_ALLOWED=$signupStr",
    "WEBSOCKET_ENABLED=true",
    "ALLOWED_CLIENT_ORIGINS=chrome-extension://*,tauri://localhost,http://tauri.localhost,https://tauri.localhost",
    "ADMIN_TOKEN=$phc",
    "BACKUP_INTERVAL_SECONDS=86400",
    "BACKUP_KEEP_DAYS=30"
) -join "`n"

$envPath = Join-Path $prodDir ".env"
[System.IO.File]::WriteAllText($envPath, $envContent + "`n", (New-Object System.Text.UTF8Encoding($false)))

Write-Host ""
Write-Host "PWDSV 服务端配置已生成 ($Mode 模式)" -ForegroundColor Green
Write-Host "  配置文件   : $envPath"
Write-Host "  服务地址   : $domainUrl"
Write-Host "  管理后台   : $domainUrl/admin"
Write-Host "  管理员密码 : $AdminPassword   (请妥善保存！已转为 Argon2id 哈希写入 .env)" -ForegroundColor Yellow
Write-Host ""
Write-Host "启动命令："
Write-Host "  docker compose -f docker/production/compose.yaml up -d --build"
if ($Mode -eq "internal") {
    Write-Host ""
    Write-Host "内网/Tailscale 模式首次启动后导出根证书并在客户端安装受信任根证书：" -ForegroundColor Cyan
    Write-Host "  docker cp pwdsv-caddy:/data/caddy/pki/authorities/local/root.crt ./pwdsv-root.crt"
}
