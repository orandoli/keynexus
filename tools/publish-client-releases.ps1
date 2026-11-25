<#
.SYNOPSIS
  打包汇总三端产物并生成服务端自托管更新清单 data/client-releases/latest.json（含 SHA-256 校验值）。
#>
param(
  [string]$OutDir = "data\client-releases",
  [string]$WebVaultOutDir = "data\web-vault",
  [string]$Notes = "日常功能更新与安全优化",
  [string]$MobileApk = "",
  [string]$DesktopExe = "",
  [string]$ExtensionZip = ""
)

$ErrorActionPreference = "Stop"
$scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
$repoRoot = (Resolve-Path (Join-Path $scriptDir "..")).Path

$webSyncScript = Join-Path $repoRoot "clients\web\sync-web-assets.ps1"
if (Test-Path $webSyncScript) {
  & powershell -NoProfile -ExecutionPolicy Bypass -File $webSyncScript -WebVaultOutDir $WebVaultOutDir
  if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}

$targetDir = if ([System.IO.Path]::IsPathRooted($OutDir)) { $OutDir } else { Join-Path $repoRoot $OutDir }
New-Item -ItemType Directory -Path $targetDir -Force | Out-Null

# 读取三端版本号
$gradleText = Get-Content (Join-Path $repoRoot "clients\mobile\app\build.gradle.kts") -Raw -Encoding UTF8
$mobileVer = if ($gradleText -match 'versionName\s*=\s*"([^"]+)"') { $Matches[1] } else { "2.0.0" }
$mobileCode = if ($gradleText -match 'versionCode\s*=\s*(\d+)') { [int]$Matches[1] } else { 200 }

$tauriConf = Get-Content (Join-Path $repoRoot "clients\desktop\src-tauri\tauri.conf.json") -Raw -Encoding UTF8 | ConvertFrom-Json
$desktopVer = if ($tauriConf.version) { [string]$tauriConf.version } else { "2.0.0" }

$extManifest = Get-Content (Join-Path $repoRoot "tools\extension\manifest.json") -Raw -Encoding UTF8 | ConvertFrom-Json
$extVer = if ($extManifest.version) { [string]$extManifest.version } else { "2.0.0" }

# 自动定位产物
if (-not $MobileApk) {
  $cand = Join-Path $repoRoot "clients\mobile\app\build\outputs\apk\release\app-release.apk"
  if (Test-Path $cand) { $MobileApk = $cand }
}
if (-not $DesktopExe) {
  $rel = Join-Path $repoRoot "clients\desktop\src-tauri\target\release\pwdsv-desktop.exe"
  $dbg = Join-Path $repoRoot "clients\desktop\src-tauri\target\debug\pwdsv-desktop.exe"
  if (Test-Path $rel) { $DesktopExe = $rel }
  elseif (Test-Path $dbg) { $DesktopExe = $dbg }
}
if (-not $ExtensionZip) {
  $extDir = Join-Path $repoRoot "tools\extension\dist"
  if (Test-Path $extDir) {
    $latestZip = Get-ChildItem $extDir -Filter "pwdsv-extension-*.zip" | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if ($latestZip) { $ExtensionZip = $latestZip.FullName }
  }
}

$manifest = [ordered]@{
  publishedAt = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
  notes       = $Notes
}

$webVaultDir = if ([System.IO.Path]::IsPathRooted($WebVaultOutDir)) { $WebVaultOutDir } else { Join-Path $repoRoot $WebVaultOutDir }
if (Test-Path $webVaultDir) {
  Add-Type -AssemblyName System.IO.Compression.FileSystem
  $webZipName = "keynexus-web-$desktopVer.zip"
  $webZipPath = Join-Path $targetDir $webZipName
  if (Test-Path $webZipPath) { Remove-Item $webZipPath -Force }
  [System.IO.Compression.ZipFile]::CreateFromDirectory($webVaultDir, $webZipPath, [System.IO.Compression.CompressionLevel]::Optimal, $false)
  $webHash = (Get-FileHash -Path $webZipPath -Algorithm SHA256).Hash.ToLowerInvariant()
  $manifest["web"] = [ordered]@{
    version = $desktopVer
    url     = "/client-releases/$webZipName"
    sha256  = $webHash
    size    = (Get-Item $webZipPath).Length
    notes   = $Notes
  }
  Write-Host "已写入 web: $webZipName (v$desktopVer, sha256=$webHash)" -ForegroundColor Green
} else {
  $manifest["web"] = [ordered]@{
    version = $desktopVer
    url     = "/"
    notes   = $Notes
  }
}

function Add-ReleaseEntry {
  param([string]$Key, [string]$SrcFile, [string]$DestName, [hashtable]$Extra)
  if (-not $SrcFile -or -not (Test-Path $SrcFile)) {
    Write-Warning "跳过 ${Key}：未找到产物文件 ($SrcFile)"
    return
  }
  $destPath = Join-Path $targetDir $DestName
  Copy-Item $SrcFile $destPath -Force
  $hash = (Get-FileHash -Path $destPath -Algorithm SHA256).Hash.ToLowerInvariant()
  $entry = [ordered]@{
    version = $Extra.version
    url     = "/client-releases/$DestName"
    sha256  = $hash
    size    = (Get-Item $destPath).Length
    notes   = $Notes
  }
  if ($Extra.ContainsKey("versionCode")) {
    $entry["versionCode"] = [int]$Extra.versionCode
  }
  $manifest[$Key] = $entry
  Write-Host "已写入 ${Key}: $DestName (v$($Extra.version), sha256=$hash)" -ForegroundColor Green
}

Add-ReleaseEntry -Key "mobile" -SrcFile $MobileApk -DestName "keynexus-android-$mobileVer.apk" -Extra @{
  version     = $mobileVer
  versionCode = $mobileCode
}
Add-ReleaseEntry -Key "desktop" -SrcFile $DesktopExe -DestName "keynexus-windows-$desktopVer.exe" -Extra @{
  version = $desktopVer
}
Add-ReleaseEntry -Key "extension" -SrcFile $ExtensionZip -DestName "keynexus-extension-$extVer.zip" -Extra @{
  version = $extVer
}

$json = $manifest | ConvertTo-Json -Depth 5
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText((Join-Path $targetDir "latest.json"), $json, $utf8NoBom)
Write-Host "已生成统一更新清单：$targetDir\latest.json" -ForegroundColor Cyan
