<#
.SYNOPSIS
  从指定 GitHub 仓库的最新 Release 拉取四端产物与 latest.json 同步到服务器 data 目录，并自动解压更新网页端目录 data\web-vault。
.EXAMPLE
  powershell -NoProfile -ExecutionPolicy Bypass -File tools\sync-from-github-release.ps1 -Repo "yourname/keynexus"
#>
param(
  [Parameter(Mandatory = $true)]
  [string]$Repo,
  [string]$DataDir = "data"
)

$ErrorActionPreference = "Stop"
$scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
$repoRoot = (Resolve-Path (Join-Path $scriptDir "..")).Path
$baseData = if ([System.IO.Path]::IsPathRooted($DataDir)) { $DataDir } else { Join-Path $repoRoot $DataDir }
$relDir = Join-Path $baseData "client-releases"
$webDir = Join-Path $baseData "web-vault"

New-Item -ItemType Directory -Path $relDir -Force | Out-Null
New-Item -ItemType Directory -Path $webDir -Force | Out-Null

$cleanRepo = ($Repo.Trim() -replace '^https?://github\.com/', '' -replace '\.git$', '').Trim('/')
$apiUrl = "https://api.github.com/repos/$cleanRepo/releases/latest"
Write-Host "Fetching GitHub Release: $apiUrl" -ForegroundColor Cyan

$tmpJson = Join-Path $env:TEMP ("gh-release-" + [guid]::NewGuid().ToString("N") + ".json")
try {
  & C:\Windows\System32\curl.exe -sSL -H "Accept: application/vnd.github+json" -H "User-Agent: KeyNexus-Updater" $apiUrl -o $tmpJson
  if ($LASTEXITCODE -ne 0) { throw "Failed to query GitHub Release API" }
  $release = [System.IO.File]::ReadAllText($tmpJson, [System.Text.Encoding]::UTF8) | ConvertFrom-Json
} finally {
  Remove-Item $tmpJson -Force -ErrorAction SilentlyContinue
}

if (-not $release.tag_name) {
  throw "GitHub Release response missing tag_name (message: $($release.message))"
}

$ver = ($release.tag_name -replace '^[vV]', '').Trim()
$downloadedWebZip = $null
foreach ($asset in $release.assets) {
  $name = [string]$asset.name
  $dl = [string]$asset.browser_download_url
  if (-not $dl) { continue }
  $dst = Join-Path $relDir $name
  Write-Host "Downloading $name ..."
  & C:\Windows\System32\curl.exe -fSL -H "User-Agent: KeyNexus-Updater" $dl -o $dst
  if ($LASTEXITCODE -ne 0) { throw "Failed downloading $name" }
  if ($name -match 'web.*\.zip$') { $downloadedWebZip = $dst }
}

if ($downloadedWebZip -and (Test-Path $downloadedWebZip)) {
  Add-Type -AssemblyName System.IO.Compression.FileSystem
  Remove-Item (Join-Path $webDir "*") -Recurse -Force -ErrorAction SilentlyContinue
  [System.IO.Compression.ZipFile]::ExtractToDirectory($downloadedWebZip, $webDir)
  Write-Host "Extracted web client to $webDir" -ForegroundColor Green
}

$latestJsonPath = Join-Path $relDir "latest.json"
if (-not (Test-Path $latestJsonPath)) {
  $manifest = [ordered]@{
    publishedAt = [string]$release.published_at
    notes       = [string]$release.body
  }
  foreach ($f in (Get-ChildItem $relDir -File)) {
    $hash = (Get-FileHash -Path $f.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    $entry = [ordered]@{
      version = $ver
      url     = "/client-releases/$($f.Name)"
      sha256  = $hash
      size    = $f.Length
      notes   = [string]$release.body
    }
    if ($f.Name -match '\.apk$') { $manifest["mobile"] = $entry }
    elseif ($f.Name -match '\.(exe|msi)$') { $manifest["desktop"] = $entry }
    elseif ($f.Name -match 'ext.*\.zip$') { $manifest["extension"] = $entry }
    elseif ($f.Name -match 'web.*\.zip$') { $manifest["web"] = $entry }
  }
  $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
  [System.IO.File]::WriteAllText($latestJsonPath, ($manifest | ConvertTo-Json -Depth 5), $utf8NoBom)
  Write-Host "Generated $latestJsonPath from GitHub assets" -ForegroundColor Green
}

Write-Host "Synced GitHub Release v$ver -> $relDir" -ForegroundColor Cyan
