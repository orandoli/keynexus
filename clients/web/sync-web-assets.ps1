<#
.SYNOPSIS
  Sync shared zero-knowledge modules & brand icons into clients/web/src and mirror to data/web-vault.
#>
param(
  [string]$WebVaultOutDir = "data\web-vault"
)

$ErrorActionPreference = "Stop"
$scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
$repoRoot = (Resolve-Path (Join-Path $scriptDir "..\..")).Path
$extLibDir = Join-Path $repoRoot "tools\extension\src\lib"
$impLibDir = Join-Path $repoRoot "packages\importer-core\src"
$webSrcDir = Join-Path $scriptDir "src"
$webLibDir = Join-Path $webSrcDir "lib"
$webImpDir = Join-Path $webLibDir "importer"

New-Item -ItemType Directory -Path $webLibDir -Force | Out-Null
New-Item -ItemType Directory -Path $webImpDir -Force | Out-Null
Copy-Item (Join-Path $extLibDir "*.js") -Destination $webLibDir -Force
Copy-Item (Join-Path $impLibDir "*.js") -Destination $webImpDir -Force

$iconSrc = Join-Path $repoRoot "src\static\images\pwdsv-icon.png"
$favSrc = Join-Path $repoRoot "src\static\images\pwdsv-favicon.png"
if (Test-Path $iconSrc) { Copy-Item $iconSrc (Join-Path $webSrcDir "brand-icon.png") -Force }
if (Test-Path $favSrc) { Copy-Item $favSrc (Join-Path $webSrcDir "favicon.png") -Force }

$targetWebVault = if ([System.IO.Path]::IsPathRooted($WebVaultOutDir)) { $WebVaultOutDir } else { Join-Path $repoRoot $WebVaultOutDir }
if (Test-Path $targetWebVault) {
  Remove-Item (Join-Path $targetWebVault "*") -Recurse -Force -ErrorAction SilentlyContinue
}
New-Item -ItemType Directory -Path $targetWebVault -Force | Out-Null
Copy-Item (Join-Path $webSrcDir "*") -Destination $targetWebVault -Recurse -Force

Write-Host "Web client synced to $webSrcDir and mirrored to $targetWebVault" -ForegroundColor Green
