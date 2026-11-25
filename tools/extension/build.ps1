<#
.SYNOPSIS
  打包 PWDSV 浏览器插件：生成 16/32/48/128 图标，同步回源码目录与 dist，并打包成 zip。

.DESCRIPTION
  兼容 Windows PowerShell 5.1 (powershell) 与 PowerShell 7+ (pwsh)：
    powershell -NoProfile -ExecutionPolicy Bypass -File tools\extension\build.ps1
#>
[CmdletBinding()]
param(
    [string]$OutputDir = "",
    [string]$SourceIcon = ""
)

$ErrorActionPreference = "Stop"
$scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
if (-not $OutputDir) { $OutputDir = Join-Path $scriptDir "dist" }
if (-not $SourceIcon) { $SourceIcon = Join-Path $scriptDir "..\..\src\static\images\pwdsv-icon.png" }

Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.IO.Compression.FileSystem

function New-ExtensionIcon {
    param([string]$From, [int]$Size, [string]$To)

    $image = [System.Drawing.Image]::FromFile($From)
    try {
        $bitmap = New-Object System.Drawing.Bitmap($Size, $Size)
        try {
            $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
            try {
                $graphics.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
                $graphics.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::HighQuality
                $graphics.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
                $graphics.Clear([System.Drawing.Color]::Transparent)
                $graphics.DrawImage($image, 0, 0, $Size, $Size)
            } finally { $graphics.Dispose() }
            $bitmap.Save($To, [System.Drawing.Imaging.ImageFormat]::Png)
        } finally { $bitmap.Dispose() }
    } finally { $image.Dispose() }
}

if (-not (Test-Path $SourceIcon)) {
    throw "找不到图标源文件：$SourceIcon"
}
$resolvedSource = (Resolve-Path $SourceIcon).Path

# 1. 先在源码树 src\icons 下生成正式图标，方便直接「加载已解压的扩展程序」也有品牌图标
$srcIconDir = Join-Path $scriptDir "src\icons"
New-Item -ItemType Directory -Path $srcIconDir -Force | Out-Null
foreach ($size in 16, 32, 48, 128) {
    New-ExtensionIcon -From $resolvedSource -Size $size -To (Join-Path $srcIconDir "$size.png")
}

# 2. 准备 dist 目录并拷贝源码（跳过测试与构建产物）
$stage = Join-Path $OutputDir "pwdsv-extension"
if (Test-Path $stage) { Remove-Item $stage -Recurse -Force }
New-Item -ItemType Directory -Path $stage -Force | Out-Null

$exclude = @("test", "dist", "build.ps1", "README.md")
foreach ($item in Get-ChildItem -Path $scriptDir -Force) {
    if ($exclude -contains $item.Name) { continue }
    Copy-Item $item.FullName -Destination $stage -Recurse -Force
}

# 3. 确认 manifest 图标字段并读取版本号
$manifestPath = Join-Path $stage "manifest.json"
$manifest = Get-Content $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
$version = $manifest.version

# 4. 打 zip 包（使用 .NET ZipFile，避免无交互终端下 Compress-Archive 的 Write-Progress 报错）
$zip = Join-Path $OutputDir "pwdsv-extension-$version.zip"
if (Test-Path $zip) { Remove-Item $zip -Force }
[System.IO.Compression.ZipFile]::CreateFromDirectory($stage, $zip)

Write-Host "打包完成：" -ForegroundColor Green
Write-Host "  目录   $stage"
Write-Host "  压缩包 $zip"
