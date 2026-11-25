<#
.SYNOPSIS
  同步共享零知识加密内核与多格式 AI 导密模块到 Android 客户端 assets/www/lib，并生成各分辨率桌面启动图标。
#>
$ErrorActionPreference = "Stop"
$scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
$repoRoot = (Resolve-Path (Join-Path $scriptDir "..\..")).Path
$extLibDir = Join-Path $repoRoot "tools\extension\src\lib"
$impLibDir = Join-Path $repoRoot "packages\importer-core\src"
$mobLibDir = Join-Path $scriptDir "app\src\main\assets\www\lib"
$mobImpDir = Join-Path $mobLibDir "importer"
$resDir = Join-Path $scriptDir "app\src\main\res"
$sourcePng = (Resolve-Path (Join-Path $repoRoot "src\static\images\pwdsv-icon.png")).Path

Add-Type -AssemblyName System.Drawing

# 1. 同步共享 JS 核心模块
New-Item -ItemType Directory -Path $mobLibDir -Force | Out-Null
New-Item -ItemType Directory -Path $mobImpDir -Force | Out-Null
Copy-Item (Join-Path $extLibDir "*.js") -Destination $mobLibDir -Force
Copy-Item (Join-Path $impLibDir "*.js") -Destination $mobImpDir -Force

# 2. 生成 Android 各密度启动图标
$mipmaps = @{
    "mipmap-mdpi"    = 48
    "mipmap-hdpi"    = 72
    "mipmap-xhdpi"   = 96
    "mipmap-xxhdpi"  = 144
    "mipmap-xxxhdpi" = 192
}

$img = [System.Drawing.Image]::FromFile($sourcePng)
try {
    foreach ($kv in $mipmaps.GetEnumerator()) {
        $dir = Join-Path $resDir $kv.Key
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        $sz = $kv.Value
        $bmp = New-Object System.Drawing.Bitmap($sz, $sz)
        try {
            $g = [System.Drawing.Graphics]::FromImage($bmp)
            try {
                $g.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
                $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::HighQuality
                $g.Clear([System.Drawing.Color]::Transparent)
                $g.DrawImage($img, 0, 0, $sz, $sz)
            } finally { $g.Dispose() }
            $bmp.Save((Join-Path $dir "ic_launcher.png"), [System.Drawing.Imaging.ImageFormat]::Png)
        } finally { $bmp.Dispose() }
    }
} finally {
    $img.Dispose()
}

Write-Host "已同步 Android 客户端共享内核与启动图标 ($mobLibDir)" -ForegroundColor Green
