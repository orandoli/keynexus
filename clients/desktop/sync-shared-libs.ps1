<#
.SYNOPSIS
  同步共享零知识加密/协议模块到桌面客户端 src/lib，并由品牌图标生成 Tauri 所需的 PNG 与标准多尺寸 ICO。
#>
$ErrorActionPreference = "Stop"
$scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
$repoRoot = (Resolve-Path (Join-Path $scriptDir "..\..")).Path
$extLibDir = Join-Path $repoRoot "tools\extension\src\lib"
$impLibDir = Join-Path $repoRoot "packages\importer-core\src"
$deskLibDir = Join-Path $scriptDir "src\lib"
$deskImpDir = Join-Path $deskLibDir "importer"
$iconOutDir = Join-Path $scriptDir "src-tauri\icons"
$sourcePng = (Resolve-Path (Join-Path $repoRoot "src\static\images\pwdsv-icon.png")).Path

Add-Type -AssemblyName System.Drawing

# 1. 同步共享 JS 核心库与多格式 AI 导密核心库
New-Item -ItemType Directory -Path $deskLibDir -Force | Out-Null
New-Item -ItemType Directory -Path $deskImpDir -Force | Out-Null
Copy-Item (Join-Path $extLibDir "*.js") -Destination $deskLibDir -Force
Copy-Item (Join-Path $impLibDir "*.js") -Destination $deskImpDir -Force

# 2. 生成 PNG 字节辅助函数
function Get-ResizedPngBytes {
    param([string]$From, [int]$Size)
    $img = [System.Drawing.Image]::FromFile($From)
    try {
        $bmp = New-Object System.Drawing.Bitmap($Size, $Size)
        try {
            $g = [System.Drawing.Graphics]::FromImage($bmp)
            try {
                $g.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
                $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::HighQuality
                $g.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
                $g.Clear([System.Drawing.Color]::Transparent)
                $g.DrawImage($img, 0, 0, $Size, $Size)
            } finally { $g.Dispose() }
            $ms = New-Object System.IO.MemoryStream
            $bmp.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)
            return ,$ms.ToArray()
        } finally { $bmp.Dispose() }
    } finally { $img.Dispose() }
}

New-Item -ItemType Directory -Path $iconOutDir -Force | Out-Null
foreach ($s in @(32, 128)) {
    $bytes = Get-ResizedPngBytes -From $sourcePng -Size $s
    [System.IO.File]::WriteAllBytes((Join-Path $iconOutDir "${s}x${s}.png"), $bytes)
}
$bytes256 = Get-ResizedPngBytes -From $sourcePng -Size 256
[System.IO.File]::WriteAllBytes((Join-Path $iconOutDir "128x128@2x.png"), $bytes256)

# 3. 封装合法的多尺寸 Windows ICO（内嵌 16/32/48/256 PNG 帧）
$icoSizes = @(16, 32, 48, 256)
$frames = New-Object 'System.Collections.Generic.List[byte[]]'
foreach ($sz in $icoSizes) {
    $frames.Add((Get-ResizedPngBytes -From $sourcePng -Size $sz))
}

$icoStream = New-Object System.IO.MemoryStream
$bw = New-Object System.IO.BinaryWriter($icoStream)
$bw.Write([uint16]0)                  # Reserved
$bw.Write([uint16]1)                  # Type = 1 (ICO)
$bw.Write([uint16]$icoSizes.Count)    # Count

$offset = 6 + (16 * $icoSizes.Count)
for ($i = 0; $i -lt $icoSizes.Count; $i++) {
    $sz = $icoSizes[$i]
    $data = $frames[$i]
    $dimByte = if ($sz -ge 256) { [byte]0 } else { [byte]$sz }
    $bw.Write($dimByte)               # Width
    $bw.Write($dimByte)               # Height
    $bw.Write([byte]0)                # ColorCount
    $bw.Write([byte]0)                # Reserved
    $bw.Write([uint16]1)              # Planes
    $bw.Write([uint16]32)             # BitCount
    $bw.Write([uint32]$data.Length)   # BytesInRes
    $bw.Write([uint32]$offset)        # ImageOffset
    $offset += $data.Length
}
$bw.Flush()
for ($i = 0; $i -lt $icoSizes.Count; $i++) {
    $d = $frames[$i]
    $icoStream.Write($d, 0, $d.Length)
}
[System.IO.File]::WriteAllBytes((Join-Path $iconOutDir "icon.ico"), $icoStream.ToArray())
$bw.Dispose()

Write-Host "已同步共享库并生成桌面端图标 ($iconOutDir)" -ForegroundColor Green
