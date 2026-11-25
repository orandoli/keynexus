<#
.SYNOPSIS
  在本地 Windows 免安装完整 Android Studio，一键配置最小化 Android Command-Line SDK + Gradle 以编译 PWDSV 手机端 APK。
#>
$ErrorActionPreference = "Stop"
Add-Type -AssemblyName System.IO.Compression.FileSystem

# 优先使用本机 JDK 17/21 LTS（兼容 Android sdkmanager 与 Gradle 8.x）
if (-not $env:JAVA_HOME -or -not (Test-Path (Join-Path $env:JAVA_HOME "bin\java.exe"))) {
    foreach ($candidateJdk in @("D:\jdk", "C:\Program Files\Eclipse Adoptium\jdk-17", "C:\Program Files\Java\jdk-17")) {
        if (Test-Path (Join-Path $candidateJdk "bin\java.exe")) {
            $env:JAVA_HOME = $candidateJdk
            $env:PATH = "$(Join-Path $candidateJdk 'bin');$env:PATH"
            Write-Host "Using JAVA_HOME=$candidateJdk" -ForegroundColor Cyan
            break
        }
    }
}

$curlExe = "C:\Windows\System32\curl.exe"
function Download-Fast([string[]]$Urls, [string]$Dest) {
    foreach ($u in $Urls) {
        Write-Host "Downloading $u ..."
        & $curlExe -fL --connect-timeout 10 --retry 2 -o $Dest $u
        if ($LASTEXITCODE -eq 0 -and (Test-Path $Dest) -and (Get-Item $Dest).Length -gt 100000) {
            Write-Host "Downloaded $([Math]::Round((Get-Item $Dest).Length / 1MB, 1)) MB"
            return
        }
    }
    throw "Failed to download to $Dest"
}

$scriptDir = $PSScriptRoot
if (-not $scriptDir) { $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path }
$repoRoot = (Resolve-Path (Join-Path $scriptDir "..")).Path
$mobileDir = Join-Path $repoRoot "clients\mobile"

$sdkRoot = Join-Path $env:LOCALAPPDATA "Android\Sdk"
New-Item -ItemType Directory -Path $sdkRoot -Force | Out-Null
$sdkManager = Join-Path $sdkRoot "cmdline-tools\latest\bin\sdkmanager.bat"

if (-not (Test-Path $sdkManager)) {
    Write-Host "[1/3] 正在通过高速镜像下载 Android Command-Line Tools..." -ForegroundColor Cyan
    $tmpDir = Join-Path $sdkRoot ".tmp"
    if (Test-Path $tmpDir) { Remove-Item $tmpDir -Recurse -Force }
    New-Item -ItemType Directory -Path $tmpDir -Force | Out-Null
    $tmpZip = Join-Path $tmpDir "android-cmdline.zip"
    Download-Fast @(
        "https://mirrors.cloud.tencent.com/AndroidSDK/commandlinetools-win-11076708_latest.zip",
        "https://dl.google.com/android/repository/commandlinetools-win-11076708_latest.zip"
    ) $tmpZip
    $extractTmp = Join-Path $tmpDir "extract"
    [System.IO.Compression.ZipFile]::ExtractToDirectory($tmpZip, $extractTmp)
    $targetLatest = Join-Path $sdkRoot "cmdline-tools\latest"
    if (Test-Path $targetLatest) { Remove-Item $targetLatest -Recurse -Force }
    New-Item -ItemType Directory -Path (Split-Path $targetLatest) -Force | Out-Null
    Move-Item (Join-Path $extractTmp "cmdline-tools") $targetLatest -Force
    Remove-Item $tmpDir -Recurse -Force -ErrorAction SilentlyContinue
}

$env:ANDROID_HOME = $sdkRoot
$env:ANDROID_SDK_ROOT = $sdkRoot

if (-not (Test-Path (Join-Path $sdkRoot "platforms\android-35\android.jar")) -or -not (Test-Path (Join-Path $sdkRoot "build-tools\35.0.0\aapt2.exe"))) {
    Write-Host "[2/3] 正在安装 platforms;android-35 与 build-tools;35.0.0..." -ForegroundColor Cyan
    $yesLines = 1..30 | ForEach-Object { "y" }
    $yesLines | & $sdkManager --sdk_root="$sdkRoot" --licenses | Out-Null
    $yesLines | & $sdkManager --sdk_root="$sdkRoot" "platforms;android-35" "build-tools;35.0.0"
}

# 优先复用本机 ~/.gradle 已缓存的 Gradle 8.10.2
$cachedGradle = Get-ChildItem (Join-Path $env:USERPROFILE ".gradle\wrapper\dists\gradle-8.10.2-*") -Recurse -Filter "gradle.bat" -ErrorAction SilentlyContinue | Select-Object -First 1
if ($cachedGradle) {
    $gradleBin = $cachedGradle.FullName
    Write-Host "复用本机已缓存 Gradle: $gradleBin" -ForegroundColor Cyan
} else {
    $gradleRoot = Join-Path $env:LOCALAPPDATA "Gradle\gradle-8.10.2"
    $gradleBin = Join-Path $gradleRoot "bin\gradle.bat"
    if (-not (Test-Path $gradleBin)) {
        Write-Host "[3/3] 正在准备 Gradle 8.10.2..." -ForegroundColor Cyan
        $gParent = Join-Path $env:LOCALAPPDATA "Gradle"
        New-Item -ItemType Directory -Path $gParent -Force | Out-Null
        $gZip = Join-Path $gParent "gradle-8.10.2.zip"
        Download-Fast @(
            "https://mirrors.cloud.tencent.com/gradle/gradle-8.10.2-bin.zip",
            "https://services.gradle.org/distributions/gradle-8.10.2-bin.zip"
        ) $gZip
        [System.IO.Compression.ZipFile]::ExtractToDirectory($gZip, $gParent)
        Remove-Item $gZip -Force -ErrorAction SilentlyContinue
    }
}

& powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $mobileDir "sync-mobile-assets.ps1")

$localProps = "sdk.dir=" + ($sdkRoot.Replace("\", "\\"))
[System.IO.File]::WriteAllText((Join-Path $mobileDir "local.properties"), $localProps + "`n")

Write-Host "环境就绪，开始编译 APK..." -ForegroundColor Green
Push-Location $mobileDir
try {
    & $gradleBin assembleRelease --no-daemon --console=plain
    $apkPath = Join-Path $mobileDir "app\build\outputs\apk\release\app-release.apk"
    if (-not (Test-Path $apkPath)) { throw "未找到生成的 APK: $apkPath" }
    Write-Host "APK_BUILD_SUCCESS: $apkPath" -ForegroundColor Green
} finally {
    Pop-Location
}
