#!/usr/bin/env bash
set -euo pipefail

# 用法：
#   /opt/keynexus/refresh.sh
#   /opt/keynexus/refresh.sh orandoli/keynexus /opt/keynexus

REPO="${1:-orandoli/keynexus}"
BASE_DIR="${2:-/opt/keynexus}"
RELEASES_DIR="${BASE_DIR}/client-releases"
WEB_DIR="${BASE_DIR}/web-vault"

mkdir -p "$RELEASES_DIR" "$WEB_DIR"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

echo "[1/4] 正在查询 GitHub Release: https://api.github.com/repos/${REPO}/releases/latest ..."
curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" -o "${TMP_DIR}/release.json"

python3 - "${TMP_DIR}/release.json" "$RELEASES_DIR" "$WEB_DIR" "$TMP_DIR" <<'PY'
import datetime
import hashlib
import json
import pathlib
import re
import sys
import urllib.request
import zipfile

release_path, releases_dir_s, web_dir_s, tmp_dir_s = sys.argv[1:5]
releases_dir = pathlib.Path(releases_dir_s)
web_dir = pathlib.Path(web_dir_s)
tmp_dir = pathlib.Path(tmp_dir_s)

release = json.loads(pathlib.Path(release_path).read_text(encoding="utf-8"))
tag = str(release.get("tag_name") or "").strip()
ver = tag.lstrip("vV") or "2.0.1"
published_at = release.get("published_at") or datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
notes = (release.get("body") or f"KeyNexus {tag}").strip()
assets = release.get("assets") or []

def find_asset(patterns):
    for pat in patterns:
        for a in assets:
            name = str(a.get("name") or "")
            if re.search(pat, name, re.I):
                return a
    return None

wanted = {
    "web": find_asset([r"^keynexus-web-.*\.zip$", r"web.*\.zip$"]),
    "mobile": find_asset([r"^keynexus-android-.*\.apk$", r"\.apk$"]),
    "desktop": find_asset([r"^keynexus-windows-.*\.exe$", r"\.exe$", r"\.msi$"]),
    "extension": find_asset([r"^keynexus-extension-.*\.zip$", r"extension.*\.zip$", r"ext.*\.zip$"]),
    "manifest": find_asset([r"^latest\.json$"]),
}

remote_manifest = {}
if wanted["manifest"]:
    url = wanted["manifest"]["browser_download_url"]
    with urllib.request.urlopen(url, timeout=30) as resp:
        remote_manifest = json.loads(resp.read().decode("utf-8"))

# 仅清理旧版四端包，保留 keynexus-ca.crt 等自定义证书
for pat in ("keynexus-web-*.zip", "keynexus-windows-*.exe", "keynexus-android-*.apk", "keynexus-extension-*.zip"):
    for old in releases_dir.glob(pat):
        if old.is_file():
            old.unlink()

print(f"[2/4] 发现版本 {tag}，正在下载客户端产物...")
manifest = {
    "version": ver,
    "publishedAt": published_at,
    "notes": notes,
}

downloaded = {}
for key in ("web", "mobile", "desktop", "extension"):
    asset = wanted[key]
    if not asset:
        print(f"  - 跳过 {key}（该 Release 未附带）")
        continue
    name = asset["name"]
    url = asset["browser_download_url"]
    dst = releases_dir / name
    tmp_dst = tmp_dir / name
    print(f"  - 下载 {key}: {name}")
    req = urllib.request.Request(url, headers={"User-Agent": "KeyNexus-Server-Refresh/1.0"})
    with urllib.request.urlopen(req, timeout=180) as resp:
        data = resp.read()
    tmp_dst.write_bytes(data)
    dst.write_bytes(data)
    downloaded[key] = dst

    entry = {
        "version": ver,
        "fileName": name,
        "url": f"/client-releases/{name}",
        "sha256": hashlib.sha256(data).hexdigest(),
        "size": len(data),
        "notes": notes,
    }
    remote_entry = remote_manifest.get(key) if isinstance(remote_manifest, dict) else None
    if isinstance(remote_entry, dict) and remote_entry.get("versionCode"):
        entry["versionCode"] = int(remote_entry["versionCode"])
    elif key == "mobile":
        parts = [int(x) for x in re.findall(r"\d+", ver)[:3]]
        while len(parts) < 3:
            parts.append(0)
        entry["versionCode"] = parts[0] * 100 + parts[1] * 10 + parts[2]
    manifest[key] = entry

if "web" in downloaded:
    print("[3/4] 正在部署最新 Web 网页端到 web-vault（即时生效）...")
    for old_file in list(web_dir.rglob("*")):
        if old_file.is_file():
            old_file.unlink()
    with zipfile.ZipFile(downloaded["web"], "r") as zf:
        for member in zf.namelist():
            norm = member.replace("\\", "/").lstrip("/")
            if not norm or norm.endswith("/"):
                continue
            target = (web_dir / norm).resolve()
            if web_dir.resolve() not in target.parents and target != web_dir.resolve():
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(zf.read(member))
    print(f"  - 已解压 {len(list(web_dir.rglob('*.js')))} 个 JS 文件到 {web_dir}")

(releases_dir / "latest.json").write_text(
    json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
    encoding="utf-8",
)
print(f"[4/4] 已更新 {releases_dir / 'latest.json'} -> 当前版本 v{ver}")
PY

if command -v curl >/dev/null 2>&1; then
  echo "--- 本地 HTTPS 端口自检 ---"
  curl -skI --resolve 152.32.234.200:8443:127.0.0.1 https://152.32.234.200:8443/ | head -n 3 || true
  curl -skI --resolve 152.32.234.200:8443:127.0.0.1 https://152.32.234.200:8443/client-releases/latest.json | head -n 3 || true
fi
