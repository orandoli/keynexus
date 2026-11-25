# Local HTTPS for PWDSV

This local development setup keeps PWDSV on HTTP inside Docker and adds a Caddy TLS endpoint at `https://localhost:8443`.
Caddy creates a local certificate authority and stores it in the persistent `caddy_data` volume.

Set `PWDSV_DATA_VOLUME` to the existing Docker volume mounted at `/data`, then start this Compose file:

```powershell
$env:PWDSV_DATA_VOLUME = "<existing-pwdsv-data-volume>"
docker compose -f docker/local-https/compose.yaml up -d
```

Export Caddy's public root certificate for local trust setup:

```powershell
New-Item -ItemType Directory -Force "$env:LOCALAPPDATA\pwdsv" | Out-Null
docker cp pwdsv-caddy-https:/data/caddy/pki/authorities/local/root.crt "$env:LOCALAPPDATA\pwdsv\caddy-local-root.crt"
```

The browser must trust this root certificate before the local HTTPS site will load without a certificate error. Keep the root private key inside the `caddy_data` volume; only distribute the public `root.crt`.

To stop the HTTPS stack:

```powershell
docker compose -f docker/local-https/compose.yaml down
```

The named PWDSV data volume is external and is not deleted by Compose.

## Mounted Clients (Web / Desktop / Mobile / Extension)

Before starting Docker, run `powershell -NoProfile -ExecutionPolicy Bypass -File tools\publish-client-releases.ps1` from the repository root to populate `data/web-vault` and `data/client-releases`:

- **Web Client**: `https://localhost:8443/` (served from `data/web-vault`)
- **Update Manifest**: `https://localhost:8443/client-releases/latest.json`
- **Installers & Extension Zip**: `https://localhost:8443/client-releases/keynexus-*.{exe,apk,zip}`
