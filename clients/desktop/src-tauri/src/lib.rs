pub mod pin_store;
pub mod win_platform;

use std::{collections::HashMap, fs, process::Command, sync::Mutex, time::Duration};

use once_cell::sync::Lazy;
use reqwest::Method;
use ring::digest;
use serde::{Deserialize, Serialize};
use tauri::{
    menu::{Menu, MenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    AppHandle, Emitter, Manager, WindowEvent,
};

use crate::win_platform::{AppWatchRule, RunningAppInfo};

static LATEST_HUD_PAYLOAD: Lazy<Mutex<Option<serde_json::Value>>> = Lazy::new(|| Mutex::new(None));

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HttpProxyRequest {
    pub url: String,
    pub method: String,
    pub headers: HashMap<String, String>,
    pub body: Option<String>,
    pub insecure_tls: bool,
}

#[derive(Debug, Serialize)]
pub struct HttpProxyResponse {
    pub status: u16,
    pub body: String,
}

#[tauri::command]
async fn http_request(req: HttpProxyRequest) -> Result<HttpProxyResponse, String> {
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(req.insecure_tls)
        .timeout(Duration::from_secs(20))
        .build()
        .map_err(|e| format!("创建 HTTP 客户端失败: {e}"))?;

    let method = Method::from_bytes(req.method.as_bytes()).unwrap_or(Method::GET);
    let mut builder = client.request(method, &req.url);
    for (k, v) in req.headers {
        builder = builder.header(&k, &v);
    }
    if let Some(body) = req.body {
        builder = builder.body(body);
    }

    let resp = builder
        .send()
        .await
        .map_err(|e| format!("网络请求失败: {e}"))?;
    let status = resp.status().as_u16();
    let body = resp.text().await.map_err(|e| format!("读取响应失败: {e}"))?;
    Ok(HttpProxyResponse { status, body })
}

#[tauri::command]
fn pin_vault_status() -> pin_store::PinStatus {
    pin_store::get_status()
}

#[tauri::command]
fn save_pin_vault(pin: String, email: String, server_url: String, secret_json: String) -> Result<(), String> {
    pin_store::save(&pin, &email, &server_url, &secret_json)
}

#[tauri::command]
fn unlock_pin_vault(pin: String) -> Result<String, String> {
    pin_store::unlock(&pin)
}

#[tauri::command]
fn clear_pin_vault() -> Result<(), String> {
    pin_store::clear()
}

#[tauri::command]
fn save_ai_providers_config(config_json: String) -> Result<(), String> {
    pin_store::save_ai_providers(&config_json)
}

#[tauri::command]
fn load_ai_providers_config() -> Result<Option<String>, String> {
    pin_store::load_ai_providers()
}

#[tauri::command]
fn update_watcher_state(unlocked: bool, watch_enabled: bool, rules: Vec<AppWatchRule>) {
    win_platform::update_watcher_state(unlocked, watch_enabled, rules);
}

#[tauri::command]
fn list_running_apps() -> Vec<RunningAppInfo> {
    win_platform::list_running_apps()
}

#[tauri::command]
fn show_hud_with_payload(app: AppHandle, payload: serde_json::Value) -> Result<(), String> {
    if let Ok(mut g) = LATEST_HUD_PAYLOAD.lock() {
        *g = Some(payload.clone());
    }
    if let Some(hud) = app.get_webview_window("hud") {
        win_platform::show_hud_noactivate(&hud)?;
        let _ = hud.emit("pwdsv://hud-render", payload);
    }
    Ok(())
}

#[tauri::command]
fn get_hud_payload() -> Option<serde_json::Value> {
    LATEST_HUD_PAYLOAD.lock().ok().and_then(|g| g.clone())
}

#[tauri::command]
fn hide_hud_window(app: AppHandle) -> Result<(), String> {
    if let Some(hud) = app.get_webview_window("hud") {
        win_platform::hide_hud_window(&hud)?;
    }
    Ok(())
}

#[tauri::command]
fn dispatch_hud_action(app: AppHandle, action: serde_json::Value) -> Result<(), String> {
    app.emit("pwdsv://hud-action", action).map_err(|e| e.to_string())
}

#[tauri::command]
fn mute_pid_session(pid: u32) {
    win_platform::mute_pid(pid);
}

#[tauri::command]
fn focus_main_window(app: AppHandle) -> Result<(), String> {
    if let Some(main) = app.get_webview_window("main") {
        let _ = main.unminimize();
        let _ = main.show();
        let _ = main.set_focus();
    }
    Ok(())
}

#[tauri::command]
fn auto_type_secret(hwnd: isize, username: String, password: String, include_username: bool) -> Result<(), String> {
    let target = if hwnd != 0 { hwnd } else { win_platform::last_external_hwnd() };
    win_platform::auto_type_to_hwnd(target, &username, &password, include_username)
}

#[tauri::command]
fn auto_type_to_last_window(username: String, password: String, include_username: bool) -> Result<(), String> {
    let target = win_platform::last_external_hwnd();
    win_platform::auto_type_to_hwnd(target, &username, &password, include_username)
}

#[tauri::command]
fn copy_secret_secure(text: String, clear_seconds: u64) -> Result<(), String> {
    win_platform::copy_secret_secure(&text, clear_seconds)
}

#[tauri::command]
fn get_app_version() -> String {
    env!("CARGO_PKG_VERSION").to_owned()
}

#[tauri::command]
async fn download_and_install_update(
    app: AppHandle,
    url: String,
    expected_sha256: String,
    insecure_tls: bool,
) -> Result<String, String> {
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(insecure_tls)
        .timeout(Duration::from_secs(180))
        .build()
        .map_err(|e| format!("创建下载客户端失败: {e}"))?;

    let resp = client
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("下载更新包失败: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("下载更新包失败: HTTP {}", resp.status().as_u16()));
    }
    let bytes = resp
        .bytes()
        .await
        .map_err(|e| format!("读取更新包数据失败: {e}"))?;

    let actual_sha = digest::digest(&digest::SHA256, &bytes)
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let want = expected_sha256.trim().to_ascii_lowercase();
    if !want.is_empty() && actual_sha != want {
        return Err("安装包 SHA-256 校验失败，已中止更新".to_owned());
    }

    let pid = std::process::id();
    let is_msi = url.split('?').next().unwrap_or("").to_ascii_lowercase().ends_with(".msi");
    let ext = if is_msi { "msi" } else { "exe" };
    let dl_path = std::env::temp_dir().join(format!("keynexus-update-{pid}.{ext}"));
    fs::write(&dl_path, &bytes).map_err(|e| format!("写入临时更新文件失败: {e}"))?;

    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;

        if is_msi {
            Command::new("msiexec")
                .args(["/i", &dl_path.to_string_lossy()])
                .spawn()
                .map_err(|e| format!("启动安装程序失败: {e}"))?;
        } else {
            let cur_exe = std::env::current_exe().map_err(|e| format!("无法获取当前程序路径: {e}"))?;
            let ps_path = std::env::temp_dir().join(format!("keynexus-apply-update-{pid}.ps1"));
            let q = |p: &std::path::Path| p.to_string_lossy().replace('\'', "''");
            let script = format!(
                "$ErrorActionPreference = 'Stop'\r\n\
                $targetPid = {pid}\r\n\
                $src = '{src}'\r\n\
                $dst = '{dst}'\r\n\
                for ($i = 0; $i -lt 40; $i++) {{\r\n\
                  if (-not (Get-Process -Id $targetPid -ErrorAction SilentlyContinue)) {{ break }}\r\n\
                  Start-Sleep -Milliseconds 500\r\n\
                }}\r\n\
                Copy-Item -LiteralPath $src -Destination $dst -Force\r\n\
                Start-Process -FilePath $dst\r\n\
                Remove-Item -LiteralPath $src -Force -ErrorAction SilentlyContinue\r\n\
                Remove-Item -LiteralPath $PSCommandPath -Force -ErrorAction SilentlyContinue\r\n",
                src = q(&dl_path),
                dst = q(&cur_exe),
            );
            fs::write(&ps_path, script.as_bytes()).map_err(|e| format!("创建升级脚本失败: {e}"))?;
            Command::new("powershell.exe")
                .args([
                    "-NoProfile",
                    "-WindowStyle",
                    "Hidden",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-File",
                    &ps_path.to_string_lossy(),
                ])
                .creation_flags(CREATE_NO_WINDOW)
                .spawn()
                .map_err(|e| format!("启动自动替换升级进程失败: {e}"))?;
        }
        app.exit(0);
        return Ok("正在替换更新并自动重启…".to_owned());
    }

    #[cfg(not(windows))]
    {
        Ok(format!("更新包已下载至：{}", dl_path.display()))
    }
}

fn setup_system_tray(app: &AppHandle) -> tauri::Result<()> {
    let open_i = MenuItem::with_id(app, "open", "打开 KeyNexus", true, None::<&str>)?;
    let add_i = MenuItem::with_id(app, "quick-add", "提交新密码 (Ctrl+Alt+N)", true, None::<&str>)?;
    let lock_i = MenuItem::with_id(app, "lock", "立即锁定密码库", true, None::<&str>)?;
    let quit_i = MenuItem::with_id(app, "quit", "退出程序", true, None::<&str>)?;

    let menu = Menu::with_items(app, &[&open_i, &add_i, &lock_i, &quit_i])?;

    let mut builder = TrayIconBuilder::new()
        .tooltip("KeyNexus（后台守护中）")
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| match event.id.as_ref() {
            "open" => {
                let _ = focus_main_window(app.clone());
            }
            "quick-add" => {
                let _ = focus_main_window(app.clone());
                let _ = app.emit(
                    "pwdsv://tray-command",
                    serde_json::json!({ "command": "quick-add" }),
                );
            }
            "lock" => {
                let _ = app.emit(
                    "pwdsv://tray-command",
                    serde_json::json!({ "command": "lock" }),
                );
            }
            "quit" => {
                app.exit(0);
            }
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                let _ = focus_main_window(tray.app_handle().clone());
            }
        });

    if let Some(icon) = app.default_window_icon().cloned() {
        builder = builder.icon(icon);
    }
    builder.build(app)?;
    Ok(())
}

pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            let handle = app.handle().clone();
            setup_system_tray(&handle)?;
            win_platform::start_background_watcher(handle);
            Ok(())
        })
        .on_window_event(|window, event| {
            // 关闭主窗口时最小化到系统托盘，保持后台桌面应用密码提示常驻
            if window.label() == "main" {
                if let WindowEvent::CloseRequested { api, .. } = event {
                    api.prevent_close();
                    let _ = window.hide();
                }
            }
        })
        .invoke_handler(tauri::generate_handler![
            http_request,
            pin_vault_status,
            save_pin_vault,
            unlock_pin_vault,
            clear_pin_vault,
            save_ai_providers_config,
            load_ai_providers_config,
            update_watcher_state,
            list_running_apps,
            show_hud_with_payload,
            get_hud_payload,
            hide_hud_window,
            dispatch_hud_action,
            mute_pid_session,
            focus_main_window,
            auto_type_secret,
            auto_type_to_last_window,
            copy_secret_secure,
            get_app_version,
            download_and_install_update,
        ])
        .run(tauri::generate_context!())
        .expect("PWDSV 桌面客户端启动失败");
}
