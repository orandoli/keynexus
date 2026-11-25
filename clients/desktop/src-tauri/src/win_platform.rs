//! Windows 10/11 原生平台能力封装：
//! - 零轮询窗口监听：`SetWinEventHook` (EVENT_SYSTEM_FOREGROUND / EVENT_OBJECT_SHOW)
//! - 防打扰状态机：Per-PID 会话去重 + 退出进程自动回收，打开应用只提示一次、切窗口不反复骚扰
//! - 全局快捷键：`RegisterHotKey` 注册 `Ctrl+Alt+P`（当前软件查密提示）与 `Ctrl+Alt+N`（为当前软件记密码）
//! - 无焦点抢占 HUD：`WS_EX_NOACTIVATE | WS_EX_TOPMOST | WS_EX_TOOLWINDOW` + Win11 圆角 DWM 属性
//! - 模拟键入：`SendInput` (`KEYEVENTF_UNICODE`) 直接向目标窗口发送账号密码，突破禁止粘贴的密码框
//! - 防泄漏安全剪贴板：写入 `ExcludeClipboardContentFromMonitorProcessing` 等标记屏蔽 `Win+V` 历史，定时校验哈希清空

use std::{
    collections::{HashMap, HashSet},
    ffi::c_void,
    ptr::{null, null_mut},
    sync::Mutex,
    time::{Duration, Instant},
};

use once_cell::sync::Lazy;
use ring::digest;
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, WebviewWindow};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppWatchRule {
    pub exe: String,
    pub title_pattern: Option<String>,
    pub trigger: String, // "launch" | "always" | "hotkey"
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RunningAppInfo {
    pub hwnd: isize,
    pub pid: u32,
    pub exe: String,
    pub title: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppDetectedEvent {
    pub hwnd: isize,
    pub pid: u32,
    pub exe: String,
    pub title: String,
    pub manual_hotkey: bool,
}

struct WatcherRuntime {
    app_handle: Option<AppHandle>,
    unlocked: bool,
    watch_enabled: bool,
    rules: Vec<AppWatchRule>,
    /// 本次进程存活期内已经自动弹出过提示的 (pid, exe_or_rule)
    prompted_sessions: HashSet<(u32, String)>,
    /// 用户点击了「本次运行不再提示」的 pid
    muted_pids: HashSet<u32>,
    /// 最近一次非本软件的前台活动窗口句柄（供主窗口点「键入到上一个窗口」使用）
    last_external_hwnd: isize,
    last_prune: Instant,
    last_emit_at: HashMap<u32, Instant>,
}

static STATE: Lazy<Mutex<WatcherRuntime>> = Lazy::new(|| {
    Mutex::new(WatcherRuntime {
        app_handle: None,
        unlocked: false,
        watch_enabled: true,
        rules: Vec::new(),
        prompted_sessions: HashSet::new(),
        muted_pids: HashSet::new(),
        last_external_hwnd: 0,
        last_prune: Instant::now(),
        last_emit_at: HashMap::new(),
    })
});

static LAST_CLIPBOARD_SHA256: Lazy<Mutex<Option<[u8; 32]>>> = Lazy::new(|| Mutex::new(None));

/// 大小写不敏感通配匹配（支持 `*` 与 `?`）
pub fn wildcard_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.to_lowercase().chars().collect();
    let t: Vec<char> = text.to_lowercase().chars().collect();
    let (mut pi, mut ti) = (0usize, 0usize);
    let (mut star_idx, mut match_idx) = (None::<usize>, 0usize);

    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star_idx = Some(pi);
            match_idx = ti;
            pi += 1;
        } else if let Some(si) = star_idx {
            pi = si + 1;
            match_idx += 1;
            ti = match_idx;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

fn is_ignored_system_exe(exe_lower: &str) -> bool {
    matches!(
        exe_lower,
        "explorer.exe"
            | "searchhost.exe"
            | "startmenuexperiencehost.exe"
            | "shellexperiencehost.exe"
            | "textinputhost.exe"
            | "applicationframehost.exe"
            | "lockapp.exe"
            | "taskmgr.exe"
            | "dwm.exe"
    )
}

pub fn update_watcher_state(unlocked: bool, watch_enabled: bool, rules: Vec<AppWatchRule>) {
    if let Ok(mut st) = STATE.lock() {
        st.unlocked = unlocked;
        st.watch_enabled = watch_enabled;
        st.rules = rules;
        if !unlocked {
            st.prompted_sessions.clear();
        }
    }
}

pub fn mute_pid(pid: u32) {
    if let Ok(mut st) = STATE.lock() {
        st.muted_pids.insert(pid);
    }
}

pub fn last_external_hwnd() -> isize {
    STATE.lock().map(|s| s.last_external_hwnd).unwrap_or(0)
}

#[cfg(windows)]
mod imp {
    use super::*;
    use windows_sys::{
        core::BOOL,
        Win32::Foundation::{CloseHandle, FALSE, HWND, LPARAM, LRESULT, RECT, STILL_ACTIVE, TRUE, WPARAM},
        Win32::Graphics::Dwm::{DwmSetWindowAttribute, DWMWCP_ROUND, DWMWA_WINDOW_CORNER_PREFERENCE},
        Win32::System::{
            DataExchange::{
                CloseClipboard, EmptyClipboard, GetClipboardData, OpenClipboard, RegisterClipboardFormatW,
                SetClipboardData,
            },
            LibraryLoader::GetModuleHandleW,
            Memory::{GlobalAlloc, GlobalLock, GlobalUnlock, GMEM_MOVEABLE, GMEM_ZEROINIT},
            Threading::{
                GetCurrentProcessId, GetExitCodeProcess, OpenProcess, QueryFullProcessImageNameW,
                PROCESS_QUERY_LIMITED_INFORMATION,
            },
        },
        Win32::UI::{
            Accessibility::{SetWinEventHook, UnhookWinEvent, HWINEVENTHOOK},
            Input::KeyboardAndMouse::{
                RegisterHotKey, SendInput, INPUT, INPUT_0, INPUT_KEYBOARD, KEYBDINPUT, KEYEVENTF_KEYUP,
                KEYEVENTF_UNICODE, MOD_ALT, MOD_CONTROL, MOD_NOREPEAT, VK_CONTROL, VK_MENU, VK_SHIFT, VK_TAB,
            },
            WindowsAndMessaging::{
                CreateWindowExW, DefWindowProcW, DispatchMessageW, EnumWindows, GetForegroundWindow, GetMessageW,
                GetWindowLongPtrW, GetWindowTextLengthW, GetWindowTextW, GetWindowThreadProcessId, IsWindowVisible,
                RegisterClassW, SetForegroundWindow, SetWindowLongPtrW, SetWindowPos, ShowWindow,
                SystemParametersInfoW, TranslateMessage, EVENT_OBJECT_SHOW, EVENT_SYSTEM_FOREGROUND, GWL_EXSTYLE,
                HWND_MESSAGE, HWND_TOPMOST, MSG, SPI_GETWORKAREA, SWP_NOACTIVATE, SWP_SHOWWINDOW, SW_HIDE,
                WINEVENT_OUTOFCONTEXT, WINEVENT_SKIPOWNPROCESS, WM_HOTKEY, WNDCLASSW, WS_EX_NOACTIVATE,
                WS_EX_TOOLWINDOW, WS_EX_TOPMOST,
            },
        },
    };

    const CF_UNICODETEXT: u32 = 13;
    const HOTKEY_ID_PROMPT: i32 = 0x5001;    // Ctrl + Alt + P
    const HOTKEY_ID_QUICK_ADD: i32 = 0x5002; // Ctrl + Alt + N

    fn wide_null(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    pub fn is_pid_alive(pid: u32) -> bool {
        unsafe {
            let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
            if h.is_null() {
                return false;
            }
            let mut code: u32 = 0;
            let ok = GetExitCodeProcess(h, &mut code);
            CloseHandle(h);
            ok != 0 && code == (STILL_ACTIVE as u32)
        }
    }

    pub fn inspect_hwnd(hwnd: HWND) -> Option<RunningAppInfo> {
        if hwnd.is_null() {
            return None;
        }
        unsafe {
            let mut pid: u32 = 0;
            GetWindowThreadProcessId(hwnd, &mut pid);
            if pid == 0 || pid == GetCurrentProcessId() {
                return None;
            }

            let hproc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
            if hproc.is_null() {
                return None;
            }
            let mut buf = [0u16; 1024];
            let mut size = buf.len() as u32;
            let ok = QueryFullProcessImageNameW(hproc, 0, buf.as_mut_ptr(), &mut size);
            CloseHandle(hproc);
            if ok == 0 || size == 0 {
                return None;
            }

            let full_path = String::from_utf16_lossy(&buf[..size as usize]);
            let exe = full_path
                .rsplit(['\\', '/'])
                .next()
                .unwrap_or(&full_path)
                .to_owned();
            if exe.is_empty() {
                return None;
            }

            let title_len = GetWindowTextLengthW(hwnd);
            let title = if title_len > 0 {
                let mut tbuf = vec![0u16; (title_len as usize) + 2];
                let copied = GetWindowTextW(hwnd, tbuf.as_mut_ptr(), tbuf.len() as i32);
                String::from_utf16_lossy(&tbuf[..copied.max(0) as usize])
                    .trim()
                    .to_owned()
            } else {
                String::new()
            };

            Some(RunningAppInfo {
                hwnd: hwnd as isize,
                pid,
                exe,
                title,
            })
        }
    }

    fn handle_foreground_candidate(hwnd: HWND, manual_hotkey: bool) {
        let Some(info) = inspect_hwnd(hwnd) else {
            return;
        };
        let exe_lower = info.exe.to_lowercase();
        if !manual_hotkey && is_ignored_system_exe(&exe_lower) {
            return;
        }

        let app_to_emit = {
            let Ok(mut st) = STATE.lock() else {
                return;
            };
            st.last_external_hwnd = info.hwnd;

            // 定期回收已退出进程的 PID，这样用户把软件关掉重开后能再次正常弹出提示
            if st.last_prune.elapsed() > Duration::from_secs(15) {
                st.last_prune = Instant::now();
                st.prompted_sessions.retain(|(pid, _)| is_pid_alive(*pid));
                st.muted_pids.retain(|pid| is_pid_alive(*pid));
                st.last_emit_at.retain(|pid, _| is_pid_alive(*pid));
            }

            if manual_hotkey {
                st.app_handle.clone()
            } else {
                if !st.unlocked || !st.watch_enabled || st.muted_pids.contains(&info.pid) {
                    return;
                }
                // 防抖：同一 PID 1.2 秒内不连续触发
                if let Some(prev) = st.last_emit_at.get(&info.pid) {
                    if prev.elapsed() < Duration::from_millis(1200) {
                        return;
                    }
                }

                let matched_rule = st.rules.iter().find(|r| {
                    if r.trigger == "hotkey" {
                        return false;
                    }
                    if r.exe.to_lowercase() != exe_lower {
                        return false;
                    }
                    if let Some(pat) = &r.title_pattern {
                        if !pat.is_empty() && !wildcard_match(pat, &info.title) {
                            return false;
                        }
                    }
                    true
                }).cloned();

                let Some(rule) = matched_rule else {
                    return;
                };

                let session_key = format!(
                    "{}:{}",
                    exe_lower,
                    rule.title_pattern.as_deref().unwrap_or("*")
                );
                if rule.trigger != "always" && st.prompted_sessions.contains(&(info.pid, session_key.clone())) {
                    return;
                }

                st.prompted_sessions.insert((info.pid, session_key));
                st.last_emit_at.insert(info.pid, Instant::now());
                st.app_handle.clone()
            }
        };

        if let Some(app) = app_to_emit {
            let _ = app.emit(
                "pwdsv://app-detected",
                AppDetectedEvent {
                    hwnd: info.hwnd,
                    pid: info.pid,
                    exe: info.exe,
                    title: info.title,
                    manual_hotkey,
                },
            );
        }
    }

    unsafe extern "system" fn win_event_proc(
        _hook: HWINEVENTHOOK,
        event: u32,
        hwnd: HWND,
        id_object: i32,
        id_child: i32,
        _id_event_thread: u32,
        _event_time: u32,
    ) {
        // OBJID_WINDOW == 0，仅处理顶层窗口显示或前台切换事件
        if id_object != 0 || id_child != 0 || hwnd.is_null() {
            return;
        }
        if event == EVENT_OBJECT_SHOW {
            if unsafe { IsWindowVisible(hwnd) } == 0 {
                return;
            }
            if unsafe { GetForegroundWindow() } != hwnd {
                return;
            }
        }
        handle_foreground_candidate(hwnd, false);
    }

    unsafe extern "system" fn msg_wnd_proc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
        if msg == WM_HOTKEY {
            let id = wparam as i32;
            let fg = unsafe { GetForegroundWindow() };
            if id == HOTKEY_ID_PROMPT {
                handle_foreground_candidate(fg, true);
                return 0;
            } else if id == HOTKEY_ID_QUICK_ADD {
                let app_info = inspect_hwnd(fg);
                let handle = STATE.lock().ok().and_then(|s| s.app_handle.clone());
                if let Some(app) = handle {
                    let _ = app.emit(
                        "pwdsv://tray-command",
                        serde_json::json!({
                            "command": "quick-add",
                            "app": app_info,
                        }),
                    );
                }
                return 0;
            }
        }
        unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) }
    }

    pub fn start_background_watcher(app: AppHandle) {
        if let Ok(mut st) = STATE.lock() {
            st.app_handle = Some(app);
        }

        std::thread::Builder::new()
            .name("pwdsv-win32-watcher".to_owned())
            .spawn(move || unsafe {
                let hinstance = GetModuleHandleW(null());
                let class_name = wide_null("PWDSVWatcherMessageWindow");
                let wc = WNDCLASSW {
                    style: 0,
                    lpfnWndProc: Some(msg_wnd_proc),
                    cbClsExtra: 0,
                    cbWndExtra: 0,
                    hInstance: hinstance,
                    hIcon: null_mut(),
                    hCursor: null_mut(),
                    hbrBackground: null_mut(),
                    lpszMenuName: null(),
                    lpszClassName: class_name.as_ptr(),
                };
                RegisterClassW(&wc);

                let msg_hwnd = CreateWindowExW(
                    0,
                    class_name.as_ptr(),
                    class_name.as_ptr(),
                    0,
                    0,
                    0,
                    0,
                    0,
                    HWND_MESSAGE,
                    null_mut(),
                    hinstance,
                    null(),
                );

                // 注册全局热键：Ctrl+Alt+P (0x50) 与 Ctrl+Alt+N (0x4E)
                let mods = MOD_CONTROL | MOD_ALT | MOD_NOREPEAT;
                let _ = RegisterHotKey(msg_hwnd, HOTKEY_ID_PROMPT, mods, 0x50);
                let _ = RegisterHotKey(msg_hwnd, HOTKEY_ID_QUICK_ADD, mods, 0x4E);

                let hook = SetWinEventHook(
                    EVENT_SYSTEM_FOREGROUND,
                    EVENT_OBJECT_SHOW,
                    null_mut(),
                    Some(win_event_proc),
                    0,
                    0,
                    WINEVENT_OUTOFCONTEXT | WINEVENT_SKIPOWNPROCESS,
                );

                let mut msg: MSG = std::mem::zeroed();
                while GetMessageW(&mut msg, null_mut(), 0, 0) > 0 {
                    TranslateMessage(&msg);
                    DispatchMessageW(&msg);
                }

                if !hook.is_null() {
                    UnhookWinEvent(hook);
                }
            })
            .ok();
    }

    /// 将 HUD 窗口设为无焦点抢占置顶悬浮样式，并停靠在主屏幕工作区右上角
    pub fn show_hud_noactivate(hud: &WebviewWindow) -> Result<(), String> {
        let raw_hwnd = hud.hwnd().map_err(|e| e.to_string())?.0 as HWND;
        unsafe {
            let ex = GetWindowLongPtrW(raw_hwnd, GWL_EXSTYLE);
            let desired = ex | (WS_EX_NOACTIVATE as isize) | (WS_EX_TOPMOST as isize) | (WS_EX_TOOLWINDOW as isize);
            SetWindowLongPtrW(raw_hwnd, GWL_EXSTYLE, desired);

            // Windows 11 原生圆角窗口阴影
            let corner_pref: u32 = DWMWCP_ROUND as u32;
            let _ = DwmSetWindowAttribute(
                raw_hwnd,
                DWMWA_WINDOW_CORNER_PREFERENCE as u32,
                &corner_pref as *const u32 as *const c_void,
                std::mem::size_of::<u32>() as u32,
            );

            let mut work_rect = RECT { left: 0, top: 0, right: 1920, bottom: 1080 };
            let _ = SystemParametersInfoW(
                SPI_GETWORKAREA,
                0,
                &mut work_rect as *mut RECT as *mut c_void,
                0,
            );

            let scale = hud.scale_factor().unwrap_or(1.0);
            let width = (376.0 * scale).round() as i32;
            let height = (168.0 * scale).round() as i32;
            let margin = (18.0 * scale).round() as i32;

            let x = (work_rect.right - width - margin).max(work_rect.left + 8);
            let y = work_rect.top + margin;

            SetWindowPos(
                raw_hwnd,
                HWND_TOPMOST,
                x,
                y,
                width,
                height,
                SWP_NOACTIVATE | SWP_SHOWWINDOW,
            );
        }
        Ok(())
    }

    pub fn hide_hud_window(hud: &WebviewWindow) -> Result<(), String> {
        let raw_hwnd = hud.hwnd().map_err(|e| e.to_string())?.0 as HWND;
        unsafe {
            ShowWindow(raw_hwnd, SW_HIDE);
        }
        Ok(())
    }

    /// 枚举当前所有可见的桌面应用程序供用户一键绑定
    pub fn list_running_apps() -> Vec<RunningAppInfo> {
        unsafe extern "system" fn enum_cb(hwnd: HWND, lparam: LPARAM) -> BOOL {
            unsafe {
                if IsWindowVisible(hwnd) == 0 {
                    return TRUE;
                }
                if let Some(info) = inspect_hwnd(hwnd) {
                    let exe_lower = info.exe.to_lowercase();
                    if !info.title.is_empty() && !is_ignored_system_exe(&exe_lower) {
                        let out = &mut *(lparam as *mut Vec<RunningAppInfo>);
                        out.push(info);
                    }
                }
                TRUE
            }
        }

        let mut raw_list: Vec<RunningAppInfo> = Vec::new();
        unsafe {
            EnumWindows(Some(enum_cb), &mut raw_list as *mut Vec<RunningAppInfo> as LPARAM);
        }

        let mut seen = HashSet::new();
        let mut deduped = Vec::new();
        for item in raw_list {
            let key = item.exe.to_lowercase();
            if seen.insert(key) {
                deduped.push(item);
            }
        }
        deduped.sort_by(|a, b| a.exe.to_lowercase().cmp(&b.exe.to_lowercase()));
        deduped
    }

    fn push_vk(inputs: &mut Vec<INPUT>, vk: u16, up: bool) {
        inputs.push(INPUT {
            r#type: INPUT_KEYBOARD,
            Anonymous: INPUT_0 {
                ki: KEYBDINPUT {
                    wVk: vk,
                    wScan: 0,
                    dwFlags: if up { KEYEVENTF_KEYUP } else { 0 },
                    time: 0,
                    dwExtraInfo: 0,
                },
            },
        });
    }

    fn push_unicode_text(inputs: &mut Vec<INPUT>, text: &str) {
        for unit in text.encode_utf16() {
            for flags in [KEYEVENTF_UNICODE, KEYEVENTF_UNICODE | KEYEVENTF_KEYUP] {
                inputs.push(INPUT {
                    r#type: INPUT_KEYBOARD,
                    Anonymous: INPUT_0 {
                        ki: KEYBDINPUT {
                            wVk: 0,
                            wScan: unit,
                            dwFlags: flags,
                            time: 0,
                            dwExtraInfo: 0,
                        },
                    },
                });
            }
        }
    }

    /// 激活目标窗口并通过 SendInput 注入 Unicode 键盘流（无视输入法状态与禁粘贴限制）
    pub fn auto_type_to_hwnd(target_hwnd: isize, username: &str, password: &str, include_username: bool) -> Result<(), String> {
        if target_hwnd == 0 {
            return Err("未找到目标应用窗口，请先点击一下目标软件的输入框".to_owned());
        }
        unsafe {
            let hwnd = target_hwnd as HWND;
            let _ = SetForegroundWindow(hwnd);
            std::thread::sleep(Duration::from_millis(90));

            let mut inputs: Vec<INPUT> = Vec::new();
            // 先确保修饰键已抬起，避免用户刚按完快捷键残留 Ctrl/Alt
            for vk in [VK_CONTROL, VK_MENU, VK_SHIFT] {
                push_vk(&mut inputs, vk, true);
            }

            if include_username && !username.is_empty() {
                push_unicode_text(&mut inputs, username);
                push_vk(&mut inputs, VK_TAB, false);
                push_vk(&mut inputs, VK_TAB, true);
            }
            push_unicode_text(&mut inputs, password);

            if !inputs.is_empty() {
                let sent = SendInput(
                    inputs.len() as u32,
                    inputs.as_ptr(),
                    std::mem::size_of::<INPUT>() as i32,
                );
                if sent == 0 {
                    return Err("系统阻止了模拟键入（若目标程序以管理员身份运行，请同样以管理员启动 PWDSV，或改点复制密码）".to_owned());
                }
            }
        }
        Ok(())
    }

    fn set_clipboard_dword_flag(format_name: &str, value: u32) {
        unsafe {
            let wide = wide_null(format_name);
            let fmt = RegisterClipboardFormatW(wide.as_ptr());
            if fmt == 0 {
                return;
            }
            let hmem = GlobalAlloc(GMEM_MOVEABLE | GMEM_ZEROINIT, 4);
            if hmem.is_null() {
                return;
            }
            let ptr = GlobalLock(hmem) as *mut u32;
            if !ptr.is_null() {
                *ptr = value;
                GlobalUnlock(hmem);
                let _ = SetClipboardData(fmt, hmem);
            }
        }
    }

    /// 安全写入剪贴板（标记禁止进入 Win+V 剪贴板历史与云同步），并在超时后核对哈希自动清空
    pub fn copy_secret_secure(text: &str, clear_seconds: u64) -> Result<(), String> {
        let utf16: Vec<u16> = text.encode_utf16().chain(std::iter::once(0)).collect();
        let byte_len = utf16.len() * 2;

        unsafe {
            if OpenClipboard(null_mut()) == 0 {
                return Err("无法打开系统剪贴板".to_owned());
            }
            EmptyClipboard();

            let hmem = GlobalAlloc(GMEM_MOVEABLE, byte_len);
            if hmem.is_null() {
                CloseClipboard();
                return Err("分配剪贴板内存失败".to_owned());
            }
            let dst = GlobalLock(hmem) as *mut u16;
            if dst.is_null() {
                CloseClipboard();
                return Err("锁定剪贴板内存失败".to_owned());
            }
            std::ptr::copy_nonoverlapping(utf16.as_ptr(), dst, utf16.len());
            GlobalUnlock(hmem);
            let _ = SetClipboardData(CF_UNICODETEXT, hmem);

            // 标记敏感凭据：不进 Win+V 剪贴板历史、不上传云剪贴板、屏蔽第三方剪贴板监控
            set_clipboard_dword_flag("ExcludeClipboardContentFromMonitorProcessing", 1);
            set_clipboard_dword_flag("CanIncludeInClipboardHistory", 0);
            set_clipboard_dword_flag("CanUploadToCloudClipboard", 0);

            CloseClipboard();
        }

        let mut sha = [0u8; 32];
        sha.copy_from_slice(digest::digest(&digest::SHA256, text.as_bytes()).as_ref());
        if let Ok(mut guard) = LAST_CLIPBOARD_SHA256.lock() {
            *guard = Some(sha);
        }

        if clear_seconds > 0 {
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_secs(clear_seconds));
                clear_clipboard_if_matches(&sha);
            });
        }
        Ok(())
    }

    fn clear_clipboard_if_matches(expected_sha: &[u8; 32]) {
        let should_check = LAST_CLIPBOARD_SHA256
            .lock()
            .ok()
            .and_then(|g| *g)
            .map(|cur| &cur == expected_sha)
            .unwrap_or(false);
        if !should_check {
            return;
        }

        unsafe {
            if OpenClipboard(null_mut()) == 0 {
                return;
            }
            let hdata = GetClipboardData(CF_UNICODETEXT);
            let mut matches_current = false;
            if !hdata.is_null() {
                let ptr = GlobalLock(hdata) as *const u16;
                if !ptr.is_null() {
                    let mut len = 0usize;
                    while *ptr.add(len) != 0 && len < 16384 {
                        len += 1;
                    }
                    let current = String::from_utf16_lossy(std::slice::from_raw_parts(ptr, len));
                    GlobalUnlock(hdata);
                    let cur_digest = digest::digest(&digest::SHA256, current.as_bytes());
                    matches_current = cur_digest.as_ref() == expected_sha;
                }
            }
            if matches_current {
                EmptyClipboard();
                if let Ok(mut g) = LAST_CLIPBOARD_SHA256.lock() {
                    *g = None;
                }
            }
            CloseClipboard();
        }
    }
}

#[cfg(windows)]
pub use imp::{
    auto_type_to_hwnd, copy_secret_secure, hide_hud_window, list_running_apps, show_hud_noactivate,
    start_background_watcher,
};

#[cfg(not(windows))]
pub fn start_background_watcher(_app: AppHandle) {}
#[cfg(not(windows))]
pub fn show_hud_noactivate(hud: &WebviewWindow) -> Result<(), String> {
    hud.show().map_err(|e| e.to_string())
}
#[cfg(not(windows))]
pub fn hide_hud_window(hud: &WebviewWindow) -> Result<(), String> {
    hud.hide().map_err(|e| e.to_string())
}
#[cfg(not(windows))]
pub fn list_running_apps() -> Vec<RunningAppInfo> {
    Vec::new()
}
#[cfg(not(windows))]
pub fn auto_type_to_hwnd(_hwnd: isize, _u: &str, _p: &str, _both: bool) -> Result<(), String> {
    Err("仅支持 Windows 平台模拟键入".to_owned())
}
#[cfg(not(windows))]
pub fn copy_secret_secure(_text: &str, _clear_seconds: u64) -> Result<(), String> {
    Err("仅支持 Windows 平台安全剪贴板".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wildcard_matching() {
        assert!(wildcard_match("*远程桌面*", "Windows 远程桌面连接"));
        assert!(wildcard_match("login*", "Login - Navicat"));
        assert!(!wildcard_match("*登录*", "主工作区"));
    }
}
