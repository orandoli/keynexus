//! 本地短 PIN 快捷解锁存储模块：
//! 1. 第一层：PBKDF2-HMAC-SHA256 (210,000 次) 由用户 PIN 派生 32 字节密钥，采用 AES-256-GCM 认证加密会话凭据
//! 2. 第二层：Windows DPAPI (`CryptProtectData`) 绑定当前 Windows 登录用户账户二次加密后再落盘
//! 3. 防暴力猜解：记录连续失败次数，满 5 次立即物理删除本地凭据文件并强制回退至主密码登录

use std::{fs, num::NonZeroU32, path::PathBuf};

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use ring::{
    aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM},
    pbkdf2,
    rand::{SecureRandom, SystemRandom},
};
use serde::{Deserialize, Serialize};

const PBKDF2_ITERS: u32 = 210_000;
const MAX_FAILED_ATTEMPTS: u32 = 5;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PinEnvelope {
    pub email: String,
    pub server_url: String,
    pub salt_b64: String,
    pub nonce_b64: String,
    pub dpapi_ciphertext_b64: String,
    pub failed_attempts: u32,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PinStatus {
    pub configured: bool,
    pub email: Option<String>,
    pub server_url: Option<String>,
    pub remaining_attempts: u32,
}

fn storage_file_path() -> Result<PathBuf, String> {
    let base = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("APPDATA").map(PathBuf::from))
        .unwrap_or_else(std::env::temp_dir);
    let dir = base.join("PWDSV");
    fs::create_dir_all(&dir).map_err(|e| format!("创建本地配置目录失败: {e}"))?;
    Ok(dir.join("pin_vault_v2.json"))
}

fn derive_pin_key(pin: &str, salt: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        NonZeroU32::new(PBKDF2_ITERS).unwrap(),
        salt,
        pin.as_bytes(),
        &mut out,
    );
    out
}

#[cfg(windows)]
fn dpapi_protect(data: &[u8]) -> Result<Vec<u8>, String> {
    use std::ptr::null_mut;
    use windows_sys::Win32::{
        Foundation::LocalFree,
        Security::Cryptography::{CryptProtectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB},
    };

    unsafe {
        let in_blob = CRYPT_INTEGER_BLOB {
            cbData: data.len() as u32,
            pbData: data.as_ptr() as *mut u8,
        };
        let mut out_blob = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: null_mut(),
        };
        let ok = CryptProtectData(
            &in_blob,
            null_mut(),
            null_mut(),
            null_mut(),
            null_mut(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut out_blob,
        );
        if ok == 0 || out_blob.pbData.is_null() {
            return Err("Windows DPAPI 加密保护失败".to_owned());
        }
        let slice = std::slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize);
        let vec = slice.to_vec();
        LocalFree(out_blob.pbData as *mut _);
        Ok(vec)
    }
}

#[cfg(not(windows))]
fn dpapi_protect(data: &[u8]) -> Result<Vec<u8>, String> {
    Ok(data.to_vec())
}

#[cfg(windows)]
fn dpapi_unprotect(data: &[u8]) -> Result<Vec<u8>, String> {
    use std::ptr::null_mut;
    use windows_sys::Win32::{
        Foundation::LocalFree,
        Security::Cryptography::{CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB},
    };

    unsafe {
        let in_blob = CRYPT_INTEGER_BLOB {
            cbData: data.len() as u32,
            pbData: data.as_ptr() as *mut u8,
        };
        let mut out_blob = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: null_mut(),
        };
        let ok = CryptUnprotectData(
            &in_blob,
            null_mut(),
            null_mut(),
            null_mut(),
            null_mut(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut out_blob,
        );
        if ok == 0 || out_blob.pbData.is_null() {
            return Err("Windows DPAPI 解包失败（可能更换了系统账户）".to_owned());
        }
        let slice = std::slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize);
        let vec = slice.to_vec();
        LocalFree(out_blob.pbData as *mut _);
        Ok(vec)
    }
}

#[cfg(not(windows))]
fn dpapi_unprotect(data: &[u8]) -> Result<Vec<u8>, String> {
    Ok(data.to_vec())
}

pub fn seal_with_pin(pin: &str, email: &str, server_url: &str, secret_json: &str) -> Result<PinEnvelope, String> {
    if pin.trim().len() < 4 {
        return Err("快捷 PIN 长度不能少于 4 位".to_owned());
    }
    let rng = SystemRandom::new();
    let mut salt = [0u8; 16];
    let mut nonce_bytes = [0u8; 12];
    rng.fill(&mut salt).map_err(|_| "生成随机盐失败")?;
    rng.fill(&mut nonce_bytes).map_err(|_| "生成随机 Nonce 失败")?;

    let key_bytes = derive_pin_key(pin, &salt);
    let unbound = UnboundKey::new(&AES_256_GCM, &key_bytes).map_err(|_| "初始化 AES-GCM 失败")?;
    let key = LessSafeKey::new(unbound);

    let mut in_out = secret_json.as_bytes().to_vec();
    key.seal_in_place_append_tag(
        Nonce::assume_unique_for_key(nonce_bytes),
        Aad::from(email.as_bytes()),
        &mut in_out,
    )
    .map_err(|_| "AES-GCM 加密失败")?;

    let dpapi_wrapped = dpapi_protect(&in_out)?;

    Ok(PinEnvelope {
        email: email.to_owned(),
        server_url: server_url.to_owned(),
        salt_b64: B64.encode(salt),
        nonce_b64: B64.encode(nonce_bytes),
        dpapi_ciphertext_b64: B64.encode(dpapi_wrapped),
        failed_attempts: 0,
    })
}

pub fn open_with_pin(env: &PinEnvelope, pin: &str) -> Result<String, String> {
    let salt = B64.decode(&env.salt_b64).map_err(|_| "盐格式损坏")?;
    let nonce_vec = B64.decode(&env.nonce_b64).map_err(|_| "Nonce 格式损坏")?;
    let nonce_arr: [u8; 12] = nonce_vec.try_into().map_err(|_| "Nonce 长度错误")?;
    let dpapi_raw = B64.decode(&env.dpapi_ciphertext_b64).map_err(|_| "密文格式损坏")?;

    let mut aead_buf = dpapi_unprotect(&dpapi_raw)?;
    let key_bytes = derive_pin_key(pin, &salt);
    let unbound = UnboundKey::new(&AES_256_GCM, &key_bytes).map_err(|_| "初始化解密密钥失败")?;
    let key = LessSafeKey::new(unbound);

    let plain = key
        .open_in_place(
            Nonce::assume_unique_for_key(nonce_arr),
            Aad::from(env.email.as_bytes()),
            &mut aead_buf,
        )
        .map_err(|_| "PIN 不正确")?;

    String::from_utf8(plain.to_vec()).map_err(|_| "解密内容编码异常".to_owned())
}

pub fn get_status() -> PinStatus {
    let Ok(path) = storage_file_path() else {
        return PinStatus { configured: false, email: None, server_url: None, remaining_attempts: 0 };
    };
    let Ok(raw) = fs::read_to_string(&path) else {
        return PinStatus { configured: false, email: None, server_url: None, remaining_attempts: 0 };
    };
    let Ok(env) = serde_json::from_str::<PinEnvelope>(&raw) else {
        return PinStatus { configured: false, email: None, server_url: None, remaining_attempts: 0 };
    };
    PinStatus {
        configured: true,
        email: Some(env.email),
        server_url: Some(env.server_url),
        remaining_attempts: MAX_FAILED_ATTEMPTS.saturating_sub(env.failed_attempts),
    }
}

pub fn save(pin: &str, email: &str, server_url: &str, secret_json: &str) -> Result<(), String> {
    let env = seal_with_pin(pin, email, server_url, secret_json)?;
    let path = storage_file_path()?;
    let json = serde_json::to_string_pretty(&env).map_err(|e| e.to_string())?;
    fs::write(path, json).map_err(|e| format!("写入本地 PIN 凭据失败: {e}"))
}

pub fn unlock(pin: &str) -> Result<String, String> {
    let path = storage_file_path()?;
    let raw = fs::read_to_string(&path).map_err(|_| "尚未配置本地快捷 PIN".to_owned())?;
    let mut env: PinEnvelope = serde_json::from_str(&raw).map_err(|_| "本地快捷凭据已损坏".to_owned())?;

    match open_with_pin(&env, pin) {
        Ok(secret) => {
            if env.failed_attempts != 0 {
                env.failed_attempts = 0;
                if let Ok(j) = serde_json::to_string_pretty(&env) {
                    let _ = fs::write(&path, j);
                }
            }
            Ok(secret)
        }
        Err(_) => {
            env.failed_attempts += 1;
            if env.failed_attempts >= MAX_FAILED_ATTEMPTS {
                let _ = fs::remove_file(&path);
                Err(format!(
                    "PIN 连续输错 {MAX_FAILED_ATTEMPTS} 次，已自动销毁本地快捷凭据，请使用主密码重新登录"
                ))
            } else {
                let left = MAX_FAILED_ATTEMPTS - env.failed_attempts;
                if let Ok(j) = serde_json::to_string_pretty(&env) {
                    let _ = fs::write(&path, j);
                }
                Err(format!("PIN 错误，还剩 {left} 次机会"))
            }
        }
    }
}

pub fn clear() -> Result<(), String> {
    let path = storage_file_path()?;
    if path.exists() {
        fs::remove_file(path).map_err(|e| format!("清除本地 PIN 失败: {e}"))?;
    }
    Ok(())
}

fn ai_providers_file_path() -> Result<PathBuf, String> {
    let base = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("APPDATA").map(PathBuf::from))
        .unwrap_or_else(std::env::temp_dir);
    let dir = base.join("PWDSV");
    fs::create_dir_all(&dir).map_err(|e| format!("创建本地配置目录失败: {e}"))?;
    Ok(dir.join("ai_providers_dpapi.bin"))
}

/// 使用 Windows DPAPI 加密保存本机 AI 模型提供商配置与 API Key（绝不经过 PWDSV 服务器）
pub fn save_ai_providers(config_json: &str) -> Result<(), String> {
    let encrypted = dpapi_protect(config_json.as_bytes())?;
    let path = ai_providers_file_path()?;
    fs::write(path, B64.encode(encrypted)).map_err(|e| format!("保存本地模型配置失败: {e}"))
}

pub fn load_ai_providers() -> Result<Option<String>, String> {
    let path = ai_providers_file_path()?;
    if !path.exists() {
        return Ok(None);
    }
    let b64 = fs::read_to_string(path).map_err(|e| format!("读取本地模型配置失败: {e}"))?;
    let raw = B64.decode(b64.trim()).map_err(|_| "模型配置密文损坏".to_owned())?;
    let plain = dpapi_unprotect(&raw)?;
    let s = String::from_utf8(plain).map_err(|_| "模型配置编码错误".to_owned())?;
    Ok(Some(s))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_wrong_pin_rejected() {
        let env = seal_with_pin("2580", "me@example.com", "https://vault.test", r#"{"k":"secret"}"#)
            .expect("seal");
        let opened = open_with_pin(&env, "2580").expect("open");
        assert_eq!(opened, r#"{"k":"secret"}"#);
        assert!(open_with_pin(&env, "9999").is_err());
    }
}
