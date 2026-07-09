//! VNC weak-password detection plugin.

use crate::connection::{connect_stream, write_and_flush};
use crate::credentials::passwords_for_user;
use crate::runtime::brute_force_disabled;
use crate::{OpenService, PluginContext, PluginFinding};
use anyhow::{Context, Result};
use des::Des;
use des::cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray};
use serde_json::json;
use std::collections::BTreeMap;
use std::io::Read;
use std::time::Duration;
pub(crate) fn scan_vnc(
    target: &OpenService,
    context: &PluginContext,
) -> Result<Option<PluginFinding>> {
    if brute_force_disabled() {
        return Ok(None);
    }
    for password in passwords_for_user(None, context) {
        if vnc_login(target, &password, context.timeout_secs)? {
            return Ok(Some(PluginFinding {
                plugin: "vnc".to_string(),
                target: target.clone(),
                status: "weak-password".to_string(),
                details: BTreeMap::from([
                    ("service".to_string(), json!("vnc")),
                    ("port".to_string(), json!(target.port)),
                    ("type".to_string(), json!("weak-password")),
                    ("password".to_string(), json!(password)),
                ]),
            }));
        }
    }

    Ok(None)
}
fn vnc_login(target: &OpenService, password: &str, timeout_secs: u64) -> Result<bool> {
    let timeout = Duration::from_secs(timeout_secs.max(1));
    let mut stream = connect_stream(target, timeout)?;

    let mut version = [0u8; 12];
    stream
        .read_exact(&mut version)
        .context("failed to read vnc protocol version")?;
    write_and_flush(&mut stream, &version)?;

    let mut security_count = [0u8; 1];
    stream
        .read_exact(&mut security_count)
        .context("failed to read vnc security type count")?;
    if security_count[0] == 0 {
        return Ok(false);
    }

    let mut security_types = vec![0u8; security_count[0] as usize];
    stream
        .read_exact(&mut security_types)
        .context("failed to read vnc security types")?;
    if !security_types.contains(&2) {
        return Ok(false);
    }

    write_and_flush(&mut stream, &[2])?;

    let mut challenge = [0u8; 16];
    stream
        .read_exact(&mut challenge)
        .context("failed to read vnc auth challenge")?;
    let response = vnc_encrypt_challenge(password, &challenge)?;
    write_and_flush(&mut stream, &response)?;

    let mut status = [0u8; 4];
    stream
        .read_exact(&mut status)
        .context("failed to read vnc auth status")?;
    Ok(u32::from_be_bytes(status) == 0)
}
pub(crate) fn vnc_encrypt_challenge(password: &str, challenge: &[u8; 16]) -> Result<[u8; 16]> {
    let key = vnc_key_from_password(password);
    let cipher = Des::new_from_slice(&key).context("failed to initialize vnc des cipher")?;
    let mut encrypted = [0u8; 16];

    for (index, block) in challenge.chunks_exact(8).enumerate() {
        let mut value = GenericArray::clone_from_slice(block);
        cipher.encrypt_block(&mut value);
        encrypted[index * 8..(index + 1) * 8].copy_from_slice(&value);
    }

    Ok(encrypted)
}
fn vnc_key_from_password(password: &str) -> [u8; 8] {
    let mut key = [0u8; 8];
    for (index, byte) in password.as_bytes().iter().take(8).enumerate() {
        key[index] = byte.reverse_bits();
    }
    key
}
