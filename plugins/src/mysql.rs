use anyhow::{Context, Result};
use serde_json::json;
use std::collections::BTreeMap;
use std::io::Read;
use std::net::TcpStream;
use std::time::Duration;

use super::*;

pub(crate) fn scan_mysql(target: &OpenService, context: &PluginContext) -> Result<Option<PluginFinding>> {
    if brute_force_disabled() {
        return Ok(None);
    }
    for username in usernames_for_service("mysql", context) {
        for password in passwords_for_user(Some(username.as_str()), context) {
            if mysql_login(target, &username, &password, context.timeout_secs)? {
                return Ok(Some(PluginFinding {
                    plugin: "mysql".to_string(),
                    target: target.clone(),
                    status: "weak-password".to_string(),
                    details: BTreeMap::from([
                        ("service".to_string(), json!("mysql")),
                        ("port".to_string(), json!(target.port)),
                        ("type".to_string(), json!("weak-password")),
                        ("username".to_string(), json!(username)),
                        ("password".to_string(), json!(password)),
                    ]),
                }));
            }
        }
    }

    Ok(None)
}

pub(crate) fn mysql_login(
    target: &OpenService,
    username: &str,
    password: &str,
    timeout_secs: u64,
) -> Result<bool> {
    let timeout = Duration::from_secs(timeout_secs.max(1));
    let mut stream = connect_stream(target, timeout)?;

    let handshake = mysql_read_packet(&mut stream)?;
    let scramble = mysql_extract_scramble(&handshake)?;
    let response = mysql_handshake_response(username, password, &scramble);
    mysql_write_packet(&mut stream, 1, &response)?;

    let reply = mysql_read_packet(&mut stream)?;
    Ok(reply.first().copied() == Some(0x00))
}

pub(crate) fn mysql_handshake_response(username: &str, password: &str, scramble: &[u8]) -> Vec<u8> {
    const CLIENT_LONG_PASSWORD: u32 = 0x0000_0001;
    const CLIENT_LONG_FLAG: u32 = 0x0000_0004;
    const CLIENT_PROTOCOL_41: u32 = 0x0000_0200;
    const CLIENT_TRANSACTIONS: u32 = 0x0000_2000;
    const CLIENT_SECURE_CONNECTION: u32 = 0x0000_8000;
    const CLIENT_PLUGIN_AUTH: u32 = 0x0008_0000;

    let capabilities = CLIENT_LONG_PASSWORD
        | CLIENT_LONG_FLAG
        | CLIENT_PROTOCOL_41
        | CLIENT_TRANSACTIONS
        | CLIENT_SECURE_CONNECTION
        | CLIENT_PLUGIN_AUTH;

    let auth_response = mysql_native_password(password, scramble);

    let mut payload = Vec::new();
    payload.extend_from_slice(&capabilities.to_le_bytes());
    payload.extend_from_slice(&0x0100_0000u32.to_le_bytes());
    payload.push(0x21);
    payload.extend_from_slice(&[0u8; 23]);
    payload.extend_from_slice(username.as_bytes());
    payload.push(0x00);
    payload.push(auth_response.len() as u8);
    payload.extend_from_slice(&auth_response);
    payload.extend_from_slice(b"mysql_native_password\0");
    payload
}

pub(crate) fn mysql_native_password(password: &str, scramble: &[u8]) -> Vec<u8> {
    if password.is_empty() {
        return Vec::new();
    }

    let stage1 = Sha1::digest(password.as_bytes());
    let stage2 = Sha1::digest(stage1);
    let mut combined = Vec::with_capacity(scramble.len() + stage2.len());
    combined.extend_from_slice(scramble);
    combined.extend_from_slice(&stage2);
    let stage3 = Sha1::digest(&combined);
    stage1
        .iter()
        .zip(stage3.iter())
        .map(|(left, right)| left ^ right)
        .collect()
}

pub(crate) fn mysql_extract_scramble(handshake: &[u8]) -> Result<Vec<u8>> {
    if handshake.len() < 34 {
        anyhow::bail!("mysql handshake too short");
    }

    let first_nul = handshake
        .iter()
        .position(|byte| *byte == 0x00)
        .context("invalid mysql handshake version")?;
    let mut index = first_nul + 1 + 4;
    let mut scramble = handshake
        .get(index..index + 8)
        .context("missing mysql scramble part one")?
        .to_vec();
    index += 8 + 1;
    index += 2 + 1 + 2 + 2;
    let auth_plugin_len = *handshake
        .get(index)
        .context("missing mysql auth plugin length")? as usize;
    index += 1 + 10;
    let second_len = auth_plugin_len.saturating_sub(8).max(13);
    let second = handshake
        .get(index..index + second_len)
        .context("missing mysql scramble part two")?;
    scramble.extend_from_slice(second);
    if let Some(position) = scramble.iter().position(|byte| *byte == 0x00) {
        scramble.truncate(position);
    }
    Ok(scramble)
}

pub(crate) fn mysql_read_packet(stream: &mut TcpStream) -> Result<Vec<u8>> {
    let mut header = [0u8; 4];
    stream
        .read_exact(&mut header)
        .context("failed to read mysql packet header")?;
    let length = (header[0] as usize) | ((header[1] as usize) << 8) | ((header[2] as usize) << 16);
    let mut payload = vec![0u8; length];
    stream
        .read_exact(&mut payload)
        .context("failed to read mysql packet payload")?;
    Ok(payload)
}

pub(crate) fn mysql_write_packet(stream: &mut TcpStream, sequence: u8, payload: &[u8]) -> Result<()> {
    let length = payload.len();
    let mut packet = Vec::with_capacity(length + 4);
    packet.push((length & 0xff) as u8);
    packet.push(((length >> 8) & 0xff) as u8);
    packet.push(((length >> 16) & 0xff) as u8);
    packet.push(sequence);
    packet.extend_from_slice(payload);
    write_and_flush(stream, &packet)
}
