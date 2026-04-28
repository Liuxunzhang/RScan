use anyhow::{Context, Result};
use serde_json::json;
use std::collections::BTreeMap;
use std::io::Read;
use std::net::TcpStream;
use std::time::Duration;

use super::*;

pub(crate) fn scan_mssql(target: &OpenService, context: &PluginContext) -> Result<Option<PluginFinding>> {
    if brute_force_disabled() {
        return Ok(None);
    }
    for username in usernames_for_service("mssql", context) {
        for password in passwords_for_user(Some(username.as_str()), context) {
            if mssql_login(target, &username, &password, context.timeout_secs)? {
                return Ok(Some(PluginFinding {
                    plugin: "mssql".to_string(),
                    target: target.clone(),
                    status: "weak-password".to_string(),
                    details: BTreeMap::from([
                        ("service".to_string(), json!("mssql")),
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

pub(crate) fn mssql_login(
    target: &OpenService,
    username: &str,
    password: &str,
    timeout_secs: u64,
) -> Result<bool> {
    let timeout = Duration::from_secs(timeout_secs.max(1));
    let mut stream = connect_stream(target, timeout)?;

    mssql_write_packet(&mut stream, 0x12, 1, &mssql_prelogin_message())?;
    let _ = mssql_read_message(&mut stream)?;

    mssql_write_packet(
        &mut stream,
        0x10,
        1,
        &mssql_login7_message(&target.host, username, password),
    )?;
    let response = mssql_read_message(&mut stream)?;
    Ok(mssql_login_succeeded(&response))
}

pub(crate) fn mssql_prelogin_message() -> Vec<u8> {
    const VERSION: u8 = 0x00;
    const ENCRYPTION: u8 = 0x01;
    const THREAD_ID: u8 = 0x03;
    const MARS: u8 = 0x04;
    const TERMINATOR: u8 = 0xFF;

    let fields = [
        (VERSION, 6u16),
        (ENCRYPTION, 1u16),
        (THREAD_ID, 4u16),
        (MARS, 1u16),
    ];
    let mut payload = Vec::with_capacity(64);
    let mut offset = (fields.len() * 5 + 1) as u16;
    for (token, length) in fields {
        payload.push(token);
        payload.extend_from_slice(&offset.to_be_bytes());
        payload.extend_from_slice(&length.to_be_bytes());
        offset += length;
    }
    payload.push(TERMINATOR);
    payload.extend_from_slice(&0u32.to_be_bytes());
    payload.extend_from_slice(&0u16.to_be_bytes());
    payload.push(0x00);
    payload.extend_from_slice(&0u32.to_be_bytes());
    payload.push(0x00);
    payload
}

pub(crate) fn mssql_login7_message(server_name: &str, username: &str, password: &str) -> Vec<u8> {
    const LOGIN7_HEADER_SIZE: usize = 94;

    let hostname = "rscan";
    let app_name = "rscan";
    let library_name = "rscan";

    let hostname_utf16 = utf16le_bytes(hostname);
    let username_utf16 = utf16le_bytes(username);
    let password_utf16 = mssql_obfuscate_password(password);
    let app_name_utf16 = utf16le_bytes(app_name);
    let server_name_utf16 = utf16le_bytes(server_name);
    let library_name_utf16 = utf16le_bytes(library_name);

    let hostname_len = (hostname_utf16.len() / 2) as u16;
    let username_len = (username_utf16.len() / 2) as u16;
    let password_len = (password_utf16.len() / 2) as u16;
    let app_name_len = (app_name_utf16.len() / 2) as u16;
    let server_name_len = (server_name_utf16.len() / 2) as u16;
    let library_name_len = (library_name_utf16.len() / 2) as u16;

    let mut variable = Vec::with_capacity(256);
    let mut offset = LOGIN7_HEADER_SIZE as u16;

    let hostname_offset = offset;
    variable.extend_from_slice(&hostname_utf16);
    offset += hostname_utf16.len() as u16;

    let username_offset = offset;
    variable.extend_from_slice(&username_utf16);
    offset += username_utf16.len() as u16;

    let password_offset = offset;
    variable.extend_from_slice(&password_utf16);
    offset += password_utf16.len() as u16;

    let app_name_offset = offset;
    variable.extend_from_slice(&app_name_utf16);
    offset += app_name_utf16.len() as u16;

    let server_name_offset = offset;
    variable.extend_from_slice(&server_name_utf16);
    offset += server_name_utf16.len() as u16;

    let unused_offset = offset;

    let library_name_offset = offset;
    variable.extend_from_slice(&library_name_utf16);
    offset += library_name_utf16.len() as u16;

    let language_offset = offset;
    let database_offset = offset;
    let sspi_offset = offset;
    let attach_db_offset = offset;
    let new_password_offset = offset;

    let total_length = LOGIN7_HEADER_SIZE + variable.len();
    let mut payload = Vec::with_capacity(total_length);
    payload.extend_from_slice(&(total_length as u32).to_le_bytes());
    payload.extend_from_slice(&0x74000004u32.to_le_bytes());
    payload.extend_from_slice(&4096u32.to_le_bytes());
    payload.extend_from_slice(&0u32.to_le_bytes());
    payload.extend_from_slice(&0u32.to_le_bytes());
    payload.extend_from_slice(&0u32.to_le_bytes());
    payload.push(0x60);
    payload.push(0x03);
    payload.push(0x00);
    payload.push(0x08);
    payload.extend_from_slice(&0i32.to_le_bytes());
    payload.extend_from_slice(&0x0409u32.to_le_bytes());
    payload.extend_from_slice(&hostname_offset.to_le_bytes());
    payload.extend_from_slice(&hostname_len.to_le_bytes());
    payload.extend_from_slice(&username_offset.to_le_bytes());
    payload.extend_from_slice(&username_len.to_le_bytes());
    payload.extend_from_slice(&password_offset.to_le_bytes());
    payload.extend_from_slice(&password_len.to_le_bytes());
    payload.extend_from_slice(&app_name_offset.to_le_bytes());
    payload.extend_from_slice(&app_name_len.to_le_bytes());
    payload.extend_from_slice(&server_name_offset.to_le_bytes());
    payload.extend_from_slice(&server_name_len.to_le_bytes());
    payload.extend_from_slice(&unused_offset.to_le_bytes());
    payload.extend_from_slice(&0u16.to_le_bytes());
    payload.extend_from_slice(&library_name_offset.to_le_bytes());
    payload.extend_from_slice(&library_name_len.to_le_bytes());
    payload.extend_from_slice(&language_offset.to_le_bytes());
    payload.extend_from_slice(&0u16.to_le_bytes());
    payload.extend_from_slice(&database_offset.to_le_bytes());
    payload.extend_from_slice(&0u16.to_le_bytes());
    payload.extend_from_slice(&[0u8; 6]);
    payload.extend_from_slice(&sspi_offset.to_le_bytes());
    payload.extend_from_slice(&0u16.to_le_bytes());
    payload.extend_from_slice(&attach_db_offset.to_le_bytes());
    payload.extend_from_slice(&0u16.to_le_bytes());
    payload.extend_from_slice(&new_password_offset.to_le_bytes());
    payload.extend_from_slice(&0u16.to_le_bytes());
    payload.extend_from_slice(&0u32.to_le_bytes());
    payload.extend_from_slice(&variable);
    payload
}

pub(crate) fn mssql_obfuscate_password(password: &str) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(password.len() * 2);
    for code_unit in password.encode_utf16() {
        let low = (code_unit & 0xFF) as u8;
        let high = (code_unit >> 8) as u8;
        encoded.push(low.rotate_right(4) ^ 0xA5);
        encoded.push(high.rotate_right(4) ^ 0xA5);
    }
    encoded
}

pub(crate) fn mssql_write_packet(
    stream: &mut TcpStream,
    packet_type: u8,
    packet_id: u8,
    payload: &[u8],
) -> Result<()> {
    let length = (payload.len() + 8) as u16;
    let mut packet = Vec::with_capacity(payload.len() + 8);
    packet.push(packet_type);
    packet.push(0x01);
    packet.extend_from_slice(&length.to_be_bytes());
    packet.extend_from_slice(&[0x00, 0x00, packet_id, 0x00]);
    packet.extend_from_slice(payload);
    write_and_flush(stream, &packet)
}

pub(crate) fn mssql_read_message(stream: &mut TcpStream) -> Result<Vec<u8>> {
    let mut message = Vec::new();
    loop {
        let mut header = [0u8; 8];
        stream
            .read_exact(&mut header)
            .context("failed to read mssql packet header")?;
        let length = u16::from_be_bytes([header[2], header[3]]) as usize;
        if length < 8 {
            anyhow::bail!("invalid mssql packet length");
        }
        let mut payload = vec![0u8; length - 8];
        stream
            .read_exact(&mut payload)
            .context("failed to read mssql packet payload")?;
        message.extend_from_slice(&payload);
        if header[1] & 0x01 != 0 {
            break;
        }
    }
    Ok(message)
}

pub(crate) fn mssql_login_succeeded(payload: &[u8]) -> bool {
    let mut index = 0usize;
    let mut login_ack = false;
    while index < payload.len() {
        match payload[index] {
            0xAD => {
                if let Some(length) = payload
                    .get(index + 1..index + 3)
                    .map(|value| u16::from_le_bytes([value[0], value[1]]) as usize)
                {
                    index += 3 + length;
                    login_ack = true;
                } else {
                    break;
                }
            }
            0xAA => return false,
            0xAB | 0xE3 => {
                if let Some(length) = payload
                    .get(index + 1..index + 3)
                    .map(|value| u16::from_le_bytes([value[0], value[1]]) as usize)
                {
                    index += 3 + length;
                } else {
                    break;
                }
            }
            0xFD | 0xFE | 0xFF => {
                if payload.len().saturating_sub(index) < 13 {
                    break;
                }
                index += 13;
            }
            _ => break,
        }
    }
    login_ack
}

pub(crate) fn utf16le_bytes(value: &str) -> Vec<u8> {
    value
        .encode_utf16()
        .flat_map(|unit| unit.to_le_bytes())
        .collect()
}
