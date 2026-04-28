use anyhow::{Context, Result};
use serde_json::json;
use std::collections::BTreeMap;
use std::io::Read;
use std::net::TcpStream;
use std::time::Duration;

use super::*;

pub(crate) fn scan_neo4j(target: &OpenService, context: &PluginContext) -> Result<Option<PluginFinding>> {
    if brute_force_disabled() {
        return Ok(None);
    }
    if neo4j_login(target, None, None, context.timeout_secs)? {
        return Ok(Some(PluginFinding {
            plugin: "neo4j".to_string(),
            target: target.clone(),
            status: "unauthorized-access".to_string(),
            details: BTreeMap::from([
                ("service".to_string(), json!("neo4j")),
                ("port".to_string(), json!(target.port)),
                ("type".to_string(), json!("unauthorized-access")),
            ]),
        }));
    }

    if neo4j_login(target, Some("neo4j"), Some("neo4j"), context.timeout_secs)? {
        return Ok(Some(PluginFinding {
            plugin: "neo4j".to_string(),
            target: target.clone(),
            status: "default-credentials".to_string(),
            details: BTreeMap::from([
                ("service".to_string(), json!("neo4j")),
                ("port".to_string(), json!(target.port)),
                ("type".to_string(), json!("default-credentials")),
                ("username".to_string(), json!("neo4j")),
                ("password".to_string(), json!("neo4j")),
            ]),
        }));
    }

    for username in usernames_for_service("neo4j", context) {
        for password in passwords_for_user(Some(username.as_str()), context) {
            if username == "neo4j" && password == "neo4j" {
                continue;
            }
            if neo4j_login(
                target,
                Some(username.as_str()),
                Some(password.as_str()),
                context.timeout_secs,
            )? {
                return Ok(Some(PluginFinding {
                    plugin: "neo4j".to_string(),
                    target: target.clone(),
                    status: "weak-password".to_string(),
                    details: BTreeMap::from([
                        ("service".to_string(), json!("neo4j")),
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

pub(crate) fn neo4j_login(
    target: &OpenService,
    username: Option<&str>,
    password: Option<&str>,
    timeout_secs: u64,
) -> Result<bool> {
    let timeout = Duration::from_secs(timeout_secs.max(1));
    let mut stream = connect_stream(target, timeout)?;

    write_and_flush(
        &mut stream,
        &[
            0x60, 0x60, 0xB0, 0x17, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x04, 0x04, 0x00, 0x00,
            0x04, 0x03, 0x00, 0x00, 0x00, 0x00,
        ],
    )?;
    let mut version = [0u8; 4];
    stream
        .read_exact(&mut version)
        .context("failed to read neo4j handshake version")?;
    if version == [0, 0, 0, 0] {
        return Ok(false);
    }

    let hello = neo4j_hello_message(username, password);
    let frame = neo4j_chunk_message(&hello);
    write_and_flush(&mut stream, &frame)?;

    let response = neo4j_read_message(&mut stream)?;
    Ok(response.get(1).copied() == Some(0x70))
}

pub(crate) fn neo4j_hello_message(username: Option<&str>, password: Option<&str>) -> Vec<u8> {
    let mut fields = vec![("user_agent".to_string(), "rscan".to_string())];
    match (username, password) {
        (Some(username), Some(password)) => {
            fields.push(("scheme".to_string(), "basic".to_string()));
            fields.push(("principal".to_string(), username.to_string()));
            fields.push(("credentials".to_string(), password.to_string()));
        }
        _ => {
            fields.push(("scheme".to_string(), "none".to_string()));
        }
    }

    let mut message = vec![0xB1, 0x01];
    message.extend(packstream_map_string(fields));
    message
}

pub(crate) fn neo4j_chunk_message(message: &[u8]) -> Vec<u8> {
    let mut framed = Vec::with_capacity(message.len() + 4);
    framed.extend_from_slice(&(message.len() as u16).to_be_bytes());
    framed.extend_from_slice(message);
    framed.extend_from_slice(&[0x00, 0x00]);
    framed
}

pub(crate) fn neo4j_read_message(stream: &mut TcpStream) -> Result<Vec<u8>> {
    let mut message = Vec::new();
    loop {
        let mut length = [0u8; 2];
        stream
            .read_exact(&mut length)
            .context("failed to read neo4j chunk length")?;
        let chunk_len = u16::from_be_bytes(length) as usize;
        if chunk_len == 0 {
            break;
        }
        let start = message.len();
        message.resize(start + chunk_len, 0);
        stream
            .read_exact(&mut message[start..])
            .context("failed to read neo4j chunk body")?;
    }
    Ok(message)
}

pub(crate) fn packstream_map_string(fields: Vec<(String, String)>) -> Vec<u8> {
    let mut encoded = Vec::new();
    encoded.push(packstream_tiny_map_marker(fields.len()));
    for (key, value) in fields {
        encoded.extend(packstream_string(&key));
        encoded.extend(packstream_string(&value));
    }
    encoded
}

pub(crate) fn packstream_tiny_map_marker(size: usize) -> u8 {
    0xA0 | (size as u8 & 0x0F)
}

pub(crate) fn packstream_string(value: &str) -> Vec<u8> {
    let bytes = value.as_bytes();
    let len = bytes.len();
    let mut encoded = Vec::with_capacity(len + 2);
    match len {
        0..=15 => encoded.push(0x80 | len as u8),
        16..=255 => {
            encoded.push(0xD0);
            encoded.push(len as u8);
        }
        256..=65535 => {
            encoded.push(0xD1);
            encoded.extend_from_slice(&(len as u16).to_be_bytes());
        }
        _ => {
            encoded.push(0xD2);
            encoded.extend_from_slice(&(len as u32).to_be_bytes());
        }
    }
    encoded.extend_from_slice(bytes);
    encoded
}
