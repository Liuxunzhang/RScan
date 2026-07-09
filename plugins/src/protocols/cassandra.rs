//! Cassandra unauthorized / weak-password detection plugin.

use crate::connection::{connect_stream, write_and_flush};
use crate::credentials::{passwords_for_user, usernames_for_service};
use crate::runtime::brute_force_disabled;
use crate::{OpenService, PluginContext, PluginFinding};
use anyhow::{Context, Result};
use serde_json::json;
use std::collections::BTreeMap;
use std::convert::TryInto;
use std::io::Read;
use std::net::TcpStream;
use std::time::Duration;
pub(crate) fn scan_cassandra(
    target: &OpenService,
    context: &PluginContext,
) -> Result<Option<PluginFinding>> {
    if brute_force_disabled() {
        return Ok(None);
    }
    if cassandra_login(target, None, None, context.timeout_secs)? {
        return Ok(Some(PluginFinding {
            plugin: "cassandra".to_string(),
            target: target.clone(),
            status: "unauthorized-access".to_string(),
            details: BTreeMap::from([
                ("service".to_string(), json!("cassandra")),
                ("port".to_string(), json!(target.port)),
                ("auth_type".to_string(), json!("anonymous")),
                ("type".to_string(), json!("unauthorized-access")),
                ("description".to_string(), json!("数据库允许无认证访问")),
            ]),
        }));
    }

    for username in usernames_for_service("cassandra", context) {
        for password in passwords_for_user(Some(username.as_str()), context) {
            if cassandra_login(
                target,
                Some(username.as_str()),
                Some(password.as_str()),
                context.timeout_secs,
            )? {
                return Ok(Some(PluginFinding {
                    plugin: "cassandra".to_string(),
                    target: target.clone(),
                    status: "weak-password".to_string(),
                    details: BTreeMap::from([
                        ("service".to_string(), json!("cassandra")),
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

fn cassandra_login(
    target: &OpenService,
    username: Option<&str>,
    password: Option<&str>,
    timeout_secs: u64,
) -> Result<bool> {
    let timeout = Duration::from_secs(timeout_secs.max(1));
    let mut stream = connect_stream(target, timeout)?;

    write_and_flush(&mut stream, &cassandra_startup_frame())?;
    let response = cassandra_read_frame(&mut stream)?;
    match response.opcode {
        0x02 => Ok(username.is_none() && password.is_none()),
        0x03 => {
            let (Some(username), Some(password)) = (username, password) else {
                return Ok(false);
            };
            let auth_frame = cassandra_auth_response_frame(username, password);
            write_and_flush(&mut stream, &auth_frame)?;
            let auth_result = cassandra_read_frame(&mut stream)?;
            Ok(matches!(auth_result.opcode, 0x10 | 0x02))
        }
        _ => Ok(false),
    }
}

#[derive(Debug)]
pub(crate) struct CassandraFrame {
    pub(crate) opcode: u8,
    #[allow(dead_code)]
    pub(crate) body: Vec<u8>,
}

fn cassandra_startup_frame() -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&1u16.to_be_bytes());
    body.extend(cassandra_string("CQL_VERSION"));
    body.extend(cassandra_string("3.0.0"));
    cassandra_frame(0x04, 0x01, &body)
}

fn cassandra_auth_response_frame(username: &str, password: &str) -> Vec<u8> {
    let mut token = Vec::new();
    token.push(0);
    token.extend_from_slice(username.as_bytes());
    token.push(0);
    token.extend_from_slice(password.as_bytes());

    let mut body = Vec::new();
    body.extend_from_slice(&(token.len() as u32).to_be_bytes());
    body.extend_from_slice(&token);
    cassandra_frame(0x04, 0x0F, &body)
}

pub(crate) fn cassandra_frame(version: u8, opcode: u8, body: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(9 + body.len());
    frame.push(version);
    frame.push(0x00);
    frame.extend_from_slice(&0u16.to_be_bytes());
    frame.push(opcode);
    frame.extend_from_slice(&(body.len() as u32).to_be_bytes());
    frame.extend_from_slice(body);
    frame
}

fn cassandra_string(value: &str) -> Vec<u8> {
    let bytes = value.as_bytes();
    let mut encoded = Vec::with_capacity(2 + bytes.len());
    encoded.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
    encoded.extend_from_slice(bytes);
    encoded
}

pub(crate) fn cassandra_read_frame(stream: &mut TcpStream) -> Result<CassandraFrame> {
    let mut header = [0u8; 9];
    stream
        .read_exact(&mut header)
        .context("failed to read cassandra header")?;
    let body_len = u32::from_be_bytes(header[5..9].try_into().unwrap_or([0, 0, 0, 0])) as usize;
    let mut body = vec![0u8; body_len];
    if body_len > 0 {
        stream
            .read_exact(&mut body)
            .context("failed to read cassandra body")?;
    }
    Ok(CassandraFrame {
        opcode: header[4],
        body,
    })
}
