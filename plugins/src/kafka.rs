use anyhow::{Context, Result};
use serde_json::json;
use std::collections::BTreeMap;
use std::io::Read;
use std::net::TcpStream;
use std::time::Duration;

use super::*;

pub(crate) fn scan_kafka(target: &OpenService, context: &PluginContext) -> Result<Option<PluginFinding>> {
    if brute_force_disabled() {
        return Ok(None);
    }
    if kafka_login(target, None, None, context.timeout_secs)? {
        return Ok(Some(PluginFinding {
            plugin: "kafka".to_string(),
            target: target.clone(),
            status: "unauthorized-access".to_string(),
            details: BTreeMap::from([
                ("service".to_string(), json!("kafka")),
                ("port".to_string(), json!(target.port)),
                ("type".to_string(), json!("unauthorized-access")),
            ]),
        }));
    }

    for username in usernames_for_service("kafka", context) {
        for password in passwords_for_user(Some(username.as_str()), context) {
            if kafka_login(
                target,
                Some(username.as_str()),
                Some(password.as_str()),
                context.timeout_secs,
            )? {
                return Ok(Some(PluginFinding {
                    plugin: "kafka".to_string(),
                    target: target.clone(),
                    status: "weak-password".to_string(),
                    details: BTreeMap::from([
                        ("service".to_string(), json!("kafka")),
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

pub(crate) fn kafka_login(
    target: &OpenService,
    username: Option<&str>,
    password: Option<&str>,
    timeout_secs: u64,
) -> Result<bool> {
    let timeout = Duration::from_secs(timeout_secs.max(1));
    let mut stream = connect_stream(target, timeout)?;

    if let (Some(username), Some(password)) = (username, password) {
        write_and_flush(&mut stream, &kafka_sasl_handshake_request(1, "PLAIN"))?;
        let handshake = match kafka_read_frame(&mut stream) {
            Ok(frame) => frame,
            Err(_) => return Ok(false),
        };
        if kafka_response_correlation(&handshake) != Some(1)
            || kafka_sasl_handshake_error(&handshake).unwrap_or(i16::MAX) != 0
        {
            return Ok(false);
        }

        write_and_flush(
            &mut stream,
            &kafka_sasl_plain_auth_frame(username, password),
        )?;
        write_and_flush(&mut stream, &kafka_api_versions_request(2))?;
        let response = match kafka_read_frame(&mut stream) {
            Ok(frame) => frame,
            Err(_) => return Ok(false),
        };
        Ok(kafka_response_correlation(&response) == Some(2))
    } else {
        write_and_flush(&mut stream, &kafka_api_versions_request(1))?;
        let response = match kafka_read_frame(&mut stream) {
            Ok(frame) => frame,
            Err(_) => return Ok(false),
        };
        Ok(kafka_response_correlation(&response) == Some(1))
    }
}

pub(crate) fn kafka_api_versions_request(correlation_id: i32) -> Vec<u8> {
    kafka_request(18, 0, correlation_id, "rscan", &[])
}

pub(crate) fn kafka_sasl_handshake_request(correlation_id: i32, mechanism: &str) -> Vec<u8> {
    kafka_request(17, 1, correlation_id, "rscan", &kafka_string(mechanism))
}

pub(crate) fn kafka_sasl_plain_auth_frame(username: &str, password: &str) -> Vec<u8> {
    let payload = format!("\u{0}{username}\u{0}{password}").into_bytes();
    let mut frame = Vec::with_capacity(payload.len() + 4);
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(&payload);
    frame
}

pub(crate) fn kafka_request(
    api_key: i16,
    api_version: i16,
    correlation_id: i32,
    client_id: &str,
    body: &[u8],
) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&api_key.to_be_bytes());
    payload.extend_from_slice(&api_version.to_be_bytes());
    payload.extend_from_slice(&correlation_id.to_be_bytes());
    payload.extend_from_slice(&kafka_string(client_id));
    payload.extend_from_slice(body);

    let mut frame = Vec::with_capacity(payload.len() + 4);
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(&payload);
    frame
}

pub(crate) fn kafka_string(value: &str) -> Vec<u8> {
    let bytes = value.as_bytes();
    let mut encoded = Vec::with_capacity(bytes.len() + 2);
    encoded.extend_from_slice(&(bytes.len() as i16).to_be_bytes());
    encoded.extend_from_slice(bytes);
    encoded
}

pub(crate) fn kafka_read_frame(stream: &mut TcpStream) -> Result<Vec<u8>> {
    let mut header = [0u8; 4];
    stream
        .read_exact(&mut header)
        .context("failed to read kafka frame header")?;
    let length = u32::from_be_bytes(header) as usize;
    let mut payload = vec![0u8; length];
    stream
        .read_exact(&mut payload)
        .context("failed to read kafka frame payload")?;
    Ok(payload)
}

pub(crate) fn kafka_response_correlation(payload: &[u8]) -> Option<i32> {
    let bytes: [u8; 4] = payload.get(0..4)?.try_into().ok()?;
    Some(i32::from_be_bytes(bytes))
}

pub(crate) fn kafka_sasl_handshake_error(payload: &[u8]) -> Option<i16> {
    let bytes: [u8; 2] = payload.get(4..6)?.try_into().ok()?;
    Some(i16::from_be_bytes(bytes))
}
