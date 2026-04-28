use anyhow::{Context, Result};
use serde_json::json;
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::time::Duration;

use super::*;

pub(crate) fn scan_ldap(target: &OpenService, context: &PluginContext) -> Result<Option<PluginFinding>> {
    if brute_force_disabled() {
        return Ok(None);
    }
    if ldap_bind_and_search(target, "", "", context.timeout_secs)? {
        return Ok(Some(PluginFinding {
            plugin: "ldap".to_string(),
            target: target.clone(),
            status: "anonymous-access".to_string(),
            details: BTreeMap::from([
                ("service".to_string(), json!("ldap")),
                ("port".to_string(), json!(target.port)),
                ("type".to_string(), json!("anonymous-access")),
            ]),
        }));
    }

    for username in usernames_for_service("ldap", context) {
        for password in passwords_for_user(Some(username.as_str()), context) {
            if ldap_bind_and_search(target, &username, &password, context.timeout_secs)? {
                return Ok(Some(PluginFinding {
                    plugin: "ldap".to_string(),
                    target: target.clone(),
                    status: "weak-password".to_string(),
                    details: BTreeMap::from([
                        ("service".to_string(), json!("ldap")),
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

pub(crate) fn ldap_bind_and_search(
    target: &OpenService,
    username: &str,
    password: &str,
    timeout_secs: u64,
) -> Result<bool> {
    let timeout = Duration::from_secs(timeout_secs.max(1));
    match connect_stream(target, timeout) {
        Ok(mut stream) => match ldap_bind_and_search_with_stream(&mut stream, username, password) {
            Ok(true) => Ok(true),
            Ok(false) => Ok(false),
            Err(_) => {
                let mut tls_stream = connect_tls_stream(target, timeout)?;
                ldap_bind_and_search_with_stream(&mut tls_stream, username, password)
            }
        },
        Err(_) => {
            let mut tls_stream = connect_tls_stream(target, timeout)?;
            ldap_bind_and_search_with_stream(&mut tls_stream, username, password)
        }
    }
}

pub(crate) fn ldap_bind_and_search_with_stream<S>(
    stream: &mut S,
    username: &str,
    password: &str,
) -> Result<bool>
where
    S: Read + Write,
{
    write_and_flush_io(
        stream,
        &ldap_bind_request(1, &ldap_bind_dn(username), password),
    )?;
    let bind_response = read_available_bytes_io(stream)?;
    if bind_response.is_empty() {
        anyhow::bail!("missing ldap bind response");
    }
    if bind_response.first().copied() != Some(0x30) {
        anyhow::bail!("invalid ldap bind response");
    }
    if !ldap_operation_succeeded(&bind_response, 0x61) {
        return Ok(false);
    }

    write_and_flush_io(stream, &ldap_search_request(2))?;
    let search_response = read_available_bytes_io(stream)?;
    if search_response.is_empty() {
        anyhow::bail!("missing ldap search response");
    }
    if search_response.first().copied() != Some(0x30) {
        anyhow::bail!("invalid ldap search response");
    }
    Ok(ldap_search_succeeded(&search_response))
}

pub(crate) fn ldap_bind_dn(username: &str) -> String {
    if username.is_empty() {
        return String::new();
    }
    if username.contains('=') || username.contains(',') {
        username.to_string()
    } else {
        format!("cn={username},dc=example,dc=com")
    }
}

pub(crate) fn ldap_bind_request(message_id: i32, dn: &str, password: &str) -> Vec<u8> {
    let mut bind_body = Vec::new();
    bind_body.extend(ber_integer(message_id));

    let mut request = Vec::new();
    request.extend(ber_integer(3));
    request.extend(ber_octet_string(dn.as_bytes()));
    request.extend(ber_tlv(0x80, password.as_bytes()));
    bind_body.extend(ber_tlv(0x60, &request));

    ber_tlv(0x30, &bind_body)
}

pub(crate) fn ldap_search_request(message_id: i32) -> Vec<u8> {
    let mut search_body = Vec::new();
    search_body.extend(ber_octet_string(b""));
    search_body.extend(ber_enumerated(0));
    search_body.extend(ber_enumerated(0));
    search_body.extend(ber_integer(0));
    search_body.extend(ber_integer(0));
    search_body.extend(ber_boolean(false));
    search_body.extend(ber_tlv(0x87, b"objectClass"));
    search_body.extend(ber_tlv(0x30, &[]));

    let mut message = Vec::new();
    message.extend(ber_integer(message_id));
    message.extend(ber_tlv(0x63, &search_body));

    ber_tlv(0x30, &message)
}

pub(crate) fn ldap_operation_succeeded(response: &[u8], operation_tag: u8) -> bool {
    response.windows(5).any(|window| {
        window[0] == operation_tag && window[2] == 0x0a && window[3] == 0x01 && window[4] == 0x00
    }) || response
        .windows(3)
        .any(|window| window == [0x0a, 0x01, 0x00])
        && response.contains(&operation_tag)
}

pub(crate) fn ldap_search_succeeded(response: &[u8]) -> bool {
    response.contains(&0x64) || ldap_operation_succeeded(response, 0x65)
}

pub(crate) fn ber_tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(2 + value.len());
    encoded.push(tag);
    encoded.extend(ber_length(value.len()));
    encoded.extend_from_slice(value);
    encoded
}

pub(crate) fn ber_length(length: usize) -> Vec<u8> {
    if length < 0x80 {
        vec![length as u8]
    } else {
        let mut bytes = Vec::new();
        let mut value = length;
        while value > 0 {
            bytes.push((value & 0xff) as u8);
            value >>= 8;
        }
        bytes.reverse();
        let mut encoded = vec![0x80 | bytes.len() as u8];
        encoded.extend(bytes);
        encoded
    }
}

pub(crate) fn ber_integer(value: i32) -> Vec<u8> {
    ber_tlv(0x02, &[(value & 0xff) as u8])
}

pub(crate) fn ber_enumerated(value: u8) -> Vec<u8> {
    ber_tlv(0x0a, &[value])
}

pub(crate) fn ber_boolean(value: bool) -> Vec<u8> {
    ber_tlv(0x01, &[if value { 0xff } else { 0x00 }])
}

pub(crate) fn ber_octet_string(value: &[u8]) -> Vec<u8> {
    ber_tlv(0x04, value)
}

pub(crate) fn snmp_get_sysdescr(
    target: &OpenService,
    community: &str,
    timeout_secs: u64,
) -> Result<Option<String>> {
    let timeout = Duration::from_secs(timeout_secs.max(1));
    let socket = UdpSocket::bind("0.0.0.0:0").context("failed to bind SNMP udp socket")?;
    socket
        .set_read_timeout(Some(timeout))
        .context("failed to set SNMP read timeout")?;
    socket
        .set_write_timeout(Some(timeout))
        .context("failed to set SNMP write timeout")?;
    let target_address = format!("{}:{}", target.host, target.port);
    let socket_addr = target_address
        .to_socket_addrs()
        .with_context(|| format!("failed to resolve SNMP address {target_address}"))?
        .next()
        .with_context(|| format!("no socket addresses for SNMP target {target_address}"))?;

    let request = snmp_get_request(community, 1);
    socket
        .send_to(&request, socket_addr)
        .context("failed to send SNMP request")?;

    let mut buffer = [0u8; 2048];
    let (size, _) = socket
        .recv_from(&mut buffer)
        .context("failed to receive SNMP response")?;
    Ok(parse_snmp_response(&buffer[..size]))
}

pub(crate) fn snmp_get_request(community: &str, request_id: i32) -> Vec<u8> {
    let oid = [0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00];
    let varbind = ber_tlv(
        0x30,
        &[
            ber_tlv(0x06, &oid),
            ber_tlv(0x05, &[]), // NULL
        ]
        .concat(),
    );
    let varbinds = ber_tlv(0x30, &varbind);
    let pdu = ber_tlv(
        0xa0,
        &[
            ber_integer(request_id),
            ber_integer(0),
            ber_integer(0),
            varbinds,
        ]
        .concat(),
    );

    ber_tlv(
        0x30,
        &[ber_integer(1), ber_octet_string(community.as_bytes()), pdu].concat(),
    )
}

pub(crate) fn parse_snmp_response(response: &[u8]) -> Option<String> {
    if !response.contains(&0xa2) {
        return None;
    }
    if !response
        .windows(6)
        .any(|window| window == [0x02, 0x01, 0x00, 0x02, 0x01, 0x00])
    {
        return None;
    }

    let oid_marker = [0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00];
    let oid_index = response
        .windows(oid_marker.len())
        .position(|window| window == oid_marker)?;
    let value_index = oid_index + oid_marker.len();
    if value_index >= response.len() {
        return Some(String::new());
    }

    match response[value_index] {
        0x04 => {
            let (length, len_len) = parse_ber_length(response.get(value_index + 1..)?)?;
            let start = value_index + 1 + len_len;
            let end = start + length;
            if end > response.len() {
                return None;
            }
            Some(
                String::from_utf8_lossy(&response[start..end])
                    .trim()
                    .to_string(),
            )
        }
        0x80 => Some(String::new()),
        _ => Some(String::new()),
    }
}

pub(crate) fn parse_ber_length(bytes: &[u8]) -> Option<(usize, usize)> {
    let first = *bytes.first()?;
    if first & 0x80 == 0 {
        Some((first as usize, 1))
    } else {
        let count = (first & 0x7f) as usize;
        if count == 0 || bytes.len() < 1 + count {
            return None;
        }
        let mut length = 0usize;
        for byte in &bytes[1..=count] {
            length = (length << 8) | (*byte as usize);
        }
        Some((length, 1 + count))
    }
}
