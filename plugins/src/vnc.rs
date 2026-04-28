use anyhow::{Context, Result};
use serde_json::json;
use std::collections::BTreeMap;
use std::io::Read;
use std::time::Duration;

use super::*;

pub(crate) fn scan_vnc(target: &OpenService, context: &PluginContext) -> Result<Option<PluginFinding>> {
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

pub(crate) fn vnc_login(target: &OpenService, password: &str, timeout_secs: u64) -> Result<bool> {
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

pub(crate) fn findnet_probe(
    target: &OpenService,
    timeout_secs: u64,
) -> Result<Option<(String, Vec<String>, Vec<String>)>> {
    let timeout = Duration::from_secs(timeout_secs.max(1));
    let mut stream = connect_stream(target, timeout)?;
    write_and_flush(&mut stream, FINDNET_PROBE_ONE)?;
    let _ = read_available_bytes(&mut stream)?;
    write_and_flush(&mut stream, FINDNET_PROBE_TWO)?;
    let response = read_available_bytes(&mut stream)?;
    if response.len() < 42 {
        return Ok(None);
    }

    Ok(parse_findnet_payload(&response[42..]))
}

pub(crate) fn netbios_probe(target: &OpenService, timeout_secs: u64) -> Result<Option<NetBiosInfo>> {
    let mut info = netbios_query_udp(&target.host, timeout_secs)?.unwrap_or_default();
    if let Some(smb_info) = netbios_query_tcp(target, &info, timeout_secs)? {
        join_netbios(&mut info, &smb_info);
    }

    if info.computer_name.is_empty()
        && info.domain_name.is_empty()
        && info.netbios_domain.is_empty()
        && info.netbios_computer.is_empty()
        && info.workstation_service.is_empty()
        && info.server_service.is_empty()
        && info.domain_controllers.is_empty()
        && info.os_version.is_empty()
    {
        Ok(None)
    } else {
        Ok(Some(info))
    }
}

pub(crate) fn netbios_query_udp(host: &str, timeout_secs: u64) -> Result<Option<NetBiosInfo>> {
    let timeout = Duration::from_secs(timeout_secs.max(1));
    let socket = UdpSocket::bind("0.0.0.0:0").context("failed to bind netbios udp socket")?;
    socket
        .set_read_timeout(Some(timeout))
        .context("failed to set netbios udp read timeout")?;
    socket
        .set_write_timeout(Some(timeout))
        .context("failed to set netbios udp write timeout")?;
    socket
        .connect(format!("{host}:137"))
        .with_context(|| format!("failed to connect udp to {host}:137"))?;
    socket
        .send(NETBIOS_UDP_PROBE)
        .context("failed to send netbios udp probe")?;
    let mut buffer = [0u8; 2048];
    let size = match socket.recv(&mut buffer) {
        Ok(size) => size,
        Err(_) => return Ok(None),
    };
    Ok(parse_netbios_udp_response(&buffer[..size]))
}

pub(crate) fn netbios_query_tcp(
    target: &OpenService,
    info: &NetBiosInfo,
    timeout_secs: u64,
) -> Result<Option<NetBiosInfo>> {
    let timeout = Duration::from_secs(timeout_secs.max(1));
    let mut stream = match connect_stream(target, timeout) {
        Ok(stream) => stream,
        Err(_) => return Ok(None),
    };

    if !info.server_service.is_empty() || !info.workstation_service.is_empty() {
        let seed = if !info.server_service.is_empty() {
            &info.server_service
        } else {
            &info.workstation_service
        };
        let request = netbios_session_request(seed);
        if write_and_flush(&mut stream, &request).is_err()
            || read_available_bytes(&mut stream).is_err()
        {
            return Ok(None);
        }
    }

    if write_and_flush(&mut stream, NETBIOS_NEGOTIATE_ONE).is_err()
        || read_available_bytes(&mut stream).is_err()
    {
        return Ok(None);
    }
    if write_and_flush(&mut stream, NETBIOS_NEGOTIATE_TWO).is_err() {
        return Ok(None);
    }
    let response = match read_available_bytes(&mut stream) {
        Ok(bytes) => bytes,
        Err(_) => return Ok(None),
    };
    Ok(parse_netbios_ntlm_response(&response))
}

pub(crate) fn detect_smbghost(target: &OpenService, timeout_secs: u64) -> Result<bool> {
    let timeout = Duration::from_secs(timeout_secs.max(1));
    let mut stream = connect_stream(target, timeout)?;
    write_and_flush(&mut stream, SMBGHOST_PROBE)?;
    let response = read_available_bytes(&mut stream)?;
    Ok(response.len() >= 76
        && response.windows(6).any(|window| window == b"Public")
        && response.get(72..74) == Some(&[0x11, 0x03])
        && response.get(74..76) == Some(&[0x02, 0x00]))
}

pub(crate) fn parse_findnet_payload(payload: &[u8]) -> Option<(String, Vec<String>, Vec<String>)> {
    let marker = payload
        .windows(FINDNET_END_MARKER.len())
        .position(|window| window == FINDNET_END_MARKER)?;
    let relevant = &payload[..marker.saturating_sub(4)];
    let encoded = hex::encode(relevant);

    let hostname_hex = encoded
        .as_bytes()
        .chunks(4)
        .take_while(|chunk| *chunk != b"0000")
        .flat_map(|chunk| chunk.iter().copied())
        .collect::<Vec<_>>();
    let hostname = decode_utf16le_hex(std::str::from_utf8(&hostname_hex).ok()?)
        .filter(|value| is_valid_findnet_hostname(value))
        .unwrap_or_default();

    let mut ipv4 = Vec::new();
    let mut ipv6 = Vec::new();
    let mut seen = BTreeSet::new();
    for segment in encoded.replace("0700", "").split("000000") {
        if segment.is_empty() {
            continue;
        }
        let normalized = if segment.len() % 2 == 0 {
            segment.to_string()
        } else {
            format!("{segment}0")
        };
        let bytes = match hex::decode(&normalized) {
            Ok(bytes) => bytes,
            Err(_) => continue,
        };
        let candidate = clean_findnet_address(&bytes);
        if candidate.is_empty() || !seen.insert(candidate.clone()) {
            continue;
        }
        if candidate.contains(':') {
            ipv6.push(candidate);
        } else if candidate.parse::<std::net::Ipv4Addr>().is_ok() {
            ipv4.push(candidate);
        }
    }

    if hostname.is_empty() && ipv4.is_empty() && ipv6.is_empty() {
        None
    } else {
        Some((hostname, ipv4, ipv6))
    }
}

pub(crate) fn decode_utf16le_hex(value: &str) -> Option<String> {
    let mut padded = value.to_string();
    while padded.len() % 4 != 0 {
        padded.push('0');
    }
    let mut output = String::new();
    for chunk in padded.as_bytes().chunks(4) {
        let text = std::str::from_utf8(chunk).ok()?;
        let swapped = format!("{}{}", &text[2..4], &text[0..2]);
        let code = u16::from_str_radix(&swapped, 16).ok()?;
        if let Some(ch) = char::from_u32(code as u32).filter(|ch| !ch.is_control()) {
            output.push(ch);
        }
    }
    Some(output)
}

pub(crate) fn is_valid_findnet_hostname(value: &str) -> bool {
    if value.is_empty() || value.len() > 255 {
        return false;
    }
    let bytes = value.as_bytes();
    bytes
        .first()
        .is_some_and(|byte| byte.is_ascii_alphanumeric())
        && bytes
            .last()
            .is_some_and(|byte| byte.is_ascii_alphanumeric())
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
}

pub(crate) fn clean_findnet_address(value: &[u8]) -> String {
    let candidate = String::from_utf8_lossy(value)
        .chars()
        .filter(|ch| !ch.is_control())
        .collect::<String>()
        .trim()
        .to_string();
    if candidate.parse::<std::net::IpAddr>().is_ok() || is_valid_findnet_hostname(&candidate) {
        candidate
    } else {
        String::new()
    }
}

pub(crate) fn parse_netbios_udp_response(input: &[u8]) -> Option<NetBiosInfo> {
    if input.len() < 57 {
        return None;
    }
    let count = *input.get(56)? as usize;
    let data = &input[57..];
    let mut info = NetBiosInfo::default();

    for index in 0..count {
        let start = 18 * index;
        let entry = data.get(start..start + 18)?;
        let name = String::from_utf8_lossy(&entry[..15]).trim().to_string();
        let suffix = entry[15];
        let group = entry[16] >= 128;
        match (suffix, group) {
            (0x00, true) => {
                if info.domain_name.is_empty() {
                    info.domain_name = name.clone();
                    info.group_name = name;
                }
            }
            (0x00, false) => {
                if info.workstation_service.is_empty() {
                    info.workstation_service = name;
                }
            }
            (0x20, _) => {
                if info.server_service.is_empty() {
                    info.server_service = name;
                }
            }
            (0x1c, _) => {
                if info.domain_controllers.is_empty() {
                    info.domain_controllers = name;
                }
            }
            (0x1b, _) => {
                if info.domain_name.is_empty() {
                    info.domain_name = name;
                }
            }
            _ => {}
        }
    }

    if info == NetBiosInfo::default() {
        None
    } else {
        Some(info)
    }
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

pub(crate) fn vnc_key_from_password(password: &str) -> [u8; 8] {
    let mut key = [0u8; 8];
    for (index, byte) in password.as_bytes().iter().take(8).enumerate() {
        key[index] = byte.reverse_bits();
    }
    key
}
