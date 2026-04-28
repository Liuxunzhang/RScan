use anyhow::Result;
use serde_json::json;
use std::collections::BTreeMap;

use super::*;

pub(crate) fn scan_netbios(target: &OpenService, timeout_secs: u64) -> Result<Option<PluginFinding>> {
    if let Some(info) = netbios_probe(target, timeout_secs)? {
        let mut details = BTreeMap::from([("port".to_string(), json!(target.port))]);
        if !info.computer_name.is_empty() {
            details.insert("computer_name".to_string(), json!(info.computer_name));
        }
        if !info.domain_name.is_empty() {
            details.insert("domain_name".to_string(), json!(info.domain_name));
        }
        if !info.netbios_domain.is_empty() {
            details.insert("netbios_domain".to_string(), json!(info.netbios_domain));
        }
        if !info.netbios_computer.is_empty() {
            details.insert("netbios_computer".to_string(), json!(info.netbios_computer));
        }
        if !info.workstation_service.is_empty() {
            details.insert(
                "workstation_service".to_string(),
                json!(info.workstation_service),
            );
        }
        if !info.server_service.is_empty() {
            details.insert("server_service".to_string(), json!(info.server_service));
        }
        if !info.domain_controllers.is_empty() {
            details.insert(
                "domain_controllers".to_string(),
                json!(info.domain_controllers),
            );
        }
        if !info.os_version.is_empty() {
            details.insert("os_version".to_string(), json!(info.os_version));
        }
        return Ok(Some(PluginFinding {
            plugin: "netbios".to_string(),
            target: target.clone(),
            status: "identified".to_string(),
            details,
        }));
    }

    Ok(None)
}

pub(crate) fn netbios_session_request(name: &str) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(b"\x81\x00\x00D ");
    payload.extend_from_slice(&netbios_encode_name(name));
    payload.extend_from_slice(NETBIOS_SESSION_REQUEST_SUFFIX);
    payload
}

pub(crate) fn netbios_encode_name(name: &str) -> Vec<u8> {
    format!("{name:<16}")
        .bytes()
        .flat_map(|byte| [((byte >> 4) & 0x0f) + b'A', (byte & 0x0f) + b'A'])
        .collect()
}

pub(crate) fn parse_netbios_ntlm_response(input: &[u8]) -> Option<NetBiosInfo> {
    if input.len() < 48 {
        return None;
    }

    let target_info_length = u16::from_le_bytes([*input.get(43)?, *input.get(44)?]) as usize;
    if input.len() < 47 + target_info_length {
        return None;
    }
    let os_bytes = &input[47 + target_info_length..];
    let os_text = String::from_utf8_lossy(
        &os_bytes
            .iter()
            .copied()
            .filter(|byte| *byte != 0)
            .collect::<Vec<_>>(),
    )
    .trim_end_matches('|')
    .to_string();

    let start = input.windows(7).position(|window| window == b"NTLMSSP")?;
    if input.len() < start + 45 {
        return None;
    }
    let length = u16::from_le_bytes([input[start + 40], input[start + 41]]) as usize;
    let offset = input[start + 44] as usize;
    if input.len() < start + offset + length {
        return None;
    }

    let mut info = NetBiosInfo {
        os_version: os_text,
        ..NetBiosInfo::default()
    };
    let mut index = start + offset;
    let end = start + offset + length;
    while index + 4 <= end && index + 4 <= input.len() {
        let item_type = &input[index..index + 2];
        let item_len = u16::from_le_bytes([input[index + 2], input[index + 3]]) as usize;
        index += 4;
        if item_type == b"\x00\x00" || index + item_len > input.len() {
            break;
        }
        let content = String::from_utf8_lossy(
            &input[index..index + item_len]
                .iter()
                .copied()
                .filter(|byte| *byte != 0)
                .collect::<Vec<_>>(),
        )
        .to_string();
        match item_type {
            b"\x01\x00" => info.netbios_computer = content,
            b"\x02\x00" => info.netbios_domain = content,
            b"\x03\x00" => info.computer_name = content,
            b"\x04\x00" => info.domain_name = content,
            _ => {}
        }
        index += item_len;
    }

    if info == NetBiosInfo::default() {
        None
    } else {
        Some(info)
    }
}

pub(crate) fn join_netbios(base: &mut NetBiosInfo, extra: &NetBiosInfo) {
    if !extra.computer_name.is_empty() {
        base.computer_name = extra.computer_name.clone();
    }
    if !extra.netbios_domain.is_empty() {
        base.netbios_domain = extra.netbios_domain.clone();
    }
    if !extra.netbios_computer.is_empty() {
        base.netbios_computer = extra.netbios_computer.clone();
    }
    if !extra.domain_name.is_empty() {
        base.domain_name = extra.domain_name.clone();
    }
    if !extra.os_version.is_empty() {
        base.os_version = extra.os_version.clone();
    }
}
