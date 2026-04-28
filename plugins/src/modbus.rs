use anyhow::Result;
use serde_json::json;
use std::collections::BTreeMap;

use super::*;

pub(crate) fn scan_modbus(target: &OpenService, timeout_secs: u64) -> Result<Option<PluginFinding>> {
    if let Some(device_info) = modbus_probe(target, timeout_secs)? {
        return Ok(Some(PluginFinding {
            plugin: "modbus".to_string(),
            target: target.clone(),
            status: "unauthorized-access".to_string(),
            details: BTreeMap::from([
                ("service".to_string(), json!("modbus")),
                ("port".to_string(), json!(target.port)),
                ("type".to_string(), json!("unauthorized-access")),
                ("device_info".to_string(), json!(device_info)),
            ]),
        }));
    }

    Ok(None)
}

pub(crate) fn modbus_probe(target: &OpenService, timeout_secs: u64) -> Result<Option<String>> {
    let response = send_tcp_payload(target, &modbus_request_packet(), timeout_secs)?;
    let bytes = response.as_bytes();
    if !is_valid_modbus_response(bytes) {
        return Ok(None);
    }

    Ok(Some(parse_modbus_response(bytes)))
}

pub(crate) fn modbus_request_packet() -> Vec<u8> {
    vec![
        0x00, 0x01, // transaction id
        0x00, 0x00, // protocol id
        0x00, 0x06, // length
        0x01, // unit id
        0x01, // function code: Read Coils
        0x00, 0x00, // starting address
        0x00, 0x01, // quantity
    ]
}

pub(crate) fn is_valid_modbus_response(response: &[u8]) -> bool {
    if response.len() < 9 {
        return false;
    }

    let protocol = u16::from_be_bytes(response[2..4].try_into().unwrap_or([0xff, 0xff]));
    if protocol != 0 {
        return false;
    }

    response[7] != 0x81
}

pub(crate) fn parse_modbus_response(response: &[u8]) -> String {
    if response.len() < 9 {
        return String::new();
    }

    let unit_id = response[6];
    let function_code = response[7];
    let mut info = format!("Unit ID: {unit_id}, Function: 0x{function_code:02X}");

    if function_code == 0x01 && response.len() >= 10 {
        let byte_count = response[8] as usize;
        if byte_count > 0 && response.len() >= 9 + byte_count {
            let coil_value = response[9] & 0x01;
            info.push_str(&format!(", Coil Status: {coil_value}"));
        }
    }

    info
}
