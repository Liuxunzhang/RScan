//! SMBGhost (CVE-2020-0796) detection plugin.

use crate::connection::{connect_stream, read_available_bytes, write_and_flush};
use crate::exploit_assets::SMBGHOST_PROBE;
use crate::runtime::brute_force_disabled;
use crate::{OpenService, PluginFinding};
use anyhow::Result;
use serde_json::json;
use std::collections::BTreeMap;
use std::time::Duration;
pub(crate) fn scan_smbghost(
    target: &OpenService,
    timeout_secs: u64,
) -> Result<Option<PluginFinding>> {
    if brute_force_disabled() {
        return Ok(None);
    }
    if detect_smbghost(target, timeout_secs)? {
        return Ok(Some(PluginFinding {
            plugin: "smbghost".to_string(),
            target: target.clone(),
            status: "vulnerable".to_string(),
            details: BTreeMap::from([
                ("service".to_string(), json!("smb")),
                ("port".to_string(), json!(target.port)),
                ("type".to_string(), json!("cve-2020-0796")),
                ("name".to_string(), json!("SmbGhost")),
            ]),
        }));
    }

    Ok(None)
}
fn detect_smbghost(target: &OpenService, timeout_secs: u64) -> Result<bool> {
    let timeout = Duration::from_secs(timeout_secs.max(1));
    let mut stream = connect_stream(target, timeout)?;
    write_and_flush(&mut stream, SMBGHOST_PROBE)?;
    let response = read_available_bytes(&mut stream)?;
    Ok(response.len() >= 76
        && response.windows(6).any(|window| window == b"Public")
        && response.get(72..74) == Some(&[0x11, 0x03])
        && response.get(74..76) == Some(&[0x02, 0x00]))
}
