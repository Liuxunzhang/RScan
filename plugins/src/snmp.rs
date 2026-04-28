use anyhow::Result;
use serde_json::json;
use std::collections::BTreeMap;

use super::*;

pub(crate) fn scan_snmp(target: &OpenService, timeout_secs: u64) -> Result<Option<PluginFinding>> {
    if brute_force_disabled() {
        return Ok(None);
    }
    for community in DEFAULT_SNMP_COMMUNITIES {
        if let Some(system) = snmp_get_sysdescr(target, community, timeout_secs)? {
            return Ok(Some(PluginFinding {
                plugin: "snmp".to_string(),
                target: target.clone(),
                status: "weak-community".to_string(),
                details: BTreeMap::from([
                    ("service".to_string(), json!("snmp")),
                    ("port".to_string(), json!(target.port)),
                    ("type".to_string(), json!("weak-community")),
                    ("community".to_string(), json!(community)),
                    ("system".to_string(), json!(system)),
                ]),
            }));
        }
    }

    Ok(None)
}
