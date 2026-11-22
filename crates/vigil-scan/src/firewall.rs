//! Windows Defender Firewall rules in the scan, READ-ONLY. The rules are read with the same reader
//! and judged with the same flags as the Firewall rules page (`vigil_sys::firewall`), so the report,
//! the AI review and the page agree. Only rules with a flag are kept in the inventory
//! (`sysconfig.firewall_rules`); they are judged in `posture.rs`.

use serde_json::{Value, json};

/// The most flagged rules kept in the inventory.
const KEEP: usize = 200;

/// Remote Desktop's own rules (Windows' "Remote Desktop" group on port 3389) are left to the
/// Remote Desktop setting, which the scan already reports: one finding, not three.
#[cfg(windows)]
fn covered_elsewhere(rule: &vigil_sys::firewall::FirewallRule) -> bool {
    rule.builtin && rule.flags.iter().all(|f| f.code == "remote_access" && f.port == 3389)
}

/// The rules with a flag, plus counts. `{"error": "..."}` when the firewall could not be read.
#[cfg(windows)]
pub(crate) fn collect() -> Value {
    let firewall = match vigil_sys::firewall::read(std::time::Duration::from_secs(30)) {
        Ok(firewall) => firewall,
        Err(error) => return json!({"error": error.to_string()}),
    };
    let summary = vigil_sys::firewall::summarize(&firewall.rules);
    let mut kept: Vec<&vigil_sys::firewall::FirewallRule> = firewall
        .rules
        .iter()
        .filter(|r| !r.flags.is_empty() && !covered_elsewhere(r))
        .collect();
    // Rules left for removed programs can number in the hundreds: the warnings come first, so
    // the cap never pushes one out.
    kept.sort_by_key(|r| !r.flags.iter().any(|f| f.warn));
    let flagged: Vec<Value> = kept
        .into_iter()
        .take(KEEP)
        .map(|r| {
            json!({
                "name": r.name,
                "group": r.group,
                "builtin": r.builtin,
                "direction": r.direction,
                "action": r.action,
                "profiles": r.profiles,
                "program": r.program,
                "program_exists": r.program_exists,
                "service": r.service,
                "protocol": r.protocol_name,
                "local_ports": r.local_ports,
                "remote_addresses": r.remote_addresses,
                "edge_traversal": r.edge_traversal,
                "flags": r.flags.iter().map(|f| f.code).collect::<Vec<_>>(),
                "port": r.flags.iter().map(|f| f.port).max().unwrap_or(0),
            })
        })
        .collect();
    json!({
        "total": summary.total,
        "inbound_allow": summary.inbound_allow,
        "missing": summary.missing,
        "flagged": flagged,
    })
}

#[cfg(not(windows))]
pub(crate) fn collect() -> Value {
    json!({"error": "not available on this system"})
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reads this computer's firewall (read-only) and prints counts only:
    /// `cargo test -p vigil-scan firewall::tests::live_counts -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn live_counts() {
        let started = std::time::Instant::now();
        let rules = collect();
        let flagged = rules["flagged"].as_array().cloned().unwrap_or_default();
        let count = |code: &str| {
            flagged
                .iter()
                .filter(|r| r["flags"].as_array().is_some_and(|f| f.iter().any(|c| c == code)))
                .count()
        };
        println!(
            "in {:?}: {} rules, {} flagged (open_public {}, remote_access {}, writable_program {}, missing_program {}), error: {}",
            started.elapsed(),
            rules["total"],
            flagged.len(),
            count("open_public"),
            count("remote_access"),
            count("writable_program"),
            count("missing_program"),
            rules.get("error").is_some(),
        );
    }
}
