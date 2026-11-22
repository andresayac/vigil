//! Firewall rules: turn one on or off, or delete it (its whole definition is kept so undo can
//! recreate it).
//!
//! The firewall has no unique id the rule list and the cmdlets share, so a rule is named by the
//! fields that tell rules apart: name, direction, program, service, protocol and ports (normalized
//! the same way `vigil_sys::firewall` does). Every action looks the rule up again and refuses
//! unless exactly one rule matches; undo then uses the cmdlets' own id (`InstanceID`) recorded at
//! that moment. Rules of the groups Windows defines can be turned off but never deleted.

use serde_json::{Value, json};

use crate::engine::{Builtin, Outcome, run_fn, undo_fn};
use crate::error::{ActionError, Result, fail};
use crate::params::Params;
use crate::runner::ps_ok;
use crate::store::Store;
use vigil_i18n::tr;

/// Helpers shared by the scripts: the cmdlets' values normalized like the rule list's.
const NORMALIZE: &str = r#"
function One($v) {
    $t = "$v".Trim().ToLowerInvariant()
    if ($t -eq '*' -or $t -eq 'any') { '' } else { $t }
}
function List($v) {
    # Port keywords take one spelling (see vigil_sys::firewall::norm_list); ranges keep their dash.
    $parts = @((@($v) | Where-Object { $null -ne $_ } | ForEach-Object { "$_" }) -join ',' -split ',' |
        ForEach-Object {
            $t = $_.Trim().ToLowerInvariant()
            if ($t -notmatch '[a-z]') { $t } else {
                switch ($t -replace '-', '') {
                    { $_ -in 'rpc', 'any', '*' } { break }
                    { $_ -in 'iphttpsin', 'iphttpsout' } { 'iphttps'; break }
                    'playtodiscovery' { 'ply2disc'; break }
                    default { $_ }
                }
            }
        } | Where-Object { $_ -ne '' })
    One ($parts -join ',')
}
function Proto($v) {
    switch ("$v".Trim()) { 'TCP' { '6' } 'UDP' { '17' } 'ICMPv4' { '1' } 'ICMPv6' { '58' } 'Any' { '256' } '' { '256' } default { "$v".Trim() } }
}
function Answer($table) { [pscustomobject]$table | ConvertTo-Json -Compress -Depth 6 }
"#;

/// Finds the one rule that matches every `PC_*` field, or answers `missing`, `ambiguous` or
/// `policy`. The match runs on the active store, whose display names are in the same language as
/// the rule list's (the persistent store may resolve built-in names in another one); the rule is
/// then taken from the local persistent store by its id. Rules from Group Policy or other sources
/// are not changed.
const FIND: &str = r#"
$dir = if ($env:PC_DIRECTION -eq 'out') { 'Outbound' } else { 'Inbound' }
$want = "$env:PC_NAME"
$found = @(Get-NetFirewallRule -PolicyStore ActiveStore -Direction $dir |
    Where-Object { $_.DisplayName -ceq $want -or $_.ElementName -ceq $want } |
    Where-Object {
        $a = $_ | Get-NetFirewallApplicationFilter
        $s = $_ | Get-NetFirewallServiceFilter
        $p = $_ | Get-NetFirewallPortFilter
        (One ([Environment]::ExpandEnvironmentVariables("$($a.Program)"))) -eq "$env:PC_PROGRAM" -and
        (One $s.Service) -eq "$env:PC_SERVICE" -and
        (Proto $p.Protocol) -eq "$env:PC_PROTOCOL" -and
        (List $p.LocalPort) -eq "$env:PC_LOCALPORTS" -and
        (List $p.RemotePort) -eq "$env:PC_REMOTEPORTS"
    })
if ($found.Count -eq 0) { Answer @{ status = 'missing' }; return }
if ($found.Count -gt 1) { Answer @{ status = 'ambiguous' }; return }
if ("$($found[0].PolicyStoreSourceType)" -ne 'Local' -or "$($found[0].PolicyStoreSource)" -ne 'PersistentStore') {
    Answer @{ status = 'policy' }; return
}
$id = "$($found[0].Name)"
$r = @(Get-NetFirewallRule -Name ([WildcardPattern]::Escape($id)) -ErrorAction SilentlyContinue | Where-Object { $_.Name -ceq $id })
if ($r.Count -ne 1) { Answer @{ status = 'missing' }; return }
$r = $r[0]
$group = "$($r.Group)"
"#;

const SET_STATE: &str = r#"
$was = "$($r.Enabled)" -eq 'True'
if ($env:PC_ENABLE -eq '1') { $r | Enable-NetFirewallRule } else { $r | Disable-NetFirewallRule }
Answer @{ status = 'ok'; id = "$($r.Name)"; was = $was }
"#;

const DELETE: &str = r#"
if ($group.StartsWith('@') -and -not $group.StartsWith('@{')) { Answer @{ status = 'builtin' }; return }
$a = $r | Get-NetFirewallApplicationFilter
$s = $r | Get-NetFirewallServiceFilter
$p = $r | Get-NetFirewallPortFilter
$ad = $r | Get-NetFirewallAddressFilter
$it = $r | Get-NetFirewallInterfaceTypeFilter
$sec = $r | Get-NetFirewallSecurityFilter
function Vals($v) { @(@($v) | Where-Object { $null -ne $_ } | ForEach-Object { "$_" }) }
$def = [ordered]@{
    Name = "$($r.Name)"
    DisplayName = if ("$($r.ElementName)") { "$($r.ElementName)" } else { "$($r.DisplayName)" }
    Description = "$($r.Description)"
    Group = $group
    Direction = "$($r.Direction)"
    Action = "$($r.Action)"
    Enabled = "$($r.Enabled)"
    Profile = "$($r.Profile)"
    EdgeTraversalPolicy = "$($r.EdgeTraversalPolicy)"
    Owner = "$($r.Owner)"
    Program = "$($a.Program)"
    Package = "$($a.Package)"
    Service = "$($s.Service)"
    Protocol = "$($p.Protocol)"
    LocalPort = @(Vals $p.LocalPort)
    RemotePort = @(Vals $p.RemotePort)
    IcmpType = @(Vals $p.IcmpType)
    LocalAddress = @(Vals $ad.LocalAddress)
    RemoteAddress = @(Vals $ad.RemoteAddress)
    InterfaceType = "$($it.InterfaceType)"
    Authentication = "$($sec.Authentication)"
    Encryption = "$($sec.Encryption)"
    OverrideBlockRules = "$($sec.OverrideBlockRules)"
    LocalUser = "$($sec.LocalUser)"
    RemoteUser = "$($sec.RemoteUser)"
    RemoteMachine = "$($sec.RemoteMachine)"
}
$r | Remove-NetFirewallRule
Answer @{ status = 'ok'; rule = $def }
"#;

/// Finds a rule by the cmdlets' id (recorded when the action ran).
const BY_ID: &str = r#"
$id = "$env:PC_ID"
$r = @(Get-NetFirewallRule -Name ([WildcardPattern]::Escape($id)) -ErrorAction SilentlyContinue | Where-Object { $_.Name -ceq $id })
"#;

const RESTORE_STATE: &str = r#"
if ($r.Count -ne 1) { Answer @{ status = 'missing' }; return }
if ($env:PC_ENABLE -eq '1') { $r[0] | Enable-NetFirewallRule } else { $r[0] | Disable-NetFirewallRule }
Answer @{ status = 'ok' }
"#;

/// Recreates a deleted rule from its saved definition. Values "Any" and empty ones are left to
/// the cmdlet's defaults (which are "any").
const RECREATE: &str = r#"
if ($r.Count -gt 0) { Answer @{ status = 'exists' }; return }
$d = $env:PC_RULE | ConvertFrom-Json
$lists = 'LocalPort', 'RemotePort', 'IcmpType', 'LocalAddress', 'RemoteAddress'
$params = @{}
foreach ($k in 'Name', 'DisplayName', 'Description', 'Group', 'Direction', 'Action', 'Enabled', 'Profile',
        'EdgeTraversalPolicy', 'Owner', 'Program', 'Package', 'Service', 'Protocol', 'LocalPort', 'RemotePort',
        'IcmpType', 'LocalAddress', 'RemoteAddress', 'InterfaceType', 'Authentication', 'Encryption', 'LocalUser',
        'RemoteUser', 'RemoteMachine') {
    $vals = @(@($d.$k) | Where-Object { $null -ne $_ } | ForEach-Object { "$_" } | Where-Object { $_ -ne '' -and $_ -ne 'Any' })
    if ($vals.Count -eq 0) { continue }
    if ($lists -contains $k) { $params[$k] = [string[]]$vals } else { $params[$k] = $vals[0] }
}
if ("$($d.OverrideBlockRules)" -eq 'True') { $params['OverrideBlockRules'] = $true }
New-NetFirewallRule @params | Out-Null
Answer @{ status = 'ok' }
"#;

/// The longest rule name accepted (the firewall allows long names; this only bounds the input).
const MAX_NAME: usize = 1024;

/// The rule's identifying fields from the action parameters, as PowerShell values.
fn rule_values(p: &Params<'_>) -> Result<Vec<(&'static str, String)>> {
    let name = p.req_str("name")?;
    let direction = p.req_str("direction")?;
    let protocol = p.req_str("protocol")?;
    if name.trim().is_empty() || name.len() > MAX_NAME || name.contains('\0') {
        return fail(tr!("Invalid firewall rule name."));
    }
    if direction != "in" && direction != "out" {
        return fail(tr!("Unknown firewall rule direction: {0}", direction));
    }
    if protocol.is_empty() || protocol.len() > 3 || !protocol.chars().all(|c| c.is_ascii_digit()) {
        return fail(tr!("Unknown firewall protocol: {0}", protocol));
    }
    let mut values = vec![("name", name), ("direction", direction), ("protocol", protocol)];
    for (env, key) in [
        ("program", "program"),
        ("service", "service"),
        ("localports", "localPorts"),
        ("remoteports", "remotePorts"),
    ] {
        values.push((env, p.str_or_empty(key)));
    }
    Ok(values)
}

/// The name messages use: the resolved display name when the page sent one.
fn label_of(p: &Params<'_>) -> String {
    let label = p.str_or_empty("label");
    let label = if label.is_empty() {
        p.str_or_empty("name")
    } else {
        label
    };
    format!("\"{label}\"")
}

/// Runs a script and reads the JSON object it answers with.
fn answer(script: &str, what: &str, values: &[(&str, String)]) -> Result<Value> {
    let values: Vec<(&str, &str)> = values.iter().map(|(k, v)| (*k, v.as_str())).collect();
    let out = ps_ok(&format!("{NORMALIZE}{script}"), what, 300, &values)?;
    out.lines()
        .rev()
        .map(str::trim)
        .find(|line| line.starts_with('{'))
        .and_then(|line| serde_json::from_str::<Value>(line).ok())
        .ok_or_else(|| ActionError::new(tr!("{0} failed: unexpected answer from PowerShell", what)))
}

fn status_of(answer: &Value) -> &str {
    answer.get("status").and_then(Value::as_str).unwrap_or("")
}

/// The error for a lookup that did not find exactly one rule.
fn not_found(status: &str) -> ActionError {
    match status {
        "ambiguous" => ActionError::new(tr!(
            "Several firewall rules match this one exactly, so Vigil cannot tell which one to change. Use Windows Defender Firewall instead."
        )),
        "policy" => ActionError::new(tr!(
            "Group Policy or another management tool sets this firewall rule, so Vigil does not change it."
        )),
        _ => ActionError::new(tr!("The firewall rule is no longer there. Refresh the list.")),
    }
}

fn set_state(p: Params<'_>, enable: bool) -> Result<Outcome> {
    let mut values = rule_values(&p)?;
    values.push(("enable", if enable { "1" } else { "0" }.into()));
    let label = label_of(&p);
    let what = if enable {
        tr!("turning on the firewall rule")
    } else {
        tr!("turning off the firewall rule")
    };
    let result = answer(&format!("{FIND}{SET_STATE}"), &what, &values)?;
    if status_of(&result) != "ok" {
        return Err(not_found(status_of(&result)));
    }
    let id = result.get("id").and_then(Value::as_str).unwrap_or("");
    let was = result.get("was").and_then(Value::as_bool).unwrap_or(!enable);
    let message = if enable {
        tr!("turned on the firewall rule {0}", label)
    } else {
        tr!("turned off the firewall rule {0}", label)
    };
    Ok(Outcome::new(
        message,
        Some(json!({ "id": id, "enabled": was, "label": p.str_or_empty("label") })),
    ))
}

fn op_rule_disable(p: Params<'_>, _store: &Store, _id: &str) -> Result<Outcome> {
    set_state(p, false)
}

fn op_rule_enable(p: Params<'_>, _store: &Store, _id: &str) -> Result<Outcome> {
    set_state(p, true)
}

fn undo_rule_state(u: Params<'_>, _store: &Store) -> Result<String> {
    let id = u.req_str("id")?;
    let enabled = u.flag("enabled");
    let label = label_of(&u);
    let values = [("id", id), ("enable", if enabled { "1" } else { "0" }.to_string())];
    let result = answer(
        &format!("{BY_ID}{RESTORE_STATE}"),
        &tr!("restoring the firewall rule"),
        &values,
    )?;
    if status_of(&result) != "ok" {
        return fail(tr!("The firewall rule {0} is no longer there.", label));
    }
    Ok(if enabled {
        tr!("turned the firewall rule {0} back on", label)
    } else {
        tr!("turned the firewall rule {0} back off", label)
    })
}

fn op_rule_delete(p: Params<'_>, _store: &Store, _id: &str) -> Result<Outcome> {
    let values = rule_values(&p)?;
    let label = label_of(&p);
    let result = answer(&format!("{FIND}{DELETE}"), &tr!("deleting the firewall rule"), &values)?;
    match status_of(&result) {
        "ok" => {}
        "builtin" => {
            return fail(tr!(
                "{0} belongs to a rule group Windows defines. It can be turned off, but not deleted.",
                label
            ));
        }
        other => return Err(not_found(other)),
    }
    let rule = result.get("rule").cloned().unwrap_or(Value::Null);
    if !rule.get("Name").and_then(Value::as_str).is_some_and(|n| !n.is_empty()) {
        return fail(tr!(
            "deleting the firewall rule failed: unexpected answer from PowerShell"
        ));
    }
    Ok(Outcome::new(
        tr!(
            "deleted the firewall rule {0}; its definition is kept so it can be recreated",
            label
        ),
        Some(json!({ "rule": rule, "label": p.str_or_empty("label") })),
    ))
}

fn undo_rule_delete(u: Params<'_>, _store: &Store) -> Result<String> {
    let rule = u.get("rule");
    let id = rule.get("Name").and_then(Value::as_str).unwrap_or("").to_string();
    if id.is_empty() {
        return fail(tr!("The saved firewall rule is incomplete."));
    }
    let label = label_of(&u);
    let values = [("id", id), ("rule", rule.to_string())];
    let result = answer(
        &format!("{BY_ID}{RECREATE}"),
        &tr!("recreating the firewall rule"),
        &values,
    )?;
    match status_of(&result) {
        "ok" => Ok(tr!("recreated the firewall rule {0}", label)),
        "exists" => fail(tr!(
            "A firewall rule with the same id already exists, so {0} was not recreated.",
            label
        )),
        _ => fail(tr!(
            "recreating the firewall rule failed: unexpected answer from PowerShell"
        )),
    }
}

pub(crate) fn builtin() -> Vec<Builtin> {
    vec![
        (
            "firewall.rule_disable",
            run_fn(op_rule_disable),
            Some(undo_fn(undo_rule_state)),
            false,
        ),
        (
            "firewall.rule_enable",
            run_fn(op_rule_enable),
            Some(undo_fn(undo_rule_state)),
            false,
        ),
        (
            "firewall.rule_delete",
            run_fn(op_rule_delete),
            Some(undo_fn(undo_rule_delete)),
            false,
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use vigil_sys::firewall::{norm_list, norm_one};

    /// The PowerShell helpers normalize exactly like the rule list does (pure string functions:
    /// nothing on the firewall is read or changed).
    #[test]
    fn powershell_normalization_matches_the_rule_list() {
        crate::testing::reset();
        let cases = [
            " 80, 443 ",
            "*",
            "Any",
            "RPC-EPMap",
            "RPCEPMap",
            "5000-5020",
            "5000-5020, IPHTTPS-In",
            "IPHTTPSOut",
            "PlayToDiscovery",
            "Ply2Disc",
            "RPC",
            "135, RPC",
            "",
        ];
        let script = format!(
            "{NORMALIZE}$v = $env:PC_VALUES | ConvertFrom-Json; \
             Answer @{{ list = @($v | ForEach-Object {{ List ($_ -split ';') }}); one = @($v | ForEach-Object {{ One $_ }}); \
             proto = @('TCP', 'udp', 'ICMPv6', 'Any', '47' | ForEach-Object {{ Proto $_ }}) }}"
        );
        let values = serde_json::to_string(&cases).expect("json");
        let out = ps_ok(&script, "normalize", 120, &[("values", &values)]).expect("powershell");
        let got: Value = serde_json::from_str(out.lines().last().unwrap_or("")).expect("answer");
        let list: Vec<String> = cases.iter().map(|c| norm_list(c)).collect();
        let one: Vec<String> = cases.iter().map(|c| norm_one(c)).collect();
        assert_eq!(got["list"], json!(list));
        assert_eq!(got["one"], json!(one));
        assert_eq!(got["proto"], json!(["6", "17", "58", "256", "47"]));
    }

    /// Every script the actions run is valid PowerShell (only parsed, never run).
    #[test]
    fn the_scripts_parse() {
        crate::testing::reset();
        let scripts = [
            format!("{NORMALIZE}{FIND}{SET_STATE}"),
            format!("{NORMALIZE}{FIND}{DELETE}"),
            format!("{NORMALIZE}{BY_ID}{RESTORE_STATE}"),
            format!("{NORMALIZE}{BY_ID}{RECREATE}"),
        ];
        let check = "$errors = $null; \
             [void][System.Management.Automation.Language.Parser]::ParseInput($env:PC_SCRIPT, [ref]$null, [ref]$errors); \
             ($errors | ForEach-Object { $_.Message }) -join ' / '";
        for script in &scripts {
            let out = ps_ok(check, "parse", 120, &[("script", script)]).expect("powershell");
            assert_eq!(out, "", "{script}");
        }
    }
}
