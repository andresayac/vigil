//! Windows Defender Firewall, read-only: the three network profiles and every rule, through the
//! firewall COM API (`INetFwPolicy2`). A few thousand rules take a fraction of a second.
//!
//! Rules have no unique id in this API (two rules may share a name), so each rule gets a key made
//! of its name, direction, program, service, protocol and ports. Rules that share a key are marked
//! `duplicate`; the app refuses to act on them. The analysis helpers (`flags_for`, `analyze`,
//! `summarize`) are pure functions over the rule data.

use std::collections::HashMap;
use std::path::Path;
use std::sync::mpsc;
use std::time::Duration;

use serde::Serialize;
use windows::Win32::NetworkManagement::WindowsFirewall::{
    INetFwPolicy2, INetFwRule, INetFwRule2, NET_FW_ACTION, NET_FW_ACTION_ALLOW, NET_FW_PROFILE_TYPE2,
    NET_FW_PROFILE2_DOMAIN, NET_FW_PROFILE2_PRIVATE, NET_FW_PROFILE2_PUBLIC, NET_FW_RULE_DIR_OUT, NetFwPolicy2,
};
use windows::Win32::System::Com::{
    CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx, CoUninitialize, IDispatch,
};
use windows::Win32::System::Environment::ExpandEnvironmentStringsW;
use windows::Win32::System::Ole::IEnumVARIANT;
use windows::Win32::System::Variant::{VARIANT, VT_DISPATCH, VT_UNKNOWN, VariantClear};
use windows::Win32::UI::Shell::SHLoadIndirectString;
use windows::core::{BSTR, HSTRING, Interface, PCWSTR};

use crate::SysError;
use crate::util::{from_wide, wide};

/// The description `firewall.block` gives the rules it creates.
pub const VIGIL_DESCRIPTION: &str = "Created by Vigil";
/// The display-name prefix of the rules `firewall.block` creates.
pub const VIGIL_PREFIX: &str = "Vigil: ";

/// Ports of remote-access services: an inbound allow rule that opens one lets other computers
/// control this one.
pub const REMOTE_ACCESS_PORTS: [(u16, &str); 6] = [
    (3389, "Remote Desktop"),
    (22, "SSH"),
    (5900, "VNC"),
    (5985, "WinRM"),
    (5986, "WinRM over HTTPS"),
    (23, "Telnet"),
];

/// Protocol numbers the firewall uses.
pub const PROTOCOL_ANY: i32 = 256;
const PROTOCOL_ICMPV4: i32 = 1;
const PROTOCOL_ICMPV6: i32 = 58;
const PROTOCOL_TCP: i32 = 6;
const PROTOCOL_UDP: i32 = 17;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct FirewallProfile {
    /// "domain", "private" or "public".
    pub name: String,
    pub enabled: bool,
    /// The computer is on a network of this type now.
    pub active: bool,
    /// What happens to traffic no rule matches: "allow" or "block".
    pub default_inbound: String,
    pub default_outbound: String,
    /// Inbound traffic is blocked even when a rule allows it.
    pub block_all_inbound: bool,
}

/// One reason a rule deserves a look.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RuleFlag {
    /// "open_public", "remote_access", "writable_program" or "missing_program".
    pub code: &'static str,
    /// The remote-access port it opens (0 for the other flags).
    pub port: u16,
    /// A risk worth a look; false for housekeeping (a leftover rule for a program that is gone).
    pub warn: bool,
}

impl RuleFlag {
    fn new(code: &'static str, port: u16) -> Self {
        Self {
            code,
            port,
            warn: code != "missing_program",
        }
    }
}

/// The fields that tell rules apart, normalized the way the firewall cmdlets report them
/// (lower case, "any" as empty, ports joined with commas).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RuleIdent {
    /// The name as stored (`@` resource strings are not resolved).
    pub name: String,
    /// "in" or "out".
    pub direction: String,
    pub program: String,
    pub service: String,
    /// Protocol number as text ("6", "17", "256" for any).
    pub protocol: String,
    pub local_ports: String,
    pub remote_ports: String,
}

impl RuleIdent {
    pub fn key(&self) -> String {
        [
            self.name.as_str(),
            &self.direction,
            &self.program,
            &self.service,
            &self.protocol,
            &self.local_ports,
            &self.remote_ports,
        ]
        .join("|")
    }
}

#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct FirewallRule {
    /// Identifies the rule in requests (see `RuleIdent::key`).
    pub key: String,
    /// The display name (`@` resource strings resolved).
    pub name: String,
    pub description: String,
    /// The group, resolved ("Remote Desktop", "Core Networking").
    pub group: String,
    /// A rule of a group Windows itself defines (`@FirewallAPI.dll,-28752` and similar).
    pub builtin: bool,
    /// A rule a Microsoft Store app declared (group `@{Package?ms-resource:...}`).
    pub app_package: bool,
    /// "in" or "out".
    pub direction: String,
    /// "allow" or "block".
    pub action: String,
    pub enabled: bool,
    /// The profiles it applies to: "domain", "private", "public".
    pub profiles: Vec<String>,
    /// The program, environment variables expanded ("" for every program).
    pub program: String,
    /// False when `program` is a full path to a file that does not exist.
    pub program_exists: bool,
    pub service: String,
    pub protocol: i32,
    /// "TCP", "UDP", "ICMPv4", "Any" or the protocol number.
    pub protocol_name: String,
    /// As the firewall stores them; "" or "*" means any.
    pub local_ports: String,
    pub remote_ports: String,
    pub local_addresses: String,
    pub remote_addresses: String,
    /// "All" or a list such as "Lan,Wireless".
    pub interface_types: String,
    /// Allows unsolicited traffic through NAT devices (edge traversal).
    pub edge_traversal: bool,
    /// Created by Vigil's "Block network access" action.
    pub vigil: bool,
    /// Another rule has the same key: Vigil cannot tell them apart and does not act on either.
    pub duplicate: bool,
    pub flags: Vec<RuleFlag>,
    #[serde(skip)]
    pub ident: RuleIdent,
}

#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Firewall {
    pub profiles: Vec<FirewallProfile>,
    pub rules: Vec<FirewallRule>,
}

#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Summary {
    pub total: usize,
    pub enabled: usize,
    pub inbound: usize,
    pub outbound: usize,
    /// Enabled inbound rules that allow traffic.
    pub inbound_allow: usize,
    /// Rules with a warning flag.
    pub flagged: usize,
    /// Allow rules for programs that no longer exist.
    pub missing: usize,
    pub vigil: usize,
}

// ------------------------------------------------------------------------------ normalization

/// A port list in a form this API and the firewall cmdlets agree on: trimmed, lower case, "any" as
/// "". Port keywords are spelled differently by the two ("RPC-EPMap" / "RPCEPMap", "IPHTTPS" /
/// "IPHTTPSIn", "Ply2Disc" / "PlayToDiscovery", and "RPC" that this API reports as no port), so
/// keywords lose their dashes and take one spelling, and "RPC" counts as any port. Ranges
/// ("5000-5020") keep their dash. The lookup still has to find exactly one rule.
pub fn norm_list(text: &str) -> String {
    let joined = text
        .split(',')
        .map(|part| part.trim().to_lowercase())
        .filter_map(|part| {
            if !part.chars().any(|c| c.is_ascii_alphabetic()) {
                return Some(part);
            }
            match part.replace('-', "").as_str() {
                "rpc" | "any" | "*" => None,
                "iphttpsin" | "iphttpsout" => Some("iphttps".to_string()),
                "playtodiscovery" => Some("ply2disc".to_string()),
                other => Some(other.to_string()),
            }
        })
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join(",");
    if joined == "*" { String::new() } else { joined }
}

/// One value (a service name) as the cmdlets compare it: trimmed, lower case, "any" as "".
pub fn norm_one(text: &str) -> String {
    let text = text.trim().to_lowercase();
    if text == "*" || text == "any" {
        String::new()
    } else {
        text
    }
}

/// A program path as the cmdlets compare it: environment variables expanded, lower case.
pub fn norm_program(text: &str) -> String {
    norm_one(&expand(text.trim()))
}

/// Any remote address: "", "*" or "Any".
pub fn any_address(text: &str) -> bool {
    norm_list(text).is_empty()
}

pub fn protocol_name(protocol: i32) -> String {
    match protocol {
        PROTOCOL_TCP => "TCP".into(),
        PROTOCOL_UDP => "UDP".into(),
        PROTOCOL_ICMPV4 => "ICMPv4".into(),
        PROTOCOL_ICMPV6 => "ICMPv6".into(),
        PROTOCOL_ANY => "Any".into(),
        2 => "IGMP".into(),
        47 => "GRE".into(),
        other => other.to_string(),
    }
}

/// The port list includes `port` explicitly ("3389", "3380-3390", "80,3389"); "any" and keywords
/// such as "RPC" do not count.
pub fn ports_include(ports: &str, port: u16) -> bool {
    ports.split(',').map(str::trim).any(|part| match part.split_once('-') {
        Some((low, high)) => match (low.trim().parse::<u16>(), high.trim().parse::<u16>()) {
            (Ok(low), Ok(high)) => (low..=high).contains(&port),
            _ => false,
        },
        None => part.parse::<u16>() == Ok(port),
    })
}

fn profile_names(mask: i32) -> Vec<String> {
    [
        (NET_FW_PROFILE2_DOMAIN, "domain"),
        (NET_FW_PROFILE2_PRIVATE, "private"),
        (NET_FW_PROFILE2_PUBLIC, "public"),
    ]
    .iter()
    .filter(|(kind, _)| mask & kind.0 != 0)
    .map(|(_, name)| (*name).to_string())
    .collect()
}

/// Groups Windows defines are resource strings in a system DLL; Store apps use `@{Package?...}`.
pub fn builtin_group(raw: &str) -> bool {
    raw.starts_with('@') && !raw.starts_with("@{")
}

pub fn created_by_vigil(name: &str, description: &str) -> bool {
    name.starts_with(VIGIL_PREFIX) && description == VIGIL_DESCRIPTION
}

/// Sets `key` and `duplicate` from each rule's `ident`.
pub fn assign_keys(rules: &mut [FirewallRule]) {
    let mut counts: HashMap<String, usize> = HashMap::new();
    for rule in rules.iter_mut() {
        rule.key = rule.ident.key();
        *counts.entry(rule.key.clone()).or_default() += 1;
    }
    for rule in rules.iter_mut() {
        rule.duplicate = counts.get(&rule.key).copied().unwrap_or(0) > 1;
    }
}

// ------------------------------------------------------------------------------ analysis

/// Folders a standard user can write to, for the "program in a user-writable folder" flag.
#[derive(Debug, Clone, Default)]
pub struct Folders {
    writable: Vec<String>,
    protected: Vec<String>,
}

impl Folders {
    /// `writable` and `protected` are folder paths; a path is writable when the longest folder
    /// that contains it is a writable one (so `C:\Windows\Temp` stays writable inside the
    /// protected `C:\Windows`).
    pub fn new(writable: &[&str], protected: &[&str]) -> Self {
        let clean = |dirs: &[&str]| {
            dirs.iter()
                .map(|d| d.trim().trim_end_matches('\\').to_lowercase())
                .filter(|d| !d.is_empty())
                .collect()
        };
        Self {
            writable: clean(writable),
            protected: clean(protected),
        }
    }

    /// The profile folders, ProgramData, temp folders and `C:\Users` are writable; Windows, the
    /// Program Files folders and `ProgramData\Microsoft` are not.
    pub fn from_env() -> Self {
        let var = |name: &str| std::env::var(name).unwrap_or_default();
        let drive = {
            let d = var("SystemDrive");
            if d.is_empty() { "C:".to_string() } else { d }
        };
        let root = {
            let r = crate::paths::windows_dir().display().to_string();
            if r.is_empty() { format!(r"{drive}\Windows") } else { r }
        };
        // System folders from Windows, not the environment (which the user controls).
        let text = |p: std::path::PathBuf| p.display().to_string();
        let program_data = text(crate::paths::program_data());
        let writable = [
            crate::paths::profile().map(text).unwrap_or_default(),
            var("TEMP"),
            var("TMP"),
            program_data.clone(),
            format!(r"{drive}\Users"),
            format!(r"{root}\Temp"),
        ];
        let protected = [
            root,
            text(crate::paths::program_files()),
            text(crate::paths::program_files_x86()),
            text(crate::paths::program_files()),
            if program_data.is_empty() {
                String::new()
            } else {
                format!(r"{program_data}\Microsoft")
            },
        ];
        let writable: Vec<&str> = writable.iter().map(String::as_str).collect();
        let protected: Vec<&str> = protected.iter().map(String::as_str).collect();
        Self::new(&writable, &protected)
    }

    pub fn user_writable(&self, path: &str) -> bool {
        let path = path.trim().to_lowercase();
        let longest = |dirs: &[String]| {
            dirs.iter()
                .filter(|d| path.starts_with(&format!("{d}\\")))
                .map(String::len)
                .max()
        };
        match (longest(&self.writable), longest(&self.protected)) {
            (Some(writable), Some(protected)) => writable > protected,
            (Some(_), None) => true,
            _ => false,
        }
    }
}

/// Why an enabled rule deserves a look:
/// * `open_public`: an inbound allow rule for public networks that accepts any remote address for
///   every program (Windows' own rule groups, Store apps, which are confined to their package, and
///   ICMP are left out: they are expected; a rule limited to one program is how Windows allows an
///   app, so it is not flagged either);
/// * `remote_access`: an inbound allow rule that opens a remote-access port (Remote Desktop, SSH,
///   VNC, WinRM, Telnet);
/// * `writable_program`: an inbound allow rule for a program in a folder a standard user can
///   write to, so any program could take its place;
/// * `missing_program`: an inbound allow rule for a program that no longer exists, so a file put at
///   that path would inherit the rule (housekeeping, not a warning: `warn` is false).
pub fn flags_for(rule: &FirewallRule, folders: &Folders) -> Vec<RuleFlag> {
    let mut flags = Vec::new();
    if !rule.enabled || rule.action != "allow" {
        return flags;
    }
    let inbound = rule.direction == "in";
    let icmp = matches!(rule.protocol, PROTOCOL_ICMPV4 | PROTOCOL_ICMPV6);
    let every_program = rule.program.trim().is_empty() && norm_one(&rule.service).is_empty();
    if inbound
        && every_program
        && !rule.builtin
        && !rule.app_package
        && !icmp
        && rule.profiles.iter().any(|p| p == "public")
        && any_address(&rule.remote_addresses)
    {
        flags.push(RuleFlag::new("open_public", 0));
    }
    let remote_port = REMOTE_ACCESS_PORTS
        .iter()
        .find(|(port, _)| ports_include(&rule.local_ports, *port));
    if let Some((port, _)) =
        remote_port.filter(|_| inbound && matches!(rule.protocol, PROTOCOL_TCP | PROTOCOL_UDP | PROTOCOL_ANY))
    {
        flags.push(RuleFlag::new("remote_access", *port));
    }
    let program = rule.program.trim();
    let is_path = program.len() > 2 && program.as_bytes()[1] == b':';
    if inbound && is_path && rule.program_exists && folders.user_writable(program) {
        flags.push(RuleFlag::new("writable_program", 0));
    }
    if inbound && is_path && !rule.program_exists {
        flags.push(RuleFlag::new("missing_program", 0));
    }
    flags
}

/// Fills in every rule's flags.
pub fn analyze(firewall: &mut Firewall, folders: &Folders) {
    for rule in &mut firewall.rules {
        rule.flags = flags_for(rule, folders);
    }
}

pub fn summarize(rules: &[FirewallRule]) -> Summary {
    let mut summary = Summary {
        total: rules.len(),
        ..Summary::default()
    };
    for rule in rules {
        summary.enabled += usize::from(rule.enabled);
        if rule.direction == "in" {
            summary.inbound += 1;
            summary.inbound_allow += usize::from(rule.enabled && rule.action == "allow");
        } else {
            summary.outbound += 1;
        }
        summary.flagged += usize::from(rule.flags.iter().any(|f| f.warn));
        summary.missing += usize::from(rule.flags.iter().any(|f| f.code == "missing_program"));
        summary.vigil += usize::from(rule.vigil);
    }
    summary
}

// ------------------------------------------------------------------------------ reading

/// The profiles and every rule (with flags), read on a worker thread; gives up after `timeout`.
pub fn read(timeout: Duration) -> Result<Firewall, SysError> {
    let (tx, rx) = mpsc::channel();
    std::thread::Builder::new()
        .name("vigil-firewall".into())
        .spawn(move || {
            let _ = tx.send(read_now());
        })
        .map_err(|e| SysError::new(format!("reading the firewall rules: {e}"), 0))?;
    let mut firewall = rx
        .recv_timeout(timeout)
        .map_err(|_| SysError::new("reading the firewall rules took too long", 0))??;
    analyze(&mut firewall, &Folders::from_env());
    Ok(firewall)
}

/// Balances a successful `CoInitializeEx` when dropped.
struct ComScope(bool);

impl Drop for ComScope {
    fn drop(&mut self) {
        if self.0 {
            // SAFETY: balances the successful CoInitializeEx on this thread.
            unsafe { CoUninitialize() };
        }
    }
}

fn read_now() -> Result<Firewall, SysError> {
    // SAFETY: initializes COM for this worker thread; ComScope uninitializes it last.
    let _com = ComScope(unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) }.is_ok());
    // SAFETY: plain COM activation of the in-process firewall policy object.
    let policy: INetFwPolicy2 = unsafe { CoCreateInstance(&NetFwPolicy2, None, CLSCTX_INPROC_SERVER) }
        .map_err(|e| SysError::from_windows("opening the firewall settings", &e))?;
    // SAFETY: COM property reads on a live object.
    let current = unsafe { policy.CurrentProfileTypes() }.unwrap_or(0);
    let profiles = [
        (NET_FW_PROFILE2_DOMAIN, "domain"),
        (NET_FW_PROFILE2_PRIVATE, "private"),
        (NET_FW_PROFILE2_PUBLIC, "public"),
    ]
    .iter()
    .map(|(kind, name)| read_profile(&policy, *kind, name, current))
    .collect();
    let mut rules = read_rules(&policy)?;
    assign_keys(&mut rules);
    Ok(Firewall { profiles, rules })
}

fn action_name(action: NET_FW_ACTION) -> String {
    if action == NET_FW_ACTION_ALLOW {
        "allow"
    } else {
        "block"
    }
    .into()
}

fn read_profile(policy: &INetFwPolicy2, kind: NET_FW_PROFILE_TYPE2, name: &str, current: i32) -> FirewallProfile {
    // SAFETY: COM property reads on a live object.
    unsafe {
        FirewallProfile {
            name: name.into(),
            enabled: policy.get_FirewallEnabled(kind).is_ok_and(|b| b.0 != 0),
            active: current & kind.0 != 0,
            default_inbound: policy
                .get_DefaultInboundAction(kind)
                .map_or_else(|_| "block".into(), action_name),
            default_outbound: policy
                .get_DefaultOutboundAction(kind)
                .map_or_else(|_| "allow".into(), action_name),
            block_all_inbound: policy.get_BlockAllInboundTraffic(kind).is_ok_and(|b| b.0 != 0),
        }
    }
}

/// The IDispatch a VARIANT holds (with its own reference), if it holds one.
///
/// # Safety
/// `item` must be a VARIANT filled in by COM.
unsafe fn dispatch_of(item: &VARIANT) -> Option<IDispatch> {
    // SAFETY: the type tag says which union member is valid; the clone adds a reference.
    unsafe {
        let inner = &item.Anonymous.Anonymous;
        if inner.vt == VT_DISPATCH {
            (*inner.Anonymous.pdispVal).clone()
        } else if inner.vt == VT_UNKNOWN {
            (*inner.Anonymous.punkVal).as_ref().and_then(|u| u.cast().ok())
        } else {
            None
        }
    }
}

fn read_rules(policy: &INetFwPolicy2) -> Result<Vec<FirewallRule>, SysError> {
    let failed = |e: windows::core::Error| SysError::from_windows("reading the firewall rules", &e);
    // SAFETY: COM calls on live objects; each VARIANT the enumerator fills is cleared after use.
    unsafe {
        let rules = policy.Rules().map_err(failed)?;
        let count = rules.Count().unwrap_or(0).max(0) as usize;
        let enumerator: IEnumVARIANT = rules._NewEnum().map_err(failed)?.cast().map_err(failed)?;
        let mut out = Vec::with_capacity(count);
        let mut strings = Strings::default();
        loop {
            let mut batch: [VARIANT; 64] = std::array::from_fn(|_| VARIANT::default());
            let mut fetched = 0u32;
            let status = enumerator.Next(&mut batch, &mut fetched);
            let fetched = (fetched as usize).min(batch.len());
            for item in batch.iter_mut().take(fetched) {
                let rule = dispatch_of(item).and_then(|d| d.cast::<INetFwRule>().ok());
                let _ = VariantClear(item);
                if let Some(rule) = rule {
                    out.push(read_rule(&rule, &mut strings));
                }
            }
            status.ok().map_err(failed)?;
            if fetched < batch.len() {
                break;
            }
        }
        Ok(out)
    }
}

fn text(value: windows::core::Result<BSTR>) -> String {
    value.map(|b| b.to_string()).unwrap_or_default()
}

/// Resolved `@` strings and file checks, cached: many rules share a group or a program.
#[derive(Default)]
struct Strings {
    resolved: HashMap<String, String>,
    exists: HashMap<String, bool>,
}

impl Strings {
    fn resolve(&mut self, raw: &str) -> String {
        if !raw.starts_with('@') {
            return raw.to_string();
        }
        self.resolved
            .entry(raw.to_string())
            .or_insert_with(|| indirect(raw).unwrap_or_else(|| raw.to_string()))
            .clone()
    }

    /// False only for a local full path (`C:\...`) that does not exist; network paths are not
    /// probed (an unreachable share would stall the read).
    fn exists(&mut self, program: &str) -> bool {
        let local = program.len() > 2 && program.as_bytes()[1] == b':' && program.is_char_boundary(2);
        if !local {
            return true;
        }
        *self
            .exists
            .entry(program.to_lowercase())
            .or_insert_with(|| Path::new(program).exists())
    }
}

/// An indirect string (`@FirewallAPI.dll,-28502`, `@{Package?ms-resource://...}`) resolved.
fn indirect(raw: &str) -> Option<String> {
    let source = wide(raw);
    let mut buffer = vec![0u16; 1024];
    // SAFETY: `source` is NUL-terminated and `buffer` is writable for its length.
    unsafe { SHLoadIndirectString(PCWSTR(source.as_ptr()), &mut buffer, None) }.ok()?;
    let text = from_wide(&buffer).trim().to_string();
    (!text.is_empty() && !text.starts_with('@') && !text.starts_with("ms-resource:")).then_some(text)
}

fn expand(text: &str) -> String {
    if !text.contains('%') {
        return text.to_string();
    }
    let source = HSTRING::from(text);
    // SAFETY: a size query (no buffer).
    let needed = unsafe { ExpandEnvironmentStringsW(&source, None) };
    if needed == 0 {
        return text.to_string();
    }
    let mut buffer = vec![0u16; needed as usize];
    // SAFETY: the buffer has the size the first call asked for.
    let written = unsafe { ExpandEnvironmentStringsW(&source, Some(&mut buffer)) };
    if written == 0 || written as usize > buffer.len() {
        return text.to_string();
    }
    from_wide(&buffer)
}

fn read_rule(rule: &INetFwRule, strings: &mut Strings) -> FirewallRule {
    // SAFETY: COM property reads on a live rule object.
    unsafe {
        let name_raw = text(rule.Name());
        let description_raw = text(rule.Description());
        let group_raw = text(rule.Grouping());
        let program_raw = text(rule.ApplicationName());
        let service = text(rule.ServiceName());
        let protocol = rule.Protocol().unwrap_or(PROTOCOL_ANY);
        let local_ports = text(rule.LocalPorts());
        let remote_ports = text(rule.RemotePorts());
        let direction = if rule.Direction().is_ok_and(|d| d == NET_FW_RULE_DIR_OUT) {
            "out"
        } else {
            "in"
        };
        let edge = rule.EdgeTraversal().is_ok_and(|b| b.0 != 0)
            || rule
                .cast::<INetFwRule2>()
                .ok()
                .and_then(|r| r.EdgeTraversalOptions().ok())
                .is_some_and(|o| o != 0);
        let program = expand(program_raw.trim());
        let program_exists = strings.exists(&program);
        let name = strings.resolve(&name_raw);
        let description = strings.resolve(&description_raw);
        FirewallRule {
            key: String::new(),
            vigil: created_by_vigil(&name, &description),
            name,
            description,
            group: strings.resolve(&group_raw),
            builtin: builtin_group(&group_raw),
            app_package: group_raw.starts_with("@{"),
            direction: direction.into(),
            action: rule.Action().map_or_else(|_| "block".into(), action_name),
            enabled: rule.Enabled().is_ok_and(|b| b.0 != 0),
            profiles: profile_names(rule.Profiles().unwrap_or(0)),
            program_exists,
            program,
            service: service.clone(),
            protocol,
            protocol_name: protocol_name(protocol),
            local_addresses: text(rule.LocalAddresses()),
            remote_addresses: text(rule.RemoteAddresses()),
            interface_types: text(rule.InterfaceTypes()),
            edge_traversal: edge,
            duplicate: false,
            flags: Vec::new(),
            ident: RuleIdent {
                name: name_raw,
                direction: direction.into(),
                program: norm_program(&program_raw),
                service: norm_one(&service),
                protocol: protocol.to_string(),
                local_ports: norm_list(&local_ports),
                remote_ports: norm_list(&remote_ports),
            },
            local_ports,
            remote_ports,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn folders() -> Folders {
        Folders::new(
            &[
                r"C:\Users\jdoe",
                r"C:\Users",
                r"C:\ProgramData",
                r"C:\Users\jdoe\AppData\Local\Temp",
                r"C:\Windows\Temp",
            ],
            &[
                r"C:\Windows",
                r"C:\Program Files",
                r"C:\Program Files (x86)",
                r"C:\ProgramData\Microsoft",
            ],
        )
    }

    fn inbound_allow(name: &str) -> FirewallRule {
        FirewallRule {
            name: name.into(),
            direction: "in".into(),
            action: "allow".into(),
            enabled: true,
            profiles: vec!["private".into(), "public".into()],
            protocol: PROTOCOL_TCP,
            remote_addresses: "*".into(),
            program_exists: true,
            ..FirewallRule::default()
        }
    }

    fn codes(rule: &FirewallRule) -> Vec<&'static str> {
        flags_for(rule, &folders()).iter().map(|f| f.code).collect()
    }

    #[test]
    fn normalization_matches_the_cmdlets() {
        assert_eq!(norm_list(" 80, 443 "), "80,443");
        assert_eq!(norm_list("*"), "");
        assert_eq!(norm_list("Any"), "");
        assert_eq!(norm_list("RPC-EPMap"), "rpcepmap");
        assert_eq!(norm_list("RPCEPMap"), "rpcepmap");
        assert_eq!(norm_list("5000-5020, IPHTTPS-In"), "5000-5020,iphttps");
        assert_eq!(norm_list("IPHTTPS"), "iphttps");
        assert_eq!(norm_list("PlayToDiscovery"), norm_list("Ply2Disc"));
        assert_eq!(norm_list("RPC"), "");
        assert_eq!(norm_list("135, RPC"), "135");
        assert_eq!(
            norm_one(r" C:\Apps\Contoso, Inc\app.exe "),
            r"c:\apps\contoso, inc\app.exe"
        );
        assert_eq!(norm_one("Any"), "");
        assert_eq!(
            norm_program(r"C:\Program Files\App\App.exe"),
            r"c:\program files\app\app.exe"
        );
        assert!(any_address(""));
        assert!(any_address("*"));
        assert!(!any_address("LocalSubnet"));
        assert_eq!(protocol_name(6), "TCP");
        assert_eq!(protocol_name(256), "Any");
        assert_eq!(protocol_name(99), "99");
        assert_eq!(profile_names(0x7FFF_FFFF), ["domain", "private", "public"]);
        assert_eq!(profile_names(4), ["public"]);
    }

    #[test]
    fn port_lists_include_only_explicit_ports() {
        assert!(ports_include("3389", 3389));
        assert!(ports_include("80, 3389", 3389));
        assert!(ports_include("3380-3390", 3389));
        assert!(!ports_include("*", 3389));
        assert!(!ports_include("", 22));
        assert!(!ports_include("RPC", 22));
        assert!(!ports_include("2200-x", 2201));
    }

    #[test]
    fn writable_folders_follow_the_longest_match() {
        let f = folders();
        assert!(f.user_writable(r"C:\Users\jdoe\AppData\Roaming\Tool\tool.exe"));
        assert!(f.user_writable(r"c:\programdata\updater\up.exe"));
        assert!(f.user_writable(r"C:\Windows\Temp\x.exe"));
        assert!(!f.user_writable(r"C:\Windows\System32\svchost.exe"));
        assert!(!f.user_writable(r"C:\ProgramData\Microsoft\Windows Defender\MsMpEng.exe"));
        assert!(!f.user_writable(r"C:\Program Files\App\app.exe"));
        assert!(!f.user_writable(r"D:\Games\game.exe"));
    }

    #[test]
    fn rules_open_to_the_internet_and_remote_access_are_flagged() {
        let open = inbound_allow("Game server");
        assert_eq!(codes(&open), ["open_public"]);

        let mut one_program = inbound_allow("Allowed app");
        one_program.program = r"C:\Program Files\App\app.exe".into();
        assert!(codes(&one_program).is_empty(), "allowing one app is how Windows works");

        let mut store_app = inbound_allow("Store app");
        store_app.app_package = true;
        assert!(codes(&store_app).is_empty());

        let mut lan_only = inbound_allow("LAN share");
        lan_only.remote_addresses = "LocalSubnet".into();
        assert!(codes(&lan_only).is_empty());

        let mut private_only = inbound_allow("Private only");
        private_only.profiles = vec!["private".into()];
        assert!(codes(&private_only).is_empty());

        let mut windows = inbound_allow("Remote Desktop - User Mode (TCP-In)");
        windows.builtin = true;
        windows.local_ports = "3389".into();
        assert_eq!(codes(&windows), ["remote_access"]);
        assert_eq!(flags_for(&windows, &folders())[0].port, 3389);

        let mut ping = inbound_allow("Echo request");
        ping.protocol = PROTOCOL_ICMPV4;
        assert!(codes(&ping).is_empty());

        let mut ssh = inbound_allow("OpenSSH");
        ssh.local_ports = "22".into();
        ssh.remote_addresses = "203.0.113.0/255.255.255.0".into();
        assert_eq!(codes(&ssh), ["remote_access"]);

        let mut blocked = inbound_allow("Blocked");
        blocked.action = "block".into();
        blocked.local_ports = "3389".into();
        assert!(codes(&blocked).is_empty());

        let mut disabled = inbound_allow("Disabled");
        disabled.enabled = false;
        assert!(codes(&disabled).is_empty());
    }

    #[test]
    fn programs_in_writable_or_missing_places_are_flagged() {
        let mut tool = inbound_allow("Tool");
        tool.remote_addresses = "LocalSubnet".into();
        tool.program = r"C:\Users\jdoe\AppData\Roaming\Tool\tool.exe".into();
        assert_eq!(codes(&tool), ["writable_program"]);

        tool.program_exists = false;
        assert_eq!(codes(&tool), ["missing_program"]);
        assert!(!flags_for(&tool, &folders())[0].warn);

        let mut outbound = tool.clone();
        outbound.direction = "out".into();
        outbound.program_exists = true;
        assert!(codes(&outbound).is_empty(), "outbound allow rules are normal");

        let mut installed = inbound_allow("App");
        installed.remote_addresses = "LocalSubnet".into();
        installed.program = r"C:\Program Files\App\app.exe".into();
        assert!(codes(&installed).is_empty());

        let mut system = inbound_allow("System");
        system.remote_addresses = "LocalSubnet".into();
        system.program = "System".into();
        assert!(codes(&system).is_empty());
    }

    #[test]
    fn keys_mark_rules_that_cannot_be_told_apart() {
        let ident = |name: &str, ports: &str| RuleIdent {
            name: name.into(),
            direction: "in".into(),
            protocol: "6".into(),
            local_ports: ports.into(),
            ..RuleIdent::default()
        };
        let mut rules = vec![
            FirewallRule {
                ident: ident("Web", "80"),
                ..FirewallRule::default()
            },
            FirewallRule {
                ident: ident("Web", "443"),
                ..FirewallRule::default()
            },
            FirewallRule {
                ident: ident("Copy", "80"),
                ..FirewallRule::default()
            },
            FirewallRule {
                ident: ident("Copy", "80"),
                ..FirewallRule::default()
            },
        ];
        assign_keys(&mut rules);
        assert_eq!(rules[0].key, "Web|in|||6|80|");
        assert!(!rules[0].duplicate && !rules[1].duplicate);
        assert!(rules[2].duplicate && rules[3].duplicate);
    }

    #[test]
    fn groups_and_vigil_rules_are_recognized() {
        assert!(builtin_group("@FirewallAPI.dll,-28752"));
        assert!(builtin_group(r"@%SystemRoot%\system32\firewallapi.dll,-37302"));
        assert!(!builtin_group(
            "@{Contoso.App_1.0.0.0_x64__abc?ms-resource://Contoso.App/Resources/Name}"
        ));
        assert!(!builtin_group("My tools"));
        assert!(created_by_vigil("Vigil: block tool.exe", VIGIL_DESCRIPTION));
        assert!(!created_by_vigil("Vigil: block tool.exe", "Something else"));
    }

    #[test]
    fn summary_counts_rules() {
        let mut flagged = inbound_allow("Open");
        flagged.flags = flags_for(&flagged, &folders());
        let mut vigil = inbound_allow("Vigil: block x");
        vigil.direction = "out".into();
        vigil.action = "block".into();
        vigil.vigil = true;
        let mut off = inbound_allow("Off");
        off.enabled = false;
        let mut gone = inbound_allow("Gone");
        gone.remote_addresses = "LocalSubnet".into();
        gone.program = r"C:\Users\jdoe\Downloads\old.exe".into();
        gone.program_exists = false;
        gone.flags = flags_for(&gone, &folders());
        let summary = summarize(&[flagged, vigil, off, gone]);
        assert_eq!(
            summary,
            Summary {
                total: 4,
                enabled: 3,
                inbound: 3,
                outbound: 1,
                inbound_allow: 2,
                flagged: 1,
                missing: 1,
                vigil: 1,
            }
        );
    }

    #[test]
    fn the_live_rules_can_be_read() {
        // Read-only: lists the profiles and rules of this computer.
        let firewall = read(Duration::from_secs(60)).expect("read the firewall");
        assert_eq!(firewall.profiles.len(), 3);
        assert!(!firewall.rules.is_empty(), "Windows always has firewall rules");
        for rule in &firewall.rules {
            assert!(rule.direction == "in" || rule.direction == "out");
            assert!(rule.action == "allow" || rule.action == "block");
            assert!(!rule.key.is_empty());
        }
        assert!(firewall.rules.iter().any(|r| r.builtin));
    }
}
