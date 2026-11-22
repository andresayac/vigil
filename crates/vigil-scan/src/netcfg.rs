//! Network settings that send name lookups or web traffic somewhere else: DNS servers set by hand
//! or by a program, DNS over HTTPS templates, name resolution policy rules, the WinHTTP proxy,
//! where a proxy or proxy script points, WPAD redirected by the hosts file, persistent routes,
//! virtual adapters and network filter drivers from unknown vendors, and LLMNR / NetBIOS.
//! READ-ONLY: the data comes from `vigil_sys::netcfg` (local configuration only; nothing is looked
//! up or sent), and lands under `sysconfig.network_config`.
//!
//! False alarms are the main risk, so:
//! - addresses on the local network, the adapter's own gateway and a short list of well-known
//!   public resolvers never count;
//! - DNS servers the network hands out (DHCP) are left to the existing "unrecognized DNS" finding;
//! - virtual adapters and filter drivers count only when their driver comes from neither Microsoft
//!   nor a known VPN, virtualization, capture or security vendor;
//! - LLMNR and NetBIOS are only a posture fact, worth a look while a public network is connected.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use serde_json::{Map, Value, json};
use vigil_i18n::tr;

use crate::lenient::{Get, as_int, list, lower, rx, strip, text, truthy};
use crate::model::{Flag, Item};
use crate::rules::is_user_writable;

/// Where collection stores its results in the inventory.
pub(crate) const SECTION: &str = "network_config";

/// A hand-set DNS server counts as recent when its adapter's settings changed this many days ago.
const RECENT_DAYS: i64 = 7;

/// Public resolvers people choose on purpose (IPv4 and IPv6): Cloudflare, Google, Quad9, OpenDNS,
/// AdGuard, NextDNS, CleanBrowsing, Control D, Mullvad and DNS.SB.
const KNOWN_RESOLVERS: &[&str] = &[
    "1.1.1.1",
    "1.0.0.1",
    "1.1.1.2",
    "1.0.0.2",
    "1.1.1.3",
    "1.0.0.3",
    "2606:4700:4700::1111",
    "2606:4700:4700::1001",
    "2606:4700:4700::1112",
    "2606:4700:4700::1002",
    "2606:4700:4700::1113",
    "2606:4700:4700::1003",
    "8.8.8.8",
    "8.8.4.4",
    "2001:4860:4860::8888",
    "2001:4860:4860::8844",
    "9.9.9.9",
    "149.112.112.112",
    "9.9.9.10",
    "149.112.112.10",
    "9.9.9.11",
    "149.112.112.11",
    "2620:fe::fe",
    "2620:fe::9",
    "2620:fe::10",
    "2620:fe::11",
    "208.67.222.222",
    "208.67.220.220",
    "208.67.222.123",
    "208.67.220.123",
    "2620:119:35::35",
    "2620:119:53::53",
    "94.140.14.14",
    "94.140.15.15",
    "94.140.14.15",
    "94.140.15.16",
    "2a10:50c0::ad1:ff",
    "2a10:50c0::ad2:ff",
    "45.90.28.0",
    "45.90.30.0",
    "185.228.168.9",
    "185.228.169.9",
    "185.228.168.168",
    "185.228.169.168",
    "76.76.2.0",
    "76.76.10.0",
    "194.242.2.2",
    "185.222.222.222",
    "45.11.45.11",
];

/// Host names of the DNS over HTTPS services of those providers (Windows' own templates included);
/// a template counts as known when its host is one of these or a subdomain of one.
const KNOWN_DOH_HOSTS: &[&str] = &[
    "cloudflare-dns.com",
    "dns.google",
    "dns.google.com",
    "quad9.net",
    "opendns.com",
    "adguard-dns.com",
    "adguard.com",
    "nextdns.io",
    "cleanbrowsing.org",
    "controld.com",
    "mullvad.net",
    "dns.sb",
];

/// Driver providers whose virtual adapters and filter drivers are expected: Microsoft, VPNs,
/// virtualization, packet capture, network hardware makers and security vendors (lower case;
/// matched as a word anywhere in the provider name).
const KNOWN_NETWORK_VENDORS: &[&str] = &[
    "microsoft",
    "openvpn",
    "wireguard",
    "tailscale",
    "zerotier",
    "nord",
    "proton",
    "mullvad",
    "express",
    "surfshark",
    "private internet access",
    "kape",
    "windscribe",
    "tunnelbear",
    "pango",
    "anchorfree",
    "cloudflare",
    "netbird",
    "logmein",
    "cisco",
    "fortinet",
    "palo alto",
    "check point",
    "sonicwall",
    "juniper",
    "pulse secure",
    "ivanti",
    "citrix",
    "zscaler",
    "netskope",
    "f5",
    "vmware",
    "broadcom",
    "oracle",
    "virtualbox",
    "docker",
    "parallels",
    "insecure.com",
    "nmap",
    "npcap",
    "wireshark",
    "intel",
    "realtek",
    "qualcomm",
    "killer",
    "rivet",
    "mediatek",
    "marvell",
    "mellanox",
    "nvidia",
    "amd",
    "avast",
    "avg",
    "bitdefender",
    "eset",
    "kaspersky",
    "norton",
    "symantec",
    "gen digital",
    "mcafee",
    "sophos",
    "trend micro",
    "malwarebytes",
    "webroot",
    "f-secure",
    "withsecure",
    "g data",
    "panda",
    "comodo",
    "crowdstrike",
    "sentinelone",
];

rx!(
    TUNNEL_RX,
    r"(?i)\b(tap|tun|wintun|wireguard|wg\d|ovpn|zttap|vpn|tunnel)"
);

// --------------------------------------------------------------------------- collection

/// Reads the network configuration (Windows only).
#[cfg(windows)]
pub(crate) fn collect() -> Value {
    serde_json::to_value(vigil_sys::netcfg::read()).unwrap_or(Value::Null)
}

#[cfg(not(windows))]
pub(crate) fn collect() -> Value {
    json!({})
}

// --------------------------------------------------------------------------- address classes

fn parse_ip(text: &str) -> Option<IpAddr> {
    strip(text).split('%').next().unwrap_or("").parse().ok()
}

/// On this computer or the local network: private, link-local, carrier-grade NAT, unique local,
/// site-local (Windows' default `fec0:0:0:ffff::1`), loopback or unspecified.
fn is_lan(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || (o[0] == 100 && (o[1] & 0xC0) == 64)
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_lan(IpAddr::V4(v4));
            }
            let first = v6.segments()[0];
            v6.is_loopback()
                || v6.is_unspecified()
                || (first & 0xfe00) == 0xfc00
                || (first & 0xffc0) == 0xfe80
                || (first & 0xffc0) == 0xfec0
        }
    }
}

fn is_known_resolver(address: &str) -> bool {
    let Some(ip) = parse_ip(address) else {
        return false;
    };
    KNOWN_RESOLVERS
        .iter()
        .any(|known| known.parse::<IpAddr>().is_ok_and(|k| k == ip))
}

/// An address outside the local network that is not a well-known resolver.
fn is_unusual_server(address: &str) -> bool {
    parse_ip(address).is_some_and(|ip| !is_lan(ip)) && !is_known_resolver(address)
}

/// The host of a URL or a `host:port` (`[v6]:port` too), lower case.
fn host_of(target: &str) -> String {
    let mut rest = strip(target);
    if let Some((_, after)) = rest.split_once("://") {
        rest = after;
    }
    let rest = rest.split(['/', '?', '#']).next().unwrap_or("");
    let rest = rest.rsplit_once('@').map_or(rest, |(_, h)| h);
    if let Some(v6) = rest.strip_prefix('[') {
        return lower(v6.split(']').next().unwrap_or(""));
    }
    if rest.matches(':').count() > 1 {
        return lower(rest); // a bare IPv6 address
    }
    lower(rest.split(':').next().unwrap_or(""))
}

/// The port of a `host:port` or URL, with the scheme's default.
fn port_of(target: &str) -> Option<i64> {
    let target = strip(target);
    let scheme = target.split_once("://").map(|(s, _)| lower(s));
    let rest = target.split_once("://").map_or(target, |(_, r)| r);
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let authority = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    let port = if let Some(v6) = authority.strip_prefix('[') {
        v6.split_once("]:").map(|(_, p)| p)
    } else if authority.matches(':').count() == 1 {
        authority.split_once(':').map(|(_, p)| p)
    } else {
        None
    };
    match port.and_then(|p| p.parse().ok()) {
        Some(p) => Some(p),
        None => match scheme.as_deref() {
            Some("https") => Some(443),
            Some("http") => Some(80),
            _ => None,
        },
    }
}

fn is_known_doh(template: &str) -> bool {
    let host = host_of(template);
    !host.is_empty()
        && KNOWN_DOH_HOSTS
            .iter()
            .any(|known| host == *known || host.ends_with(&format!(".{known}")))
}

fn is_known_vendor(provider: &str) -> bool {
    let provider = lower(provider);
    KNOWN_NETWORK_VENDORS.iter().any(|vendor| {
        provider.match_indices(vendor).any(|(at, _)| {
            let before = provider[..at].chars().next_back();
            let after = provider[at + vendor.len()..].chars().next();
            !before.is_some_and(char::is_alphanumeric) && !after.is_some_and(char::is_alphanumeric)
        })
    })
}

/// The servers of a proxy setting ("host:port", or "http=host:port;https=host:port").
fn proxy_targets(setting: &str) -> Vec<String> {
    setting
        .split([';', ' '])
        .map(strip)
        .filter(|s| !s.is_empty())
        .map(|s| s.split_once('=').map_or(s, |(_, t)| t).to_string())
        .collect()
}

// --------------------------------------------------------------------------- findings

fn section(raw: &Value) -> &Value {
    raw.at("sysconfig").at(SECTION)
}

fn map(pairs: Vec<(&str, Value)>) -> Map<String, Value> {
    pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect()
}

fn config(topic: &str, title: String, score: i64, text: String, facts: Map<String, Value>) -> Item {
    let mut item = Item::new("config", title, text.clone());
    let mut all = Map::new();
    all.insert("topic".into(), json!(topic));
    all.extend(facts);
    item.facts = all;
    item.add_flag(Flag::new(topic, score, text));
    item.rescore();
    item
}

fn adapters(raw: &Value) -> &[Value] {
    list(section(raw).at("adapters"))
}

/// A VPN or virtualization adapter of a known vendor (its own DNS servers are its business).
fn known_virtual(adapter: &Value) -> bool {
    let provider = text(adapter.at("provider"));
    let tunnel = TUNNEL_RX.is_match(&format!(
        "{} {}",
        text(adapter.at("component")),
        text(adapter.at("description"))
    )) || matches!(as_int(adapter.at("if_type")), Some(53 | 131));
    tunnel && is_known_vendor(&provider) && !lower(&provider).contains("microsoft")
}

/// Unusual DNS servers set by hand or by a program, by server -> the adapters that use them.
fn hand_set_servers(raw: &Value) -> BTreeMap<String, BTreeSet<String>> {
    let mut out: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for adapter in adapters(raw) {
        if !truthy(adapter.at("up")) || known_virtual(adapter) {
            continue;
        }
        let gateways: Vec<String> = list(adapter.at("gateways")).iter().map(text).collect();
        for server in list(adapter.at("static_dns")).iter().map(text) {
            if gateways.iter().any(|g| g.eq_ignore_ascii_case(&server)) || !is_unusual_server(&server) {
                continue;
            }
            out.entry(server).or_default().insert(text(adapter.at("name")));
        }
    }
    out
}

/// The DNS servers [`items`] already reports as set by hand, so the general "unrecognized DNS"
/// finding leaves them out.
pub(crate) fn hand_set_dns(raw: &Value) -> BTreeSet<String> {
    hand_set_servers(raw).into_keys().collect()
}

/// LLMNR and NetBIOS state, for the posture summary.
pub(crate) fn posture(raw: &Value) -> Value {
    let sec = section(raw);
    if !truthy(sec) {
        return Value::Null;
    }
    let netbios_on = adapters(raw)
        .iter()
        .filter(|a| truthy(a.at("up")) && as_int(a.at("netbios")) != Some(2))
        .count();
    json!({
        "llmnr": !truthy(sec.at("llmnr_off")),
        "netbios_adapters": netbios_on,
        "public_network": sec.at("public_network").clone(),
    })
}

/// The network configuration findings. `now_ms` dates "recent" (ms since 1970).
pub(crate) fn items(raw: &Value, now_ms: i64) -> Vec<Item> {
    let sec = section(raw);
    if !truthy(sec) {
        return Vec::new();
    }
    let mut out = Vec::new();
    dns_items(raw, now_ms, &mut out);
    doh_items(sec, &mut out);
    proxy_items(raw, &mut out);
    route_items(raw, &mut out);
    driver_items(sec, &mut out);
    if let Some(item) = broadcast_item(raw) {
        out.push(item);
    }
    out
}

fn dns_items(raw: &Value, now_ms: i64, out: &mut Vec<Item>) {
    let servers = hand_set_servers(raw);
    if !servers.is_empty() {
        let with_dns = adapters(raw)
            .iter()
            .filter(|a| truthy(a.at("up")) && !list(a.at("dns")).is_empty() && !known_virtual(a))
            .count();
        // The same unusual server on every connected adapter: set everywhere on purpose.
        let everywhere = with_dns >= 2 && servers.values().any(|names| names.len() >= with_dns);
        // Without DHCP the settings key only changes when someone changes the settings.
        let recent_ms = now_ms - RECENT_DAYS * 24 * 3_600_000;
        let recent = adapters(raw).iter().any(|a| {
            truthy(a.at("up"))
                && !truthy(a.at("dhcp"))
                && list(a.at("static_dns")).iter().any(|s| servers.contains_key(&text(s)))
                && as_int(a.at("settings_written_ms")).is_some_and(|t| t >= recent_ms && t <= now_ms)
        });
        let listed: Map<String, Value> = servers
            .iter()
            .map(|(server, names)| (server.clone(), json!(names.iter().collect::<Vec<_>>())))
            .collect();
        out.push(config(
            "dns_set_by_hand",
            tr!("DNS servers set by hand or by a program"),
            if everywhere || recent { 50 } else { 30 },
            if everywhere {
                tr!("every connected adapter asks the same server outside your network, which is neither your router nor a well-known resolver; whoever runs it sees and can change the sites you visit")
            } else if recent {
                tr!("a DNS server outside your network, which is neither your router nor a well-known resolver, was set in the last days; whoever runs it sees and can change the sites you visit")
            } else {
                tr!("an adapter asks a DNS server outside your network that is neither your router nor a well-known resolver; whoever runs it sees and can change the sites you visit")
            },
            map(vec![("servers", Value::Object(listed)), ("recent", json!(recent))]),
        ));
    }

    let mut rules = Vec::new();
    for rule in list(section(raw).at("nrpt")) {
        let unusual: Vec<String> = list(rule.at("servers"))
            .iter()
            .map(text)
            .filter(|s| is_unusual_server(s))
            .collect();
        if !unusual.is_empty() {
            rules.push(json!({
                "namespaces": rule.at("namespaces").clone(),
                "servers": unusual,
                "source": rule.at("source").clone(),
            }));
        }
    }
    if !rules.is_empty() {
        out.push(config(
            "dns_policy_rule",
            tr!("Name resolution rules send some names to an unusual server"),
            35,
            tr!("rules in the name resolution policy send some names to a server outside your network; companies use them, and so does malware that wants to answer for chosen sites"),
            map(vec![("rules", json!(rules))]),
        ));
    }
}

fn doh_items(sec: &Value, out: &mut Vec<Item>) {
    let mut found = Vec::new();
    for entry in list(sec.at("doh_servers")) {
        let template = text(entry.at("template"));
        if !template.is_empty() && !is_known_doh(&template) {
            found.push(json!({"where": "windows", "server": entry.at("server").clone(), "template": template}));
        }
    }
    for entry in list(sec.at("doh_adapters")) {
        let template = text(entry.at("template"));
        if !template.is_empty() && !is_known_doh(&template) {
            found.push(json!({"where": "adapter", "server": entry.at("server").clone(), "template": template}));
        }
    }
    for rule in list(sec.at("nrpt")) {
        let template = text(rule.at("doh_template"));
        if !template.is_empty() && !is_known_doh(&template) {
            found.push(json!({"where": "rule", "template": template}));
        }
    }
    for policy in list(sec.at("browser_doh")) {
        if lower(&text(policy.at("mode"))) == "off" {
            continue;
        }
        for template in list(policy.at("templates")).iter().map(text) {
            if !is_known_doh(&template) {
                found.push(json!({
                    "where": "browser",
                    "browser": policy.at("browser").clone(),
                    "hive": policy.at("hive").clone(),
                    "template": template,
                }));
            }
        }
    }
    if !found.is_empty() {
        out.push(config(
            "doh_unknown",
            tr!("Encrypted DNS goes to an unknown service"),
            30,
            tr!("DNS over HTTPS is set to a service that is not a well-known resolver; it sees every site you look up, and the encryption hides that from other tools"),
            map(vec![("templates", json!(found))]),
        ));
    }
}

/// The program listening on a local port (its path, "" when unknown).
fn listener(raw: &Value, port: i64) -> Option<String> {
    let pid = list(raw.at("network").at("tcp")).iter().find_map(|c| {
        (lower(&text(c.at("state"))) == "listen" && as_int(c.at("lport")) == Some(port))
            .then(|| as_int(c.at("pid")))
            .flatten()
    })?;
    Some(
        list(raw.at("processes"))
            .iter()
            .find(|p| as_int(p.at("pid")) == Some(pid))
            .map(|p| text(p.at("path")))
            .unwrap_or_default(),
    )
}

fn proxy_items(raw: &Value, out: &mut Vec<Item>) {
    let sec = section(raw);
    let winhttp = sec.at("winhttp");
    let user = sec.at("user_proxy");
    // (setting, target): the WinHTTP proxy, the user's proxy and the proxy script's address.
    let mut targets: Vec<(&str, String)> = Vec::new();
    if text(winhttp.at("kind")) == "named" {
        for target in proxy_targets(&text(winhttp.at("server"))) {
            targets.push(("winhttp", target));
        }
        out.push(config(
            "winhttp_proxy",
            tr!("Proxy for Windows services set"),
            25,
            tr!("Windows services and updates send their web traffic through an intermediary"),
            map(vec![
                ("server", winhttp.at("server").clone()),
                ("bypass", winhttp.at("bypass").clone()),
            ]),
        ));
    }
    for target in proxy_targets(&text(user.at("server"))) {
        targets.push(("user", target));
    }
    let pac = text(user.at("pac_url"));
    if !pac.is_empty() {
        targets.push(("pac", pac));
    }

    let mut local = Vec::new();
    let mut outside = Vec::new();
    for (setting, target) in &targets {
        let host = host_of(target);
        let ip = parse_ip(&host);
        if host == "localhost" || ip.is_some_and(|ip| ip.is_loopback()) {
            let port = port_of(target);
            let owner = port.and_then(|p| listener(raw, p));
            let suspicious = match &owner {
                None => true,
                Some(path) => path.is_empty() || is_user_writable(path),
            };
            if suspicious {
                local.push(json!({"setting": setting, "target": target, "program": owner.unwrap_or_default()}));
            }
        } else if ip.is_some_and(|ip| !is_lan(ip)) {
            outside.push(json!({"setting": setting, "target": target}));
        }
    }
    if !local.is_empty() {
        out.push(config(
            "proxy_local_program",
            tr!("Web traffic goes through an unknown program on this computer"),
            60,
            tr!("a proxy setting points to a port on this computer that no program listens on, or that a program in a folder anyone can change listens on; that program can read and change your web traffic"),
            map(vec![("proxies", json!(local))]),
        ));
    }
    if !outside.is_empty() {
        out.push(config(
            "proxy_outside",
            tr!("Web traffic goes through a server on the internet"),
            45,
            tr!("a proxy setting points to an address on the internet; whoever runs that server sees and can change your web traffic"),
            map(vec![("proxies", json!(outside))]),
        ));
    }

    // WPAD: automatic detection on and the hosts file answering for "wpad".
    if truthy(user.at("auto_detect")) {
        let hijacked: Vec<Value> = list(raw.at("sysconfig").at("hosts"))
            .iter()
            .filter(|entry| parse_ip(&text(entry.at("ip"))).is_some_and(|ip| !ip.is_loopback() && !ip.is_unspecified()))
            .filter_map(|entry| {
                let names: Vec<String> = list(entry.at("names"))
                    .iter()
                    .map(|n| lower(&text(n)))
                    .filter(|n| n == "wpad" || n.starts_with("wpad."))
                    .collect();
                (!names.is_empty()).then(|| json!({"ip": entry.at("ip").clone(), "names": names}))
            })
            .collect();
        if !hijacked.is_empty() {
            out.push(config(
                "wpad_hosts",
                tr!("Automatic proxy detection is redirected"),
                60,
                tr!("\"Automatically detect settings\" is on and the hosts file sends the detection name (wpad) to a chosen address, which can then give this computer any proxy"),
                map(vec![("entries", json!(hijacked))]),
            ));
        }
    }
}

fn route_items(raw: &Value, out: &mut Vec<Item>) {
    let gateways: BTreeSet<String> = adapters(raw)
        .iter()
        .flat_map(|a| list(a.at("gateways")).iter().map(|g| lower(&text(g))))
        .collect();
    let mut odd = Vec::new();
    let mut default_route = false;
    for route in list(section(raw).at("routes")) {
        let destination = text(route.at("destination"));
        let gateway = text(route.at("gateway"));
        let is_default = destination == "0.0.0.0" && text(route.at("mask")) == "0.0.0.0";
        let usual_gateway = gateways.contains(&lower(&gateway));
        let public_destination = parse_ip(&destination).is_some_and(|ip| !is_lan(ip));
        if (is_default && !usual_gateway) || (public_destination && !usual_gateway) {
            default_route |= is_default;
            odd.push(route.clone());
        }
    }
    if !odd.is_empty() {
        out.push(config(
            "persistent_routes",
            tr!("Permanent routes send traffic another way"),
            if default_route { 35 } else { 20 },
            if default_route {
                tr!("a permanent route sends all internet traffic through an address that is not one of your adapters' gateways")
            } else {
                tr!("permanent routes send traffic for internet addresses through an address that is not one of your adapters' gateways; VPN and network tools add them, and so can malware")
            },
            map(vec![("routes", json!(odd))]),
        ));
    }
}

fn driver_items(sec: &Value, out: &mut Vec<Item>) {
    let unknown_adapters: Vec<Value> = list(sec.at("adapters"))
        .iter()
        .filter(|a| {
            let tunnel = TUNNEL_RX.is_match(&format!("{} {}", text(a.at("component")), text(a.at("description"))))
                || matches!(as_int(a.at("if_type")), Some(53 | 131));
            tunnel && !is_known_vendor(&text(a.at("provider")))
        })
        .map(|a| {
            json!({
                "name": a.at("name").clone(),
                "description": a.at("description").clone(),
                "provider": a.at("provider").clone(),
                "component": a.at("component").clone(),
            })
        })
        .collect();
    if !unknown_adapters.is_empty() {
        out.push(config(
            "virtual_adapter_unknown",
            tr!("Virtual network adapter from an unknown vendor"),
            25,
            tr!("a tunnel or virtual network adapter was installed by a driver that comes from neither Microsoft nor a known VPN or virtualization vendor; traffic sent through it can be read by whoever runs it"),
            map(vec![("adapters", json!(unknown_adapters))]),
        ));
    }
    let unknown_filters: Vec<Value> = list(sec.at("filters"))
        .iter()
        .filter(|f| !is_known_vendor(&text(f.at("provider"))))
        .cloned()
        .collect();
    if !unknown_filters.is_empty() {
        out.push(config(
            "network_filter_unknown",
            tr!("Network filter driver from an unknown vendor"),
            20,
            tr!("a driver that sees every network packet was installed by a vendor that is neither Microsoft nor a known network, VPN or security company"),
            map(vec![("filters", json!(unknown_filters))]),
        ));
    }
}

fn broadcast_item(raw: &Value) -> Option<Item> {
    let summary = posture(raw);
    let public = summary.at("public_network").as_bool() == Some(true);
    let llmnr = truthy(summary.at("llmnr"));
    let netbios = as_int(summary.at("netbios_adapters")).unwrap_or(0);
    (public && (llmnr || netbios > 0)).then(|| {
        config(
            "name_broadcasts",
            tr!("Names are broadcast on a public network"),
            10,
            tr!("LLMNR or NetBIOS answer name lookups by asking every device on the network; on a public network another device can answer and catch a sign-in attempt"),
            map(vec![("llmnr", json!(llmnr)), ("netbios_adapters", json!(netbios))]),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_800_000_000_000;
    const DAY: i64 = 24 * 3_600_000;

    fn adapter(name: &str, statics: &[&str], dhcp: bool, written: i64) -> Value {
        json!({
            "guid": format!("{{{name}}}"),
            "name": name,
            "description": "Contoso Gigabit Network Connection",
            "if_type": 6,
            "up": true,
            "dhcp": dhcp,
            "gateways": ["192.168.1.1"],
            "dns": statics,
            "static_dns": statics,
            "dhcp_dns": [],
            "settings_written_ms": written,
            "provider": "Contoso",
            "component": "pci\\ven_8086",
            "netbios": 2,
        })
    }

    fn inventory(section: Value) -> Value {
        json!({"sysconfig": {"network_config": section, "hosts": []}, "network": {"tcp": []}, "processes": []})
    }

    fn topics(items: &[Item]) -> Vec<String> {
        items.iter().map(|i| text(i.facts.at("topic"))).collect()
    }

    fn score(items: &[Item], topic: &str) -> i64 {
        items
            .iter()
            .find(|i| text(i.facts.at("topic")) == topic)
            .map_or(-1, |i| i.score)
    }

    #[test]
    fn addresses_are_classified() {
        assert!(is_lan("192.168.1.1".parse().expect("ip")));
        assert!(is_lan("100.100.100.100".parse().expect("ip")));
        assert!(is_lan("fec0:0:0:ffff::1".parse().expect("ip")));
        assert!(is_lan("fd00::1".parse().expect("ip")));
        assert!(!is_lan("203.0.113.5".parse().expect("ip")));
        assert!(is_known_resolver("1.1.1.1"));
        assert!(is_known_resolver("2606:4700:4700::1111"));
        assert!(is_unusual_server("203.0.113.5"));
        assert!(!is_unusual_server("8.8.8.8"));
        assert!(!is_unusual_server("10.0.0.53"));
        assert_eq!(host_of("https://dns.example/dns-query{?dns}"), "dns.example");
        assert_eq!(host_of("http://203.0.113.9:8080/proxy.pac"), "203.0.113.9");
        assert_eq!(host_of("127.0.0.1:8888"), "127.0.0.1");
        assert_eq!(host_of("[::1]:8080"), "::1");
        assert_eq!(port_of("127.0.0.1:8888"), Some(8888));
        assert_eq!(port_of("http://127.0.0.1/proxy.pac"), Some(80));
        assert!(is_known_doh("https://mozilla.cloudflare-dns.com/dns-query"));
        assert!(!is_known_doh("https://doh.example/dns-query"));
        assert!(is_known_vendor("WireGuard LLC"));
        assert!(is_known_vendor("Microsoft"));
        assert!(!is_known_vendor("Fabrikam Networks"));
        assert!(!is_known_vendor("Ambiguous AMDX Labs"));
        assert_eq!(
            proxy_targets("http=127.0.0.1:8888;https=127.0.0.1:8888"),
            vec!["127.0.0.1:8888", "127.0.0.1:8888"]
        );
    }

    #[test]
    fn hand_set_dns_is_judged_by_where_it_points() {
        // Router, well-known resolvers and DHCP-only servers: nothing.
        let quiet = inventory(json!({"adapters": [
            adapter("Wi-Fi", &["192.168.1.1", "1.1.1.1", "2606:4700:4700::1111"], true, NOW),
        ]}));
        assert!(items(&quiet, NOW).is_empty());
        assert!(hand_set_dns(&quiet).is_empty());

        // An unusual server on one adapter with DHCP: worth a look.
        let one = inventory(json!({"adapters": [
            adapter("Wi-Fi", &["203.0.113.53"], true, NOW),
            adapter("Ethernet", &[], true, NOW),
        ]}));
        let found = items(&one, NOW);
        assert_eq!(score(&found, "dns_set_by_hand"), 30);
        assert_eq!(hand_set_dns(&one), BTreeSet::from(["203.0.113.53".to_string()]));

        // The same server on every connected adapter: high.
        let everywhere = inventory(json!({"adapters": [
            adapter("Wi-Fi", &["203.0.113.53"], true, NOW),
            adapter("Ethernet", &["203.0.113.53"], true, NOW),
        ]}));
        assert_eq!(score(&items(&everywhere, NOW), "dns_set_by_hand"), 50);

        // Set recently on an adapter without DHCP: high; long ago: worth a look.
        let recent = inventory(json!({"adapters": [adapter("Ethernet", &["198.51.100.53"], false, NOW - DAY)]}));
        assert_eq!(score(&items(&recent, NOW), "dns_set_by_hand"), 50);
        let old = inventory(json!({"adapters": [adapter("Ethernet", &["198.51.100.53"], false, NOW - 90 * DAY)]}));
        assert_eq!(score(&items(&old, NOW), "dns_set_by_hand"), 30);

        // A known VPN's own adapter: its DNS is its business.
        let mut vpn = adapter("Tunnel", &["198.51.100.53"], false, NOW);
        vpn["provider"] = json!("WireGuard LLC");
        vpn["component"] = json!("wireguard");
        vpn["if_type"] = json!(53);
        assert!(!topics(&items(&inventory(json!({"adapters": [vpn]})), NOW)).contains(&"dns_set_by_hand".to_string()));
    }

    #[test]
    fn doh_rules_and_policies() {
        let section = json!({
            "adapters": [],
            "doh_servers": [
                {"server": "1.1.1.1", "template": "https://cloudflare-dns.com/dns-query"},
                {"server": "203.0.113.53", "template": "https://doh.example/dns-query"},
            ],
            "doh_adapters": [],
            "nrpt": [
                {"rule": "{1}", "source": "local", "namespaces": [".bank.example"], "servers": ["203.0.113.54"], "doh_template": ""},
                {"rule": "{2}", "source": "policy", "namespaces": [".corp.example"], "servers": ["10.0.0.53"], "doh_template": ""},
            ],
            "browser_doh": [
                {"browser": "Chrome", "hive": "HKLM", "mode": "secure", "templates": ["https://dns.fabrikam.example/q"]},
                {"browser": "Edge", "hive": "HKLM", "mode": "off", "templates": ["https://dns.fabrikam.example/q"]},
            ],
        });
        let found = items(&inventory(section), NOW);
        assert_eq!(score(&found, "doh_unknown"), 30);
        let doh = found
            .iter()
            .find(|i| text(i.facts.at("topic")) == "doh_unknown")
            .expect("doh");
        assert_eq!(
            list(doh.facts.at("templates")).len(),
            2,
            "system template and Chrome; Edge's is off"
        );
        assert_eq!(score(&found, "dns_policy_rule"), 35);
        let rule = found
            .iter()
            .find(|i| text(i.facts.at("topic")) == "dns_policy_rule")
            .expect("rule");
        assert_eq!(
            list(rule.facts.at("rules")).len(),
            1,
            "the corporate rule to a LAN server is fine"
        );
    }

    #[test]
    fn proxies_are_judged_by_where_they_point() {
        let mut raw = inventory(json!({
            "adapters": [],
            "winhttp": {"kind": "named", "server": "203.0.113.80:3128", "bypass": ""},
            "user_proxy": {"auto_detect": true, "pac_url": "", "server": "127.0.0.1:8888", "bypass": ""},
        }));
        // Nobody listens on 8888: high.
        let found = items(&raw, NOW);
        assert_eq!(score(&found, "winhttp_proxy"), 25);
        assert_eq!(score(&found, "proxy_outside"), 45);
        assert_eq!(score(&found, "proxy_local_program"), 60);

        // A program in Program Files listens on it: not reported.
        raw["network"]["tcp"] = json!([{"state": "Listen", "laddr": "127.0.0.1", "lport": 8888, "pid": 4120}]);
        raw["processes"] = json!([{"pid": 4120, "path": r"C:\Program Files\Contoso Debugger\debugger.exe"}]);
        assert!(!topics(&items(&raw, NOW)).contains(&"proxy_local_program".to_string()));

        // The same port held by a program in AppData: high again.
        raw["processes"] = json!([{"pid": 4120, "path": r"C:\Users\jdoe\AppData\Roaming\Fabrikam\relay.exe"}]);
        assert_eq!(score(&items(&raw, NOW), "proxy_local_program"), 60);

        // WPAD: auto-detect on and the hosts file answering for wpad.
        raw["sysconfig"]["hosts"] = json!([{"ip": "203.0.113.7", "names": ["wpad", "wpad.home.example"]}]);
        assert_eq!(score(&items(&raw, NOW), "wpad_hosts"), 60);
        raw["sysconfig"]["network_config"]["user_proxy"]["auto_detect"] = json!(false);
        assert!(!topics(&items(&raw, NOW)).contains(&"wpad_hosts".to_string()));
    }

    #[test]
    fn routes_drivers_and_broadcasts() {
        let mut tap = adapter("Local Area Connection", &[], true, NOW);
        tap["description"] = json!("Fabrikam TAP Adapter");
        tap["component"] = json!("tap_fabrikam");
        tap["provider"] = json!("Fabrikam Networks");
        tap["if_type"] = json!(53);
        let mut wg = adapter("wg0", &[], true, NOW);
        wg["description"] = json!("WireGuard Tunnel");
        wg["component"] = json!("wireguard_tunnel");
        wg["provider"] = json!("WireGuard LLC");
        let mut eth = adapter("Ethernet", &[], true, NOW);
        eth["netbios"] = json!(0);
        let section = json!({
            "adapters": [tap, wg, eth],
            "routes": [
                {"destination": "10.20.0.0", "mask": "255.255.0.0", "gateway": "192.168.1.50", "metric": "1"},
                {"destination": "203.0.113.0", "mask": "255.255.255.0", "gateway": "192.168.1.1", "metric": "1"},
                {"destination": "0.0.0.0", "mask": "0.0.0.0", "gateway": "192.168.1.66", "metric": "1"},
            ],
            "filters": [
                {"component": "ms_wfplwf", "provider": "Microsoft", "description": "WFP Lightweight Filter"},
                {"component": "npcap", "provider": "Insecure.Com LLC", "description": "Npcap Packet Driver"},
                {"component": "fb_lwf", "provider": "Fabrikam Networks", "description": "Fabrikam Traffic Shaper"},
            ],
            "llmnr_off": false,
            "public_network": true,
        });
        let found = items(&inventory(section.clone()), NOW);
        assert_eq!(
            score(&found, "persistent_routes"),
            35,
            "a default route through an unknown gateway"
        );
        let routes = found
            .iter()
            .find(|i| text(i.facts.at("topic")) == "persistent_routes")
            .expect("routes");
        assert_eq!(
            list(routes.facts.at("routes")).len(),
            1,
            "LAN routes and routes through the gateway are fine"
        );
        assert_eq!(score(&found, "virtual_adapter_unknown"), 25);
        let adapters = found
            .iter()
            .find(|i| text(i.facts.at("topic")) == "virtual_adapter_unknown")
            .expect("adapters");
        assert_eq!(
            list(adapters.facts.at("adapters")).len(),
            1,
            "WireGuard's own adapter is fine"
        );
        assert_eq!(score(&found, "network_filter_unknown"), 20);
        assert_eq!(score(&found, "name_broadcasts"), 10);

        // On a private network LLMNR and NetBIOS are only a posture fact.
        let mut private = section;
        private["public_network"] = json!(false);
        let raw = inventory(private);
        assert!(!topics(&items(&raw, NOW)).contains(&"name_broadcasts".to_string()));
        assert_eq!(posture(&raw)["netbios_adapters"], json!(1));
        assert_eq!(posture(&raw)["llmnr"], json!(true));
    }

    #[test]
    #[ignore = "reads this computer's network configuration; prints topics and scores only"]
    fn live_findings() {
        let raw = json!({"sysconfig": {"network_config": collect()}, "network": {}, "processes": []});
        let found = items(&raw, chrono::Local::now().timestamp_millis());
        let summary: Vec<(String, i64)> = found.iter().map(|i| (text(i.facts.at("topic")), i.score)).collect();
        println!("findings {summary:?}; hand-set servers {}", hand_set_dns(&raw).len());
    }

    #[test]
    fn an_inventory_without_the_section_has_no_findings() {
        let raw = json!({"sysconfig": {}, "network": {}});
        assert!(items(&raw, NOW).is_empty());
        assert!(hand_set_dns(&raw).is_empty());
        assert!(posture(&raw).is_null());
    }
}
