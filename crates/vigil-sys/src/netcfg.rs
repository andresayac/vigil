//! The network configuration that decides where name lookups and web traffic go. READ-ONLY:
//! local configuration only (IP Helper, the registry, WinHTTP's stored settings, the Network List
//! Manager); nothing is looked up, sent or changed.
//!
//! - [`adapters`]: each adapter's DNS servers, set by hand (`NameServer`) or by DHCP, its
//!   gateways, its driver's provider and NetBIOS setting;
//! - [`read`]: everything the scan judges: also DNS over HTTPS templates (system, per adapter and
//!   browser policies), name resolution policy rules (NRPT), the WinHTTP and per-user proxy,
//!   persistent routes, network filter drivers, LLMNR and whether a public network is connected;
//! - [`winhttp_proxy`] and [`user_proxy`] are also what the background watch compares.

use serde::Serialize;

/// One network adapter.
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
pub struct Adapter {
    /// `{GUID}` of the adapter (its registry name).
    pub guid: String,
    /// The name Windows shows ("Wi-Fi", "Ethernet 2").
    pub name: String,
    pub description: String,
    /// IANA interface type (6 Ethernet, 71 Wi-Fi, 53 virtual, 131 tunnel, 24 loopback).
    pub if_type: u32,
    pub up: bool,
    /// IPv4 address assigned by DHCP.
    pub dhcp: bool,
    pub gateways: Vec<String>,
    /// The DNS servers in use (IPv4 and IPv6), as Windows reports them.
    pub dns: Vec<String>,
    /// DNS servers set by hand or by a program (`NameServer`, IPv4 and IPv6).
    pub static_dns: Vec<String>,
    /// DNS servers the network handed out (`DhcpNameServer`).
    pub dhcp_dns: Vec<String>,
    /// When the adapter's IPv4 settings key was last written (ms since 1970). DHCP renewals write
    /// there too, so it only dates a hand-set server on an adapter without DHCP.
    pub settings_written_ms: Option<i64>,
    /// The driver's provider and component id (the network adapter class key).
    pub provider: String,
    pub component: String,
    /// NetBIOS over TCP/IP: 0 as the network says (DHCP), 1 on, 2 off; `None` when not set.
    pub netbios: Option<u32>,
}

/// A DNS over HTTPS template Windows knows for a server address.
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
pub struct DohServer {
    pub server: String,
    pub template: String,
}

/// DNS over HTTPS set on one adapter for one of its servers.
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
pub struct DohAdapter {
    pub adapter: String,
    pub server: String,
    /// A template set for this adapter only ("" when it uses the system's).
    pub template: String,
    pub flags: u64,
}

/// A name resolution policy rule (NRPT): names under these namespaces go to these servers.
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
pub struct NrptRule {
    pub rule: String,
    /// "policy" (group policy) or "local".
    pub source: String,
    pub namespaces: Vec<String>,
    pub servers: Vec<String>,
    pub doh_template: String,
}

/// A DNS over HTTPS policy of a browser.
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
pub struct BrowserDoh {
    pub browser: String,
    /// "HKLM" or "HKCU".
    pub hive: String,
    /// "off", "automatic", "secure" or "" (Firefox: "on"/"off").
    pub mode: String,
    pub templates: Vec<String>,
}

/// WinHTTP's proxy (services and system components use it).
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
pub struct Proxy {
    /// "direct" or "named".
    pub kind: String,
    pub server: String,
    pub bypass: String,
}

/// The proxy settings of the current user (browsers and most programs use them).
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
pub struct UserProxy {
    /// "Automatically detect settings" (WPAD).
    pub auto_detect: bool,
    pub pac_url: String,
    pub server: String,
    pub bypass: String,
}

/// A persistent route (`route -p`).
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
pub struct Route {
    pub destination: String,
    pub mask: String,
    pub gateway: String,
    pub metric: String,
}

/// A network filter driver (lightweight filter) bound to the adapters.
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
pub struct Filter {
    pub component: String,
    /// "Microsoft" for filters installed by an INF that ships with Windows; otherwise the
    /// CompanyName of the driver file ("" when it has none).
    pub provider: String,
    pub description: String,
    /// The INF that installed it (`oemNN.inf` for third-party drivers).
    pub inf: String,
    /// The driver's service and file.
    pub service: String,
    pub file: String,
}

/// A driver path as the service database writes it (`\SystemRoot\…`, `System32\…`, `\??\C:\…`),
/// made absolute with the Windows folder.
pub fn driver_file(image_path: &str, windows_dir: &str) -> String {
    let path = image_path.trim().trim_matches('"');
    let path = path.strip_prefix(r"\??\").unwrap_or(path);
    let windows_dir = windows_dir.trim_end_matches('\\');
    let lower = path.to_ascii_lowercase();
    if let Some(rest) = lower.strip_prefix(r"\systemroot\") {
        return format!(r"{windows_dir}\{}", &path[path.len() - rest.len()..]);
    }
    if let Some(rest) = lower.strip_prefix("%systemroot%\\") {
        return format!(r"{windows_dir}\{}", &path[path.len() - rest.len()..]);
    }
    if lower.starts_with(r"system32\") || lower.starts_with(r"syswow64\") {
        return format!(r"{windows_dir}\{path}");
    }
    path.to_string()
}

/// Everything the scan reads. A list is `None` when it could not be read.
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
pub struct NetConfig {
    pub adapters: Option<Vec<Adapter>>,
    pub doh_servers: Vec<DohServer>,
    pub doh_adapters: Vec<DohAdapter>,
    pub nrpt: Vec<NrptRule>,
    pub browser_doh: Vec<BrowserDoh>,
    pub winhttp: Option<Proxy>,
    pub user_proxy: Option<UserProxy>,
    pub routes: Option<Vec<Route>>,
    pub filters: Option<Vec<Filter>>,
    /// LLMNR turned off by policy (`EnableMulticast` = 0); on otherwise, as Windows ships.
    pub llmnr_off: bool,
    /// A network marked Public is connected now; `None` when Windows did not say.
    pub public_network: Option<bool>,
}

/// Splits a server list as the registry writes it ("1.1.1.1,8.8.8.8", "1.1.1.1 8.8.8.8").
pub fn split_servers(text: &str) -> Vec<String> {
    text.split([',', ' ', ';'])
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

/// A persistent route from its value name ("0.0.0.0,0.0.0.0,192.168.1.1,1").
pub fn parse_route(name: &str) -> Option<Route> {
    let parts: Vec<&str> = name.split(',').map(str::trim).collect();
    if parts.len() < 3 || parts[0].is_empty() {
        return None;
    }
    Some(Route {
        destination: parts[0].to_string(),
        mask: parts[1].to_string(),
        gateway: parts[2].to_string(),
        metric: parts.get(3).map(|s| s.to_string()).unwrap_or_default(),
    })
}

#[cfg(windows)]
pub use imp::{adapters, adapters_light, read, user_proxy, winhttp_proxy};

#[cfg(not(windows))]
pub fn adapters() -> Option<Vec<Adapter>> {
    None
}
#[cfg(not(windows))]
pub fn adapters_light() -> Option<Vec<Adapter>> {
    None
}
#[cfg(not(windows))]
pub fn read() -> NetConfig {
    NetConfig::default()
}
#[cfg(not(windows))]
pub fn winhttp_proxy() -> Option<Proxy> {
    None
}
#[cfg(not(windows))]
pub fn user_proxy() -> Option<UserProxy> {
    None
}

#[cfg(windows)]
mod imp {
    use std::collections::{BTreeMap, HashMap};
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::sync::mpsc;
    use std::time::Duration;

    use windows::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, ERROR_SUCCESS, FILETIME, GlobalFree, HGLOBAL, NO_ERROR};
    use windows::Win32::NetworkManagement::IpHelper::{
        GAA_FLAG_INCLUDE_GATEWAYS, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_MULTICAST, GAA_FLAG_SKIP_UNICAST,
        GetAdaptersAddresses, IP_ADAPTER_ADDRESSES_LH, IP_ADAPTER_DHCP_ENABLED,
    };
    use windows::Win32::NetworkManagement::Ndis::IfOperStatusUp;
    use windows::Win32::Networking::NetworkListManager::{
        INetworkListManager, NLM_ENUM_NETWORK_CONNECTED, NLM_NETWORK_CATEGORY_PUBLIC, NetworkListManager,
    };
    use windows::Win32::Networking::WinHttp::{
        WINHTTP_ACCESS_TYPE_NAMED_PROXY, WINHTTP_CURRENT_USER_IE_PROXY_CONFIG, WINHTTP_PROXY_INFO,
        WinHttpGetDefaultProxyConfiguration, WinHttpGetIEProxyConfigForCurrentUser,
    };
    use windows::Win32::Networking::WinSock::{
        AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR_IN, SOCKADDR_IN6, SOCKET_ADDRESS,
    };
    use windows::Win32::System::Com::{
        CLSCTX_ALL, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx, CoUninitialize,
    };
    use windows::Win32::System::Registry::{
        HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_WOW64_64KEY, RegQueryInfoKeyW,
    };
    use windows::core::PWSTR;

    use super::{Adapter, BrowserDoh, DohAdapter, DohServer, Filter, NetConfig, NrptRule, Proxy, Route, UserProxy};
    use super::{parse_route, split_servers};
    use crate::hooks::{Key, text};

    const TCPIP: &str = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters";
    const TCPIP6: &str = r"SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters";
    const DNSCACHE: &str = r"SYSTEM\CurrentControlSet\Services\Dnscache";
    const NETBT: &str = r"SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces";
    /// The network adapter device class.
    const ADAPTER_CLASS: &str = r"SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}";
    /// The network services (filters and protocols) and their settings.
    const NETWORK_SERVICES: &str = r"SYSTEM\CurrentControlSet\Control\Network\{4d36e974-e325-11ce-bfc1-08002be10318}";
    /// `Characteristics` flag of a lightweight filter driver.
    const NCF_LW_FILTER: u64 = 0x4_0000;
    /// The most subkeys read under one key (a bound, not an expected size).
    const MAX_SUBKEYS: usize = 500;

    /// Every value of a key, names in lower case -> text; `None` when it is missing or unreadable.
    fn values(root: HKEY, path: &str) -> Option<BTreeMap<String, String>> {
        let key = Key::open(root, path, KEY_WOW64_64KEY).ok()??;
        Some(
            key.raw_values()?
                .into_iter()
                .map(|(name, kind, data)| (name.to_ascii_lowercase(), text(kind, &data)))
                .collect(),
        )
    }

    fn subkeys(root: HKEY, path: &str) -> Vec<String> {
        match Key::open(root, path, KEY_WOW64_64KEY) {
            Ok(Some(key)) => key
                .subkeys()
                .unwrap_or_default()
                .into_iter()
                .take(MAX_SUBKEYS)
                .collect(),
            _ => Vec::new(),
        }
    }

    fn get(values: &BTreeMap<String, String>, name: &str) -> String {
        values.get(&name.to_ascii_lowercase()).cloned().unwrap_or_default()
    }

    fn number(values: &BTreeMap<String, String>, name: &str) -> Option<u64> {
        values
            .get(&name.to_ascii_lowercase())
            .and_then(|v| v.trim().parse().ok())
    }

    /// When a key was last written, in ms since 1970.
    fn written_ms(root: HKEY, path: &str) -> Option<i64> {
        let key = Key::open(root, path, KEY_WOW64_64KEY).ok()??;
        let mut time = FILETIME::default();
        // SAFETY: the key handle is open for reading; only the last-write time is requested.
        let status = unsafe {
            RegQueryInfoKeyW(
                key.0,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                Some(&mut time),
            )
        };
        if status != ERROR_SUCCESS {
            return None;
        }
        let ticks = (u64::from(time.dwHighDateTime) << 32) | u64::from(time.dwLowDateTime);
        // 100 ns ticks since 1601 -> ms since 1970.
        Some((ticks / 10_000) as i64 - 11_644_473_600_000)
    }

    /// An IP address as text.
    fn address_text(address: &SOCKET_ADDRESS) -> Option<String> {
        if address.lpSockaddr.is_null() {
            return None;
        }
        // SAFETY: `lpSockaddr` points to a socket address of `iSockaddrLength` bytes written by
        // GetAdaptersAddresses inside its buffer; the family says which layout it has.
        unsafe {
            let family = (*address.lpSockaddr).sa_family;
            if family == AF_INET && address.iSockaddrLength as usize >= size_of::<SOCKADDR_IN>() {
                let v4 = &*address.lpSockaddr.cast::<SOCKADDR_IN>();
                Some(Ipv4Addr::from(u32::from_be(v4.sin_addr.S_un.S_addr)).to_string())
            } else if family == AF_INET6 && address.iSockaddrLength as usize >= size_of::<SOCKADDR_IN6>() {
                let v6 = &*address.lpSockaddr.cast::<SOCKADDR_IN6>();
                Some(Ipv6Addr::from(v6.sin6_addr.u.Byte).to_string())
            } else {
                None
            }
        }
    }

    /// The adapters' drivers by `{GUID}`: (provider, component id).
    fn adapter_drivers() -> HashMap<String, (String, String)> {
        let mut out = HashMap::new();
        for sub in subkeys(HKEY_LOCAL_MACHINE, ADAPTER_CLASS) {
            if !sub.chars().all(|c| c.is_ascii_digit()) {
                continue;
            }
            let Some(v) = values(HKEY_LOCAL_MACHINE, &format!(r"{ADAPTER_CLASS}\{sub}")) else {
                continue;
            };
            let guid = get(&v, "NetCfgInstanceId").to_ascii_lowercase();
            if !guid.is_empty() {
                out.insert(guid, (get(&v, "ProviderName"), get(&v, "ComponentId")));
            }
        }
        out
    }

    /// Every adapter Windows knows (up or not), with its DNS settings; `None` when IP Helper fails.
    pub fn adapters() -> Option<Vec<Adapter>> {
        adapters_with(true)
    }

    /// The adapters with their DNS servers only (no driver, NetBIOS or key times): what the
    /// background watch compares every minute.
    pub fn adapters_light() -> Option<Vec<Adapter>> {
        adapters_with(false)
    }

    fn adapters_with(full: bool) -> Option<Vec<Adapter>> {
        let flags = GAA_FLAG_SKIP_UNICAST | GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_INCLUDE_GATEWAYS;
        let mut size = 32 * 1024u32;
        let mut list = Vec::new();
        let mut read = false;
        for _ in 0..4 {
            let mut buffer = vec![0u64; (size as usize).div_ceil(8)];
            let first = buffer.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
            // SAFETY: the buffer is writable for `size` bytes and 8-byte aligned.
            let status = unsafe { GetAdaptersAddresses(AF_UNSPEC.0 as u32, flags, None, Some(first), &mut size) };
            if status == ERROR_BUFFER_OVERFLOW.0 {
                continue;
            }
            if status != NO_ERROR.0 {
                return None;
            }
            read = true;
            let mut current = first.cast_const();
            while !current.is_null() {
                // SAFETY: `current` is the first entry or a `Next` link written by
                // GetAdaptersAddresses; every entry lives inside `buffer`, which outlives this loop.
                let adapter = unsafe { &*current };
                current = adapter.Next.cast_const();
                if adapter.IfType == 24 {
                    continue; // loopback
                }
                // SAFETY: AdapterName is a NUL-terminated ANSI string inside the buffer (or null).
                let guid = if adapter.AdapterName.is_null() {
                    String::new()
                } else {
                    unsafe { adapter.AdapterName.to_string() }.unwrap_or_default()
                };
                // SAFETY: FriendlyName and Description are NUL-terminated strings inside the buffer.
                let name = if adapter.FriendlyName.is_null() {
                    String::new()
                } else {
                    unsafe { adapter.FriendlyName.to_string() }.unwrap_or_default()
                };
                let description = if adapter.Description.is_null() {
                    String::new()
                } else {
                    unsafe { adapter.Description.to_string() }.unwrap_or_default()
                };
                let mut dns = Vec::new();
                let mut server = adapter.FirstDnsServerAddress.cast_const();
                while !server.is_null() {
                    // SAFETY: a list inside `buffer`, linked by GetAdaptersAddresses.
                    let entry = unsafe { &*server };
                    server = entry.Next.cast_const();
                    if let Some(text) = address_text(&entry.Address) {
                        dns.push(text);
                    }
                }
                let mut gateways = Vec::new();
                let mut gateway = adapter.FirstGatewayAddress.cast_const();
                while !gateway.is_null() {
                    // SAFETY: as above.
                    let entry = unsafe { &*gateway };
                    gateway = entry.Next.cast_const();
                    if let Some(text) = address_text(&entry.Address) {
                        gateways.push(text);
                    }
                }
                // SAFETY: `Flags` is the whole 32-bit view of the flags union.
                let adapter_flags = unsafe { adapter.Anonymous2.Flags };
                list.push(Adapter {
                    guid,
                    name,
                    description,
                    if_type: adapter.IfType,
                    up: adapter.OperStatus == IfOperStatusUp,
                    dhcp: adapter_flags & IP_ADAPTER_DHCP_ENABLED != 0,
                    gateways,
                    dns,
                    ..Adapter::default()
                });
            }
            break;
        }
        if !read {
            return None;
        }
        let drivers = if full { adapter_drivers() } else { HashMap::new() };
        for adapter in &mut list {
            let v4 = values(HKEY_LOCAL_MACHINE, &format!(r"{TCPIP}\Interfaces\{}", adapter.guid)).unwrap_or_default();
            let v6 = values(HKEY_LOCAL_MACHINE, &format!(r"{TCPIP6}\Interfaces\{}", adapter.guid)).unwrap_or_default();
            adapter.static_dns = split_servers(&get(&v4, "NameServer"));
            adapter.static_dns.extend(split_servers(&get(&v6, "NameServer")));
            adapter.dhcp_dns = split_servers(&get(&v4, "DhcpNameServer"));
            adapter.dhcp_dns.extend(split_servers(&get(&v6, "Dhcpv6DNSServers")));
            if !full {
                continue;
            }
            adapter.settings_written_ms =
                written_ms(HKEY_LOCAL_MACHINE, &format!(r"{TCPIP}\Interfaces\{}", adapter.guid));
            if let Some((provider, component)) = drivers.get(&adapter.guid.to_ascii_lowercase()) {
                adapter.provider = provider.clone();
                adapter.component = component.clone();
            }
            adapter.netbios = values(HKEY_LOCAL_MACHINE, &format!(r"{NETBT}\Tcpip_{}", adapter.guid))
                .and_then(|v| number(&v, "NetbiosOptions"))
                .map(|n| n as u32);
        }
        Some(list)
    }

    /// A string WinHTTP allocated, as text, then freed.
    fn take(text: PWSTR) -> String {
        if text.is_null() {
            return String::new();
        }
        // SAFETY: WinHTTP returned a NUL-terminated string it allocated with GlobalAlloc; it is
        // read once and freed once.
        unsafe {
            let out = text.to_string().unwrap_or_default();
            let _ = GlobalFree(Some(HGLOBAL(text.0.cast())));
            out
        }
    }

    /// WinHTTP's proxy (`netsh winhttp show proxy`); `None` when it cannot be read.
    pub fn winhttp_proxy() -> Option<Proxy> {
        let mut info = WINHTTP_PROXY_INFO::default();
        // SAFETY: `info` receives two strings WinHTTP allocates; `take` frees them.
        unsafe { WinHttpGetDefaultProxyConfiguration(&mut info) }.ok()?;
        let named = info.dwAccessType == WINHTTP_ACCESS_TYPE_NAMED_PROXY;
        let server = take(info.lpszProxy);
        let bypass = take(info.lpszProxyBypass);
        Some(Proxy {
            kind: if named { "named" } else { "direct" }.to_string(),
            server: if named { server } else { String::new() },
            bypass: if named { bypass } else { String::new() },
        })
    }

    /// The current user's proxy settings; `None` when they cannot be read.
    pub fn user_proxy() -> Option<UserProxy> {
        let mut config = WINHTTP_CURRENT_USER_IE_PROXY_CONFIG::default();
        // SAFETY: `config` receives three strings WinHTTP allocates; `take` frees them.
        unsafe { WinHttpGetIEProxyConfigForCurrentUser(&mut config) }.ok()?;
        Some(UserProxy {
            auto_detect: config.fAutoDetect.as_bool(),
            pac_url: take(config.lpszAutoConfigUrl),
            server: take(config.lpszProxy),
            bypass: take(config.lpszProxyBypass),
        })
    }

    /// DNS over HTTPS templates: the system's (by server address) and each adapter's.
    fn doh() -> (Vec<DohServer>, Vec<DohAdapter>) {
        let base = format!(r"{DNSCACHE}\Parameters\DohWellKnownServers");
        let servers = subkeys(HKEY_LOCAL_MACHINE, &base)
            .into_iter()
            .filter_map(|server| {
                let v = values(HKEY_LOCAL_MACHINE, &format!(r"{base}\{server}"))?;
                Some(DohServer {
                    server,
                    template: get(&v, "Template"),
                })
            })
            .collect();
        let mut adapters = Vec::new();
        let root = format!(r"{DNSCACHE}\InterfaceSpecificParameters");
        for adapter in subkeys(HKEY_LOCAL_MACHINE, &root) {
            for family in ["Doh", "Doh6"] {
                let path = format!(r"{root}\{adapter}\DohInterfaceSettings\{family}");
                for server in subkeys(HKEY_LOCAL_MACHINE, &path) {
                    let v = values(HKEY_LOCAL_MACHINE, &format!(r"{path}\{server}")).unwrap_or_default();
                    adapters.push(DohAdapter {
                        adapter: adapter.clone(),
                        server,
                        template: get(&v, "DohTemplate"),
                        flags: number(&v, "DohFlags").unwrap_or(0),
                    });
                }
            }
        }
        (servers, adapters)
    }

    /// Name resolution policy rules, from group policy and the local configuration.
    fn nrpt() -> Vec<NrptRule> {
        let mut out = Vec::new();
        for (source, base) in [
            (
                "policy",
                r"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\DnsPolicyConfig".to_string(),
            ),
            ("local", format!(r"{DNSCACHE}\Parameters\DnsPolicyConfig")),
        ] {
            for rule in subkeys(HKEY_LOCAL_MACHINE, &base) {
                let Some(v) = values(HKEY_LOCAL_MACHINE, &format!(r"{base}\{rule}")) else {
                    continue;
                };
                out.push(NrptRule {
                    rule,
                    source: source.to_string(),
                    namespaces: get(&v, "Name")
                        .split("; ")
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .map(str::to_string)
                        .collect(),
                    servers: split_servers(&get(&v, "GenericDNSServers")),
                    doh_template: get(&v, "DohTemplate"),
                });
            }
        }
        out
    }

    /// DNS over HTTPS policies of the browsers.
    fn browser_doh() -> Vec<BrowserDoh> {
        let mut out = Vec::new();
        for (root, hive) in [(HKEY_LOCAL_MACHINE, "HKLM"), (HKEY_CURRENT_USER, "HKCU")] {
            for (browser, path) in [
                ("Chrome", r"SOFTWARE\Policies\Google\Chrome"),
                ("Edge", r"SOFTWARE\Policies\Microsoft\Edge"),
                ("Brave", r"SOFTWARE\Policies\BraveSoftware\Brave"),
            ] {
                let Some(v) = values(root, path) else {
                    continue;
                };
                let mode = get(&v, "DnsOverHttpsMode");
                let templates: Vec<String> = get(&v, "DnsOverHttpsTemplates")
                    .split_whitespace()
                    .map(str::to_string)
                    .collect();
                if !mode.is_empty() || !templates.is_empty() {
                    out.push(BrowserDoh {
                        browser: browser.to_string(),
                        hive: hive.to_string(),
                        mode,
                        templates,
                    });
                }
            }
            if let Some(v) = values(root, r"SOFTWARE\Policies\Mozilla\Firefox\DNSOverHTTPS") {
                let url = get(&v, "ProviderURL");
                let enabled = number(&v, "Enabled");
                if !url.is_empty() || enabled.is_some() {
                    out.push(BrowserDoh {
                        browser: "Firefox".to_string(),
                        hive: hive.to_string(),
                        mode: match enabled {
                            Some(0) => "off",
                            Some(_) => "on",
                            None => "",
                        }
                        .to_string(),
                        templates: if url.is_empty() { Vec::new() } else { vec![url] },
                    });
                }
            }
        }
        out
    }

    /// Persistent routes; `None` when the key cannot be read.
    fn routes() -> Option<Vec<Route>> {
        match Key::open(
            HKEY_LOCAL_MACHINE,
            &format!(r"{TCPIP}\PersistentRoutes"),
            KEY_WOW64_64KEY,
        ) {
            Ok(None) => Some(Vec::new()),
            Ok(Some(key)) => Some(
                key.raw_values()?
                    .into_iter()
                    .filter_map(|(name, _, _)| parse_route(&name))
                    .collect(),
            ),
            Err(()) => None,
        }
    }

    /// Lightweight filter drivers bound to the network adapters; `None` when unreadable.
    fn filters() -> Option<Vec<Filter>> {
        let Ok(Some(_)) = Key::open(HKEY_LOCAL_MACHINE, NETWORK_SERVICES, KEY_WOW64_64KEY) else {
            return None;
        };
        let windows_dir = crate::paths::windows_dir().display().to_string();
        let mut out = Vec::new();
        for sub in subkeys(HKEY_LOCAL_MACHINE, NETWORK_SERVICES) {
            let Some(v) = values(HKEY_LOCAL_MACHINE, &format!(r"{NETWORK_SERVICES}\{sub}")) else {
                continue;
            };
            if number(&v, "Characteristics").unwrap_or(0) & NCF_LW_FILTER == 0 {
                continue;
            }
            let inf = get(&v, "InfPath");
            let service = values(HKEY_LOCAL_MACHINE, &format!(r"{NETWORK_SERVICES}\{sub}\Ndi"))
                .map(|ndi| get(&ndi, "Service"))
                .unwrap_or_default();
            let file = if service.is_empty() {
                String::new()
            } else {
                values(
                    HKEY_LOCAL_MACHINE,
                    &format!(r"SYSTEM\CurrentControlSet\Services\{service}"),
                )
                .map(|s| super::driver_file(&get(&s, "ImagePath"), &windows_dir))
                .unwrap_or_default()
            };
            // INFs that ship with Windows are not named oemNN.inf.
            let third_party = inf.to_ascii_lowercase().starts_with("oem");
            let provider = if !third_party {
                "Microsoft".to_string()
            } else if file.is_empty() {
                String::new()
            } else {
                crate::startup::version_strings(&file).0
            };
            let description = get(&v, "Description");
            out.push(Filter {
                component: get(&v, "ComponentId"),
                provider,
                // Windows' own descriptions are resource references ("@netbrdg.dll,-2").
                description: if description.starts_with('@') {
                    service.clone()
                } else {
                    description
                },
                inf,
                service,
                file,
            });
        }
        Some(out)
    }

    /// Whether a network marked Public is connected (Network List Manager, on its own thread so the
    /// caller's COM state is not touched).
    fn public_network() -> Option<bool> {
        let (send, receive) = mpsc::channel();
        std::thread::spawn(move || {
            // SAFETY: this thread initializes COM for itself and uninitializes it before it ends.
            let result = unsafe {
                if CoInitializeEx(None, COINIT_MULTITHREADED).is_err() {
                    None
                } else {
                    let found = (|| -> Option<bool> {
                        let manager: INetworkListManager =
                            CoCreateInstance(&NetworkListManager, None, CLSCTX_ALL).ok()?;
                        let networks = manager.GetNetworks(NLM_ENUM_NETWORK_CONNECTED).ok()?;
                        let mut public = false;
                        for _ in 0..64 {
                            let mut one = [None];
                            let mut fetched = 0u32;
                            if networks.Next(&mut one, Some(&mut fetched)).is_err() || fetched == 0 {
                                break;
                            }
                            if let Some(network) = &one[0]
                                && network.GetCategory().ok() == Some(NLM_NETWORK_CATEGORY_PUBLIC)
                            {
                                public = true;
                            }
                        }
                        Some(public)
                    })();
                    CoUninitialize();
                    found
                }
            };
            let _ = send.send(result);
        });
        receive.recv_timeout(Duration::from_secs(3)).ok().flatten()
    }

    /// Everything the scan judges.
    pub fn read() -> NetConfig {
        let (doh_servers, doh_adapters) = doh();
        let llmnr_off = values(HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient")
            .and_then(|v| number(&v, "EnableMulticast"))
            == Some(0);
        NetConfig {
            adapters: adapters(),
            doh_servers,
            doh_adapters,
            nrpt: nrpt(),
            browser_doh: browser_doh(),
            winhttp: winhttp_proxy(),
            user_proxy: user_proxy(),
            routes: routes(),
            filters: filters(),
            llmnr_off,
            public_network: public_network(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn servers_and_routes_are_parsed() {
        assert_eq!(
            split_servers("203.0.113.5,198.51.100.7"),
            vec!["203.0.113.5", "198.51.100.7"]
        );
        assert_eq!(
            split_servers(" 203.0.113.5 198.51.100.7 "),
            vec!["203.0.113.5", "198.51.100.7"]
        );
        assert!(split_servers("").is_empty());
        let route = parse_route("0.0.0.0,0.0.0.0,203.0.113.1,1").expect("route");
        assert_eq!(route.destination, "0.0.0.0");
        assert_eq!(route.gateway, "203.0.113.1");
        assert_eq!(route.metric, "1");
        assert!(parse_route("garbage").is_none());
    }

    #[test]
    fn driver_paths_are_made_absolute() {
        let windows = r"C:\Windows";
        assert_eq!(
            driver_file(r"\SystemRoot\System32\drivers\a.sys", windows),
            r"C:\Windows\System32\drivers\a.sys"
        );
        assert_eq!(
            driver_file(r"System32\drivers\b.sys", windows),
            r"C:\Windows\System32\drivers\b.sys"
        );
        assert_eq!(
            driver_file(r"\??\C:\Program Files\Fabrikam\c.sys", windows),
            r"C:\Program Files\Fabrikam\c.sys"
        );
        assert_eq!(
            driver_file(r"%SystemRoot%\System32\drivers\d.sys", windows),
            r"C:\Windows\System32\drivers\d.sys"
        );
    }

    #[test]
    #[ignore = "reads this computer's network configuration; prints counts only"]
    fn live_counts() {
        let light = std::time::Instant::now();
        let _ = (adapters_light(), winhttp_proxy(), user_proxy());
        println!("watch read {:?}", light.elapsed());
        let started = std::time::Instant::now();
        let config = read();
        let adapters = config.adapters.clone().unwrap_or_default();
        println!(
            "adapters {} (up {}), with hand-set DNS {}, DoH servers {}, DoH per adapter {}, NRPT rules {}, browser DoH {}, \
             WinHTTP proxy {}, user proxy {}, PAC {}, auto-detect {}, routes {:?}, filters {:?} (third-party {:?}, vendor unknown {:?}), LLMNR off {}, public network {:?}, {:?}",
            adapters.len(),
            adapters.iter().filter(|a| a.up).count(),
            adapters.iter().filter(|a| !a.static_dns.is_empty()).count(),
            config.doh_servers.len(),
            config.doh_adapters.len(),
            config.nrpt.len(),
            config.browser_doh.len(),
            config.winhttp.as_ref().is_some_and(|p| p.kind == "named"),
            config.user_proxy.as_ref().is_some_and(|p| !p.server.is_empty()),
            config.user_proxy.as_ref().is_some_and(|p| !p.pac_url.is_empty()),
            config.user_proxy.as_ref().is_some_and(|p| p.auto_detect),
            config.routes.as_ref().map(Vec::len),
            config.filters.as_ref().map(Vec::len),
            config.filters.as_ref().map(|f| f
                .iter()
                .filter(|x| x.inf.to_ascii_lowercase().starts_with("oem"))
                .count()),
            config
                .filters
                .as_ref()
                .map(|f| f.iter().filter(|x| x.provider.is_empty()).count()),
            config.llmnr_off,
            config.public_network,
            started.elapsed(),
        );
    }
}
