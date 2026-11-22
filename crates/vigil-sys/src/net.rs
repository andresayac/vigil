//! Network endpoints (TCP and UDP, IPv4 and IPv6) with the process that owns each one.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use serde::Serialize;
use windows::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, NO_ERROR};
use windows::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCP6ROW_OWNER_PID, MIB_TCPROW_OWNER_PID, MIB_UDP6ROW_OWNER_PID,
    MIB_UDPROW_OWNER_PID, TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID,
};
use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6};

use crate::SysError;
use crate::nt::{self, SystemProcesses};
use crate::process::PathResolver;

/// One TCP connection or listening socket, or one UDP endpoint.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Connection {
    pub pid: u32,
    /// When the owning process started (Unix ms; 0 when unknown): with the PID it names exactly
    /// that process, so an action never reaches another process that reused the PID.
    pub created_ms: i64,
    pub process: String,
    pub exe: String,
    /// "TCP", "TCPv6", "UDP" or "UDPv6".
    pub protocol: String,
    /// "address:port"; IPv6 addresses are bracketed: "[::1]:80".
    pub local: String,
    /// "" for listening sockets and UDP endpoints.
    pub remote: String,
    pub remote_ip: String,
    /// "ESTABLISHED", "LISTEN", "TIME_WAIT"...; UDP endpoints are "LISTEN".
    pub state: String,
    /// The remote address is a public internet address.
    pub public: bool,
}

const TCP_STATES: [&str; 13] = [
    "",
    "CLOSED",
    "LISTEN",
    "SYN_SENT",
    "SYN_RECV",
    "ESTABLISHED",
    "FIN_WAIT1",
    "FIN_WAIT2",
    "CLOSE_WAIT",
    "CLOSING",
    "LAST_ACK",
    "TIME_WAIT",
    "DELETE_TCB",
];

/// Every endpoint, IPv4 and IPv6, TCP and UDP.
pub fn connections() -> Result<Vec<Connection>, SysError> {
    let mut endpoints = Vec::new();
    for row in table::<MIB_TCPROW_OWNER_PID>(Kind::Tcp, AF_INET.0 as u32)? {
        let local = IpAddr::V4(ipv4(row.dwLocalAddr));
        let remote = IpAddr::V4(ipv4(row.dwRemoteAddr));
        endpoints.push(Endpoint::tcp(
            row.dwOwningPid,
            row.dwState,
            local,
            port(row.dwLocalPort),
            remote,
            port(row.dwRemotePort),
        ));
    }
    for row in table::<MIB_TCP6ROW_OWNER_PID>(Kind::Tcp, AF_INET6.0 as u32)? {
        let local = IpAddr::V6(Ipv6Addr::from(row.ucLocalAddr));
        let remote = IpAddr::V6(Ipv6Addr::from(row.ucRemoteAddr));
        endpoints.push(Endpoint::tcp(
            row.dwOwningPid,
            row.dwState,
            local,
            port(row.dwLocalPort),
            remote,
            port(row.dwRemotePort),
        ));
    }
    for row in table::<MIB_UDPROW_OWNER_PID>(Kind::Udp, AF_INET.0 as u32)? {
        endpoints.push(Endpoint::udp(
            row.dwOwningPid,
            IpAddr::V4(ipv4(row.dwLocalAddr)),
            port(row.dwLocalPort),
        ));
    }
    for row in table::<MIB_UDP6ROW_OWNER_PID>(Kind::Udp, AF_INET6.0 as u32)? {
        endpoints.push(Endpoint::udp(
            row.dwOwningPid,
            IpAddr::V6(Ipv6Addr::from(row.ucLocalAddr)),
            port(row.dwLocalPort),
        ));
    }
    let names = process_names(&endpoints);
    Ok(endpoints.into_iter().map(|e| e.into_connection(&names)).collect())
}

/// The listening TCP sockets (IPv4 and IPv6) with the name of the process that owns each one,
/// read cheaply for the background watch: one kernel call for the names, no image paths.
pub fn listening_tcp() -> Result<Vec<Connection>, SysError> {
    let mut endpoints = Vec::new();
    for row in table::<MIB_TCPROW_OWNER_PID>(Kind::Tcp, AF_INET.0 as u32)? {
        endpoints.push(Endpoint::tcp(
            row.dwOwningPid,
            row.dwState,
            IpAddr::V4(ipv4(row.dwLocalAddr)),
            port(row.dwLocalPort),
            IpAddr::V4(ipv4(row.dwRemoteAddr)),
            port(row.dwRemotePort),
        ));
    }
    for row in table::<MIB_TCP6ROW_OWNER_PID>(Kind::Tcp, AF_INET6.0 as u32)? {
        endpoints.push(Endpoint::tcp(
            row.dwOwningPid,
            row.dwState,
            IpAddr::V6(Ipv6Addr::from(row.ucLocalAddr)),
            port(row.dwLocalPort),
            IpAddr::V6(Ipv6Addr::from(row.ucRemoteAddr)),
            port(row.dwRemotePort),
        ));
    }
    endpoints.retain(|e| e.state == "LISTEN");
    let owners: HashSet<u32> = endpoints.iter().map(|e| e.pid).collect();
    let names: HashMap<u32, (String, String, i64)> = SystemProcesses::new()
        .sample()
        .map(|list| {
            list.into_iter()
                .filter(|p| owners.contains(&p.pid))
                .map(|p| {
                    let created = crate::util::filetime_to_unix_ms(p.created_raw);
                    (p.pid, (p.name, String::new(), created))
                })
                .collect()
        })
        .unwrap_or_default();
    Ok(endpoints.into_iter().map(|e| e.into_connection(&names)).collect())
}

struct Endpoint {
    pid: u32,
    protocol: &'static str,
    state: String,
    local: (IpAddr, u16),
    remote: Option<(IpAddr, u16)>,
}

impl Endpoint {
    fn tcp(pid: u32, state: u32, local: IpAddr, local_port: u16, remote: IpAddr, remote_port: u16) -> Self {
        let state = TCP_STATES.get(state as usize).copied().unwrap_or("").to_string();
        let listening = state == "LISTEN" || (remote.is_unspecified() && remote_port == 0);
        Self {
            pid,
            protocol: if local.is_ipv6() { "TCPv6" } else { "TCP" },
            state,
            local: (local, local_port),
            remote: (!listening).then_some((remote, remote_port)),
        }
    }

    fn udp(pid: u32, local: IpAddr, local_port: u16) -> Self {
        Self {
            pid,
            protocol: if local.is_ipv6() { "UDPv6" } else { "UDP" },
            state: "LISTEN".to_string(),
            local: (local, local_port),
            remote: None,
        }
    }

    fn into_connection(self, names: &HashMap<u32, (String, String, i64)>) -> Connection {
        let (process, exe, created_ms) = match names.get(&self.pid) {
            Some((name, exe, created)) => (name.clone(), exe.clone(), *created),
            None => (fallback_name(self.pid), String::new(), 0),
        };
        let (remote, remote_ip, public) = match self.remote {
            Some((ip, port)) => (endpoint_text(ip, port), ip.to_string(), is_public(ip)),
            None => (String::new(), String::new(), false),
        };
        Connection {
            pid: self.pid,
            created_ms,
            process,
            exe,
            protocol: self.protocol.to_string(),
            local: endpoint_text(self.local.0, self.local.1),
            remote,
            remote_ip,
            state: self.state,
            public,
        }
    }
}

fn fallback_name(pid: u32) -> String {
    match pid {
        0 => "Idle".to_string(),
        4 => "System".to_string(),
        _ => format!("PID {pid}"),
    }
}

/// Name, image path and start time of the processes that own `endpoints`: one kernel call for the
/// names and start times, one path query per owning process.
fn process_names(endpoints: &[Endpoint]) -> HashMap<u32, (String, String, i64)> {
    let owners: HashSet<u32> = endpoints.iter().map(|e| e.pid).collect();
    let Ok(list) = SystemProcesses::new().sample() else {
        return HashMap::new();
    };
    let paths = PathResolver::new();
    list.into_iter()
        .filter(|p| owners.contains(&p.pid))
        .map(|p| {
            let path = paths.dos_path(p.pid);
            let created = crate::util::filetime_to_unix_ms(p.created_raw);
            (p.pid, (p.name, path, created))
        })
        .collect()
}

/// Ports are stored in network byte order in the low 16 bits.
fn port(raw: u32) -> u16 {
    u16::from_be((raw & 0xFFFF) as u16)
}

/// IPv4 addresses are stored in network byte order: their bytes in memory are a.b.c.d.
fn ipv4(raw: u32) -> Ipv4Addr {
    Ipv4Addr::from(raw.to_ne_bytes())
}

fn endpoint_text(ip: IpAddr, port: u16) -> String {
    match ip {
        IpAddr::V4(v4) => format!("{v4}:{port}"),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => format!("{v4}:{port}"),
            None => format!("[{v6}]:{port}"),
        },
    }
}

/// A public (globally routable) unicast address.
pub(crate) fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_public_v4(v4),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => is_public_v4(v4),
            None => is_public_v6(v6),
        },
    }
}

fn is_public_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    !(ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_documentation()
        || ip.is_unspecified()
        || ip.is_multicast()
        || a == 0
        || a >= 240
        || (a == 100 && (64..128).contains(&b)) // shared address space (carrier-grade NAT)
        || (a == 198 && (b == 18 || b == 19)) // benchmarking
        || (a == 192 && b == 0 && c == 0)) // IETF protocol assignments
}

fn is_public_v6(ip: Ipv6Addr) -> bool {
    let segments = ip.segments();
    // Global unicast is 2000::/3, minus documentation (2001:db8::/32) and IETF assignments (2001::/23).
    (segments[0] & 0xE000) == 0x2000
        && !(segments[0] == 0x2001 && segments[1] == 0x0DB8)
        && !(segments[0] == 0x2001 && segments[1] < 0x0200)
}

#[derive(Clone, Copy)]
enum Kind {
    Tcp,
    Udp,
}

/// Rows of one GetExtendedTcpTable / GetExtendedUdpTable table.
fn table<Row: Copy>(kind: Kind, family: u32) -> Result<Vec<Row>, SysError> {
    let mut size = 64 * 1024u32;
    for _ in 0..5 {
        let mut buffer = vec![0u64; (size as usize).div_ceil(8)];
        let mut length = (buffer.len() * 8) as u32;
        // SAFETY: the buffer is writable for `length` bytes and 8-byte aligned.
        let status = unsafe {
            match kind {
                Kind::Tcp => GetExtendedTcpTable(
                    Some(buffer.as_mut_ptr().cast()),
                    &mut length,
                    false,
                    family,
                    TCP_TABLE_OWNER_PID_ALL,
                    0,
                ),
                Kind::Udp => GetExtendedUdpTable(
                    Some(buffer.as_mut_ptr().cast()),
                    &mut length,
                    false,
                    family,
                    UDP_TABLE_OWNER_PID,
                    0,
                ),
            }
        };
        if status == ERROR_INSUFFICIENT_BUFFER.0 {
            size = length.max(size) + 16 * 1024;
            continue;
        }
        if status != NO_ERROR.0 {
            return Err(SysError::new("reading the connection table failed", status as i32));
        }
        return Ok(rows(nt::as_bytes(&buffer)));
    }
    Err(SysError::new(
        "the connection table kept growing while it was being read",
        0,
    ))
}

/// The table is a u32 row count followed by the rows (aligned to the row's alignment).
fn rows<Row: Copy>(bytes: &[u8]) -> Vec<Row> {
    let Some(count) = bytes
        .get(..4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize)
    else {
        return Vec::new();
    };
    let first = align_of::<Row>().max(4);
    let size = size_of::<Row>();
    (0..count)
        .map_while(|index| {
            let offset = first + index * size;
            if offset + size > bytes.len() {
                return None;
            }
            // SAFETY: the row lies inside `bytes`; the IP Helper rows are plain integer and byte
            // arrays for which any bit pattern is valid; read_unaligned handles alignment.
            Some(unsafe { std::ptr::read_unaligned(bytes.as_ptr().add(offset).cast::<Row>()) })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ports_and_addresses_are_decoded() {
        assert_eq!(port(u32::from(u16::to_be(443))), 443);
        assert_eq!(ipv4(u32::from_ne_bytes([127, 0, 0, 1])), Ipv4Addr::LOCALHOST);
        assert_eq!(endpoint_text(IpAddr::V6(Ipv6Addr::LOCALHOST), 80), "[::1]:80");
    }

    #[test]
    fn the_light_listing_has_only_listening_tcp_sockets() {
        let listening = listening_tcp().expect("tcp table");
        assert!(
            listening
                .iter()
                .all(|c| c.state == "LISTEN" && c.protocol.starts_with("TCP") && c.exe.is_empty())
        );
        let full: Vec<_> = connections()
            .expect("tables")
            .into_iter()
            .filter(|c| c.state == "LISTEN" && c.protocol.starts_with("TCP"))
            .collect();
        // Sockets come and go between the two reads; the counts stay close.
        assert!(
            full.len().abs_diff(listening.len()) <= 5,
            "{} vs {}",
            full.len(),
            listening.len()
        );
    }

    #[test]
    fn public_addresses() {
        for ip in ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"] {
            assert!(is_public(ip.parse().unwrap()), "{ip}");
        }
        for ip in [
            "10.0.0.1",
            "192.168.1.1",
            "172.16.0.1",
            "127.0.0.1",
            "100.64.0.1",
            "169.254.1.1",
            "203.0.113.7",
            "0.0.0.0",
            "::1",
            "fe80::1",
            "fd00::1",
            "2001:db8::1",
            "::ffff:10.0.0.1",
        ] {
            assert!(!is_public(ip.parse().unwrap()), "{ip}");
        }
    }
}
