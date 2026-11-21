//! IP address classification by the IANA special-purpose registries
//! (`is_global`, `is_loopback`, `is_unspecified`).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const V4_PRIVATE: &[(u32, u32)] = &[
    (0x0000_0000, 8),  // 0.0.0.0/8
    (0x0a00_0000, 8),  // 10.0.0.0/8
    (0x7f00_0000, 8),  // 127.0.0.0/8
    (0xa9fe_0000, 16), // 169.254.0.0/16
    (0xac10_0000, 12), // 172.16.0.0/12
    (0xc000_0000, 24), // 192.0.0.0/24
    (0xc000_00aa, 31), // 192.0.0.170/31
    (0xc000_0200, 24), // 192.0.2.0/24
    (0xc0a8_0000, 16), // 192.168.0.0/16
    (0xc612_0000, 15), // 198.18.0.0/15
    (0xc633_6400, 24), // 198.51.100.0/24
    (0xcb00_7100, 24), // 203.0.113.0/24
    (0xf000_0000, 4),  // 240.0.0.0/4
    (0xffff_ffff, 32), // 255.255.255.255/32
];
const V4_EXCEPTIONS: &[(u32, u32)] = &[(0xc000_0009, 32), (0xc000_000a, 32)];
const V4_SHARED: (u32, u32) = (0x6440_0000, 10); // 100.64.0.0/10

const V6_PRIVATE: &[(u128, u32)] = &[
    (1, 128),                                        // ::1/128
    (0, 128),                                        // ::/128
    (0x0000_0000_0000_0000_0000_ffff_0000_0000, 96), // ::ffff:0.0.0.0/96
    (0x0064_ff9b_0001_0000_0000_0000_0000_0000, 48), // 64:ff9b:1::/48
    (0x0100_0000_0000_0000_0000_0000_0000_0000, 64), // 100::/64
    (0x2001_0000_0000_0000_0000_0000_0000_0000, 23), // 2001::/23
    (0x2001_0db8_0000_0000_0000_0000_0000_0000, 32), // 2001:db8::/32
    (0x2002_0000_0000_0000_0000_0000_0000_0000, 16), // 2002::/16
    (0x3fff_0000_0000_0000_0000_0000_0000_0000, 20), // 3fff::/20
    (0xfc00_0000_0000_0000_0000_0000_0000_0000, 7),  // fc00::/7
    (0xfe80_0000_0000_0000_0000_0000_0000_0000, 10), // fe80::/10
];
const V6_EXCEPTIONS: &[(u128, u32)] = &[
    (0x2001_0001_0000_0000_0000_0000_0000_0001, 128),
    (0x2001_0001_0000_0000_0000_0000_0000_0002, 128),
    (0x2001_0003_0000_0000_0000_0000_0000_0000, 32),
    (0x2001_0004_0112_0000_0000_0000_0000_0000, 48),
    (0x2001_0020_0000_0000_0000_0000_0000_0000, 28),
    (0x2001_0030_0000_0000_0000_0000_0000_0000, 28),
];

fn in_v4(ip: u32, (net, prefix): (u32, u32)) -> bool {
    let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
    ip & mask == net
}

fn in_v6(ip: u128, (net, prefix): (u128, u32)) -> bool {
    let mask = if prefix == 0 { 0 } else { u128::MAX << (128 - prefix) };
    ip & mask == net
}

/// `ipaddress.ip_address(text.split("%")[0])`.
pub(crate) fn parse(text: &str) -> Option<IpAddr> {
    text.split('%').next().unwrap_or("").parse().ok()
}

fn v4_private(ip: Ipv4Addr) -> bool {
    let ip = u32::from(ip);
    V4_PRIVATE.iter().any(|&n| in_v4(ip, n)) && !V4_EXCEPTIONS.iter().any(|&n| in_v4(ip, n))
}

fn v4_global(ip: Ipv4Addr) -> bool {
    !in_v4(u32::from(ip), V4_SHARED) && !v4_private(ip)
}

fn v6_private(ip: Ipv6Addr) -> bool {
    if let Some(v4) = ip.to_ipv4_mapped() {
        return v4_private(v4);
    }
    let ip = u128::from(ip);
    V6_PRIVATE.iter().any(|&n| in_v6(ip, n)) && !V6_EXCEPTIONS.iter().any(|&n| in_v6(ip, n))
}

pub(crate) fn is_global(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4_global(v4),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => v4_global(v4),
            None => !v6_private(v6),
        },
    }
}

pub(crate) fn is_loopback(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => v4.is_loopback(),
            None => u128::from(v6) == 1,
        },
    }
}

pub(crate) fn is_unspecified(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_unspecified(),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => v4.is_unspecified(),
            None => u128::from(v6) == 0,
        },
    }
}

/// A public (globally reachable) address.
pub(crate) fn is_public(address: &str) -> bool {
    parse(address).is_some_and(is_global)
}

/// A loopback address.
pub(crate) fn is_loopback_text(address: &str) -> bool {
    parse(address).is_some_and(is_loopback)
}

/// "local" (loopback or unspecified), "public", "private" or "invalid".
pub(crate) fn address_class(value: &str) -> &'static str {
    match parse(value) {
        None => "invalid",
        Some(ip) if is_loopback(ip) || is_unspecified(ip) => "local",
        Some(ip) if is_global(ip) => "public",
        Some(_) => "private",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classes() {
        assert_eq!(address_class("8.8.8.8"), "public");
        assert_eq!(address_class("203.0.113.7"), "private");
        assert_eq!(address_class("100.64.1.1"), "private");
        assert_eq!(address_class("127.0.0.1"), "local");
        assert_eq!(address_class("0.0.0.0"), "local");
        assert_eq!(address_class("::1"), "local");
        assert_eq!(address_class("fe80::1%12"), "private");
        assert_eq!(address_class("2606:4700:4700::1111"), "public");
        assert_eq!(address_class("::ffff:8.8.8.8"), "public");
        assert_eq!(address_class("010.1.1.1"), "invalid");
        assert_eq!(address_class(""), "invalid");
    }
}
