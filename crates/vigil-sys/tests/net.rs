//! Network endpoints: every endpoint has an owner name and well-formed addresses.

use std::collections::HashSet;

use vigil_sys::net::connections;
use vigil_sys::process::ProcessSampler;

#[test]
fn endpoints_are_named_and_well_formed() {
    let list = connections().expect("connections");
    assert!(!list.is_empty(), "Windows always has some listening endpoint");
    let alive: HashSet<u32> = ProcessSampler::new()
        .expect("sampler")
        .snapshot()
        .expect("snapshot")
        .into_iter()
        .map(|r| r.pid)
        .collect();
    for c in &list {
        assert!(
            ["TCP", "TCPv6", "UDP", "UDPv6"].contains(&c.protocol.as_str()),
            "{}",
            c.protocol
        );
        assert!(!c.process.is_empty());
        if c.process.starts_with("PID ") {
            assert!(!alive.contains(&c.pid), "pid {} is running but has no name", c.pid);
        }
        assert!(
            c.local
                .rsplit_once(':')
                .is_some_and(|(_, port)| port.parse::<u16>().is_ok()),
            "{}",
            c.local
        );
        if c.protocol.starts_with("UDP") || c.state == "LISTEN" {
            assert!(c.remote.is_empty() && !c.public);
        } else if !c.remote.is_empty() {
            assert!(!c.remote_ip.is_empty());
        }
    }
    assert!(list.iter().any(|c| c.state == "LISTEN"));
}
