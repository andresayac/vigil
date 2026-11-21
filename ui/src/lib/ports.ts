// Well-known ports, to name what a connection or a listening socket is for.
import { t, type Key } from "./i18n/index.svelte";
import type { Connection } from "./types";

const PORTS: Record<number, string> = {
  20: "FTP data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 67: "DHCP", 68: "DHCP", 69: "TFTP",
  80: "HTTP", 88: "Kerberos", 110: "POP3", 123: "NTP", 135: "RPC endpoint mapper", 137: "NetBIOS name",
  138: "NetBIOS datagram", 139: "NetBIOS session", 143: "IMAP", 161: "SNMP", 389: "LDAP", 443: "HTTPS", 445: "SMB",
  465: "SMTP (TLS)", 500: "IPsec IKE", 514: "Syslog", 587: "SMTP submission", 636: "LDAP (TLS)", 853: "DNS over TLS",
  993: "IMAP (TLS)", 995: "POP3 (TLS)", 1080: "SOCKS proxy", 1194: "OpenVPN", 1433: "SQL Server", 1434: "SQL Server browser",
  1701: "L2TP", 1723: "PPTP", 1900: "SSDP (UPnP)", 2179: "Hyper-V console", 3306: "MySQL", 3389: "@port.rdp",
  3478: "STUN", 3702: "WS-Discovery", 4500: "IPsec NAT-T", 5040: "@port.cdp", 5353: "mDNS", 5355: "LLMNR",
  5357: "WSD", 5432: "PostgreSQL", 5900: "VNC", 5938: "TeamViewer", 5985: "WinRM", 5986: "WinRM (TLS)",
  6379: "Redis", 6881: "BitTorrent", 7680: "@port.do", 8080: "@port.httpAlt", 8443: "@port.httpsAlt",
  9000: "@port.httpAlt", 9050: "Tor", 9150: "Tor Browser", 11211: "Memcached", 27017: "MongoDB", 51820: "WireGuard",
};

/** Ports that let someone control this computer remotely. */
const REMOTE_ACCESS = new Set([22, 23, 3389, 5900, 5938, 5985, 5986]);

/** "192.168.1.20:443", "[::]:445" -> 443, 445. */
export function portOf(address: string): number | null {
  const i = address.lastIndexOf(":");
  if (i < 0) return null;
  const port = Number(address.slice(i + 1));
  return Number.isInteger(port) && port > 0 ? port : null;
}

/** The service a connection talks to (outgoing) or offers (listening). */
export function serviceOf(c: Connection): string {
  const port = portOf(c.remote || c.local);
  const name = port !== null ? (PORTS[port] ?? "") : "";
  // Names of Windows features are translated; protocol names stay as they are.
  return name.startsWith("@") ? t(name.slice(1) as Key) : name;
}

/** A remote-access port listening on every network interface (reachable from the network). */
export function exposedRemoteAccess(c: Connection): boolean {
  if (c.remote) return false;
  const port = portOf(c.local);
  const anyInterface = c.local.startsWith("0.0.0.0:") || c.local.startsWith("[::]:");
  return port !== null && REMOTE_ACCESS.has(port) && anyInterface;
}
