// Fictitious firewall rules for previewing the Firewall rules page in a browser.
// Nothing here describes a real computer.
import type { FirewallFlag, FirewallRule, FirewallView } from "./types";

const ALL = ["domain", "private", "public"];
const SVCHOST = "C:\\Windows\\system32\\svchost.exe";

function rule(name: string, extra: Partial<FirewallRule>): FirewallRule {
  const base: FirewallRule = {
    key: "", name, description: "", group: "", builtin: false, appPackage: false, direction: "in", action: "allow",
    enabled: true, profiles: ALL, program: "", programExists: true, service: "", protocol: 6, protocolName: "TCP",
    localPorts: "", remotePorts: "", localAddresses: "*", remoteAddresses: "*", interfaceTypes: "All",
    edgeTraversal: false, vigil: false, duplicate: false, flags: [],
  };
  const merged = { ...base, ...extra };
  merged.key ||= [name, merged.direction, merged.program.toLowerCase(), merged.service, merged.protocol, merged.localPorts,
    merged.remotePorts].join("|");
  return merged;
}

const flag = (code: FirewallFlag["code"], port = 0): FirewallFlag => ({ code, port, warn: code !== "missing_program" });

export function firewallList(): FirewallView {
  const rules: FirewallRule[] = [
    rule("Remote Desktop - User Mode (TCP-In)", {
      group: "Remote Desktop", builtin: true, program: SVCHOST, service: "TermService", localPorts: "3389",
      description: "Inbound rule for the Remote Desktop service to allow RDP traffic.", flags: [flag("remote_access", 3389)],
    }),
    rule("Windows Remote Management (HTTP-In)", {
      group: "Windows Remote Management", builtin: true, enabled: false, program: "System", localPorts: "5985",
      profiles: ["domain", "private"], remoteAddresses: "LocalSubnet",
    }),
    rule("Core Networking - DNS (UDP-Out)", {
      group: "Core Networking", builtin: true, direction: "out", program: SVCHOST, service: "dnscache", protocol: 17,
      protocolName: "UDP", remotePorts: "53",
    }),
    rule("File and Printer Sharing (Echo Request - ICMPv4-In)", {
      group: "File and Printer Sharing", builtin: true, enabled: false, program: "System", protocol: 1, protocolName: "ICMPv4",
      profiles: ["private"], remoteAddresses: "LocalSubnet",
    }),
    rule("Contoso Game Server", {
      localPorts: "27015-27030", profiles: ["private", "public"], edgeTraversal: true,
      description: "Lets other players join games you host.", flags: [flag("open_public")],
    }),
    rule("OpenSSH Server (sshd)", {
      group: "OpenSSH Server", program: "C:\\Windows\\System32\\OpenSSH\\sshd.exe", localPorts: "22",
      remoteAddresses: "203.0.113.0/255.255.255.0", flags: [flag("remote_access", 22)],
    }),
    rule("QuickShare Helper", {
      program: "C:\\Users\\jdoe\\AppData\\Roaming\\QuickShare\\helper.exe", profiles: ["private", "public"],
      flags: [flag("writable_program")],
    }),
    rule("node.exe", {
      program: "C:\\Users\\jdoe\\AppData\\Local\\Temp\\build-5821\\node.exe", programExists: false, protocol: 17,
      protocolName: "UDP", profiles: ["private"], flags: [flag("missing_program")],
    }),
    rule("Vigil: block updater.exe", {
      direction: "out", action: "block", program: "C:\\Users\\jdoe\\AppData\\Roaming\\Updater\\updater.exe", protocol: 256,
      protocolName: "Any", description: "Created by Vigil", vigil: true,
    }),
    rule("Vigil: block updater.exe", {
      direction: "in", action: "block", program: "C:\\Users\\jdoe\\AppData\\Roaming\\Updater\\updater.exe", protocol: 256,
      protocolName: "Any", description: "Created by Vigil", vigil: true,
    }),
    rule("Microsoft Edge (mDNS-In)", {
      group: "Microsoft Edge", program: "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe", protocol: 17,
      protocolName: "UDP", localPorts: "5353",
    }),
    rule("Fabrikam VPN", {
      direction: "out", program: "C:\\Program Files\\Fabrikam VPN\\vpnclient.exe", protocol: 256, protocolName: "Any",
    }),
    rule("Contoso Media Server", {
      enabled: false, program: "C:\\Program Files\\Contoso\\Media\\mediaserver.exe", protocol: 17, protocolName: "UDP",
      localPorts: "1900", profiles: ["private"], remoteAddresses: "LocalSubnet",
    }),
    rule("Xbox Accessories", {
      group: "Xbox Accessories", appPackage: true, direction: "out", protocol: 256, protocolName: "Any",
    }),
    rule("Contoso Sync", { program: "C:\\Program Files\\Contoso Sync\\sync.exe", localPorts: "8080", duplicate: true }),
    rule("Contoso Sync", { program: "C:\\Program Files\\Contoso Sync\\sync.exe", localPorts: "8080", duplicate: true }),
  ];
  const warned = rules.filter((r) => r.flags.some((f) => f.warn)).length;
  return {
    profiles: [
      { name: "domain", enabled: true, active: false, defaultInbound: "block", defaultOutbound: "allow", blockAllInbound: false },
      { name: "private", enabled: true, active: true, defaultInbound: "block", defaultOutbound: "allow", blockAllInbound: false },
      { name: "public", enabled: false, active: false, defaultInbound: "block", defaultOutbound: "allow", blockAllInbound: false },
    ],
    rules,
    summary: {
      total: rules.length,
      enabled: rules.filter((r) => r.enabled).length,
      inbound: rules.filter((r) => r.direction === "in").length,
      outbound: rules.filter((r) => r.direction === "out").length,
      inboundAllow: rules.filter((r) => r.enabled && r.direction === "in" && r.action === "allow").length,
      flagged: warned,
      missing: rules.filter((r) => r.flags.some((f) => f.code === "missing_program")).length,
      vigil: rules.filter((r) => r.vigil).length,
    },
  };
}
