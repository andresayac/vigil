// Fictitious accounts and sign-ins for previewing the Accounts page in a browser.
// Nothing here describes a real computer: names are jdoe and friends, addresses come from the
// documentation ranges (203.0.113.x, 198.51.100.x).
import type {
  AccountWarning, AccountsView, GroupMember, LocalAccount, RemoteSignin, SigninEvent, SigninSource, Signins, UserSession,
} from "./types";

const DAY = 86_400_000;
const MACHINE = "S-1-5-21-1111111111-2222222222-3333333333";
const PC = "PC-VICTIM";

function iso(ms: number): string {
  const d = new Date(ms);
  const p = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}T${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}

function at(daysAgo: number, hour: number, minute = 0): number {
  const now = new Date();
  const ms = new Date(now.getFullYear(), now.getMonth(), now.getDate() - daysAgo, hour, minute, 7).getTime();
  return Math.min(ms, now.getTime() - 60_000);
}

function account(name: string, rid: number, extra: Partial<LocalAccount>): LocalAccount {
  return {
    sid: `${MACHINE}-${rid}`, rid, name, fullName: "", comment: "", enabled: true, locked: false, passwordRequired: true,
    passwordExpires: false, passwordSet: iso(at(120, 9)), lastLogon: "", lastLogonMs: 0, logons: 0, badPasswords: 0,
    admin: false, remoteDesktop: false, builtin: "", onlineProvider: "", onlineName: "", current: false, ...extra,
  };
}

function member(sid: string, name: string, kind: GroupMember["kind"], extra: Partial<GroupMember> = {}): GroupMember {
  return { sid, name, kind, local: sid.startsWith(MACHINE), enabled: null, current: false, ...extra };
}

let record = 5000;
function event(ms: number, extra: Partial<SigninEvent>): SigninEvent {
  record += 1;
  return {
    id: `Security:${record}`, time: iso(ms), timeMs: ms, kind: "success", eventId: 4624, log: "Security", account: `${PC}\\jdoe`,
    sid: `${MACHINE}-1001`, logonType: 2, logon: "interactive", address: "", public: false, workstation: PC, process: "",
    reason: "", status: "", group: "", groupSid: "", member: "", memberSid: "", by: "", ...extra,
  };
}

function history(): SigninEvent[] {
  const out: SigninEvent[] = [];
  for (let d = 0; d < 30; d += 1) {
    out.push(event(at(d, 8, 5), { logonType: 2, logon: "interactive" }));
    if (d % 2 === 0) out.push(event(at(d, 13, 40), { logonType: 7, logon: "unlock" }));
    if (d % 7 === 3) out.push(event(at(d, 21), { account: `${PC}\\ana`, sid: `${MACHINE}-1002` }));
  }
  // A night of password guessing from one internet address.
  const names = ["administrator", "admin", "user", "test", "scanner", "backup", "support"];
  for (let i = 0; i < 46; i += 1) {
    out.push(event(at(4, 2, i), {
      kind: "failure", eventId: 4625, account: names[i % names.length], sid: "", logonType: 3, logon: "network",
      address: "198.51.100.23", public: true, workstation: "", reason: "no_such_user", status: "0xc0000064",
    }));
  }
  // Some wrong passwords typed at this computer.
  for (let i = 0; i < 3; i += 1) {
    out.push(event(at(9, 7, 55 + i), {
      kind: "failure", eventId: 4625, logonType: 2, logon: "interactive", reason: "bad_password", status: "0xc000006a",
    }));
  }
  // A Remote Desktop sign-in from the internet: authentication, then the sign-in.
  out.push(event(at(2, 22, 14), {
    kind: "remote_auth", eventId: 1149, log: "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational",
    id: "RCM:88", logon: "remote", logonType: 0, address: "203.0.113.77", public: true, workstation: "",
  }));
  out.push(event(at(2, 22, 15), { logonType: 10, logon: "remote", address: "203.0.113.77", public: true }));
  // A sign-in from another computer at home.
  out.push(event(at(6, 18, 2), { logonType: 3, logon: "network", address: "192.168.1.40", account: `${PC}\\ana` }));
  // A new account that became an administrator, and the log cleared afterwards.
  out.push(event(at(2, 22, 30), {
    kind: "created", eventId: 4720, account: `${PC}\\support`, sid: `${MACHINE}-1005`, logonType: 0, logon: "", by: `${PC}\\jdoe`,
  }));
  out.push(event(at(2, 22, 31), {
    kind: "member_added", eventId: 4732, account: "", sid: `${MACHINE}-1005`, logonType: 0, logon: "", group: "Builtin\\Administrators",
    groupSid: "S-1-5-32-544", member: "", memberSid: `${MACHINE}-1005`, by: `${PC}\\jdoe`,
  }));
  out.push(event(at(2, 22, 40), {
    kind: "log_cleared", eventId: 1102, account: `${PC}\\jdoe`, logonType: 0, logon: "", by: `${PC}\\jdoe`,
  }));
  return out.sort((a, b) => b.timeMs - a.timeMs);
}

function sources(events: SigninEvent[]): SigninSource[] {
  const map = new Map<string, SigninEvent[]>();
  for (const e of events.filter((x) => x.kind === "failure")) map.set(e.address, [...(map.get(e.address) ?? []), e]);
  return [...map.entries()].map(([address, list]) => {
    const names = [...new Set(list.map((e) => e.account.split("\\").pop()?.toLowerCase() ?? ""))];
    return {
      address, public: list[0].public, count: list.length, accounts: names.slice(0, 5), accountCount: names.length,
      first: list[list.length - 1].time, last: list[0].time,
    };
  }).sort((a, b) => b.count - a.count);
}

export function accounts(days: number): AccountsView {
  const now = Date.now();
  const all = history().filter((e) => e.timeMs >= now - days * DAY);
  const daily = Array.from({ length: days }, (_, i) => {
    const d = new Date(now - (days - 1 - i) * DAY);
    const date = iso(d.getTime()).slice(0, 10);
    const on = all.filter((e) => e.time.startsWith(date));
    return { date, success: on.filter((e) => e.kind === "success").length, failure: on.filter((e) => e.kind === "failure").length };
  });
  const remote: RemoteSignin[] = [];
  const rdp = all.filter((e) => e.address === "203.0.113.77");
  if (rdp.length) {
    remote.push({ time: rdp[0].time, timeMs: rdp[0].timeMs, account: `${PC}\\jdoe`, address: "203.0.113.77", public: true,
                  how: "remote_desktop", events: rdp.map((e) => e.id) });
  }
  const lan = all.find((e) => e.address === "192.168.1.40");
  if (lan) remote.push({ time: lan.time, timeMs: lan.timeMs, account: lan.account, address: lan.address, public: false, how: "network", events: [lan.id] });
  const src = sources(all);
  const signins: Signins = {
    days, readMs: now, events: all, daily,
    success: all.filter((e) => e.kind === "success").length, failure: all.filter((e) => e.kind === "failure").length,
    sources: src,
    failedAccounts: [
      { account: "administrator", count: 7, sources: 1, last: iso(at(4, 2, 42)) },
      { account: "admin", count: 7, sources: 1, last: iso(at(4, 2, 43)) },
      { account: `${PC}\\jdoe`, count: 3, sources: 1, last: iso(at(9, 7, 57)) },
    ],
    remote, securityReadable: true, unreadLogs: [], truncated: false,
  };
  const ids = (test: (e: SigninEvent) => boolean) => all.filter(test).map((e) => e.id);
  const warnings: AccountWarning[] = [
    { code: "internet_signin", severity: "bad", subject: "203.0.113.77", detail: `${PC}\\jdoe`, count: 1, events: ids((e) => e.address === "203.0.113.77") },
    { code: "guessing_address", severity: "bad", subject: "198.51.100.23", detail: "7", count: 46, events: ids((e) => e.address === "198.51.100.23") },
    { code: "log_cleared", severity: "bad", subject: `${PC}\\jdoe`, detail: "", count: 1, events: ids((e) => e.kind === "log_cleared") },
    { code: "no_password_required", severity: "bad", subject: "support", detail: "", count: 1, events: [] },
    { code: "guessing_names", severity: "warn", subject: "", detail: "8", count: 49, events: ids((e) => e.kind === "failure") },
    { code: "admin_added", severity: "warn", subject: `${MACHINE}-1005`, detail: `${PC}\\jdoe`, count: 1, events: ids((e) => e.kind === "member_added") },
    { code: "account_created", severity: "info", subject: `${PC}\\support`, detail: `${PC}\\jdoe`, count: 1, events: ids((e) => e.kind === "created") },
    { code: "unknown_admin", severity: "info", subject: `${MACHINE}-1009`, detail: "", count: 1, events: [] },
  ].filter((w) => w.events.length || !["internet_signin", "guessing_address", "log_cleared", "guessing_names", "admin_added", "account_created"].includes(w.code)) as AccountWarning[];

  const accountsList: LocalAccount[] = [
    account("Administrator", 500, { enabled: false, builtin: "administrator", admin: true, comment: "Built-in account for administering the computer/domain" }),
    account("DefaultAccount", 503, { enabled: false, builtin: "default", passwordRequired: false, comment: "A user account managed by the system." }),
    account("Guest", 501, { enabled: false, builtin: "guest", passwordRequired: false, comment: "Built-in account for guest access to the computer/domain" }),
    account("jdoe", 1001, {
      fullName: "Jane Doe", admin: true, current: true, lastLogon: iso(at(0, 8, 5)), lastLogonMs: at(0, 8, 5), logons: 1830,
      onlineProvider: "MicrosoftAccount", onlineName: "jdoe@example.com",
    }),
    account("ana", 1002, { fullName: "Ana", lastLogon: iso(at(3, 21)), lastLogonMs: at(3, 21), logons: 94, remoteDesktop: true }),
    account("support", 1005, { admin: true, passwordRequired: false, passwordExpires: false, lastLogon: "", comment: "" }),
    account("old-laptop", 1003, { enabled: false, lastLogon: iso(at(400, 10)), lastLogonMs: at(400, 10), logons: 12 }),
    account("WDAGUtilityAccount", 504, { enabled: false, builtin: "wdag", comment: "A user account managed and used by the system for Windows Defender Application Guard scenarios." }),
  ];
  const sessions: UserSession[] = [
    { id: 1, station: "Console", state: "active", user: `${PC}\\jdoe`, protocol: "console", clientAddress: "", clientName: "",
      logonTime: iso(at(0, 8, 5)), disconnectTime: "", current: true },
    { id: 3, station: "", state: "disconnected", user: `${PC}\\ana`, protocol: "console", clientAddress: "", clientName: "",
      logonTime: iso(at(1, 21, 2)), disconnectTime: iso(at(1, 23, 40)), current: false },
    { id: 4, station: "RDP-Tcp#7", state: "active", user: `${PC}\\support`, protocol: "rdp", clientAddress: "203.0.113.77",
      clientName: "DESKTOP-ABC123", logonTime: iso(at(0, 0, 15)), disconnectTime: "", current: false },
  ];
  return {
    machineSid: MACHINE, currentSids: [`${MACHINE}-1001`], accounts: accountsList,
    administrators: {
      sid: "S-1-5-32-544", name: "Administrators", error: "",
      members: [
        member(`${MACHINE}-500`, `${PC}\\Administrator`, "user", { enabled: false }),
        member(`${MACHINE}-1001`, `${PC}\\jdoe`, "user", { enabled: true, current: true }),
        member(`${MACHINE}-1005`, `${PC}\\support`, "user", { enabled: true }),
        member(`${MACHINE}-1009`, "", "deleted"),
      ],
    },
    remoteDesktopUsers: {
      sid: "S-1-5-32-555", name: "Remote Desktop Users", error: "",
      members: [member(`${MACHINE}-1002`, `${PC}\\ana`, "user", { enabled: true })],
    },
    sessions, domainJoined: false, lusrmgr: true, errors: [],
    signins, signinsError: "", warnings,
    disabledByVigil: [{ recordId: "mock-record-old-laptop", time: iso(at(20, 10)), sid: `${MACHINE}-1003`, name: "old-laptop", groupSid: "", groupName: "" }],
    removedByVigil: [],
  };
}
