<script lang="ts">
  import { onMount } from "svelte";
  import * as api from "../lib/api";
  import { niceCeiling, when } from "../lib/format";
  import { locale, t, type Key } from "../lib/i18n/index.svelte";
  import { act } from "../lib/report.svelte";
  import type {
    AccountGroupKey, AccountWarning, AccountsView, GroupMember, LocalAccount, LocalGroup, SigninEvent, UserSession,
  } from "../lib/types";

  // Local accounts, who is an administrator, who is signed in now and the sign-ins Windows recorded. Every name and
  // address comes from the system and is shown as plain text. Changes are requests: Rust reads the accounts again,
  // applies the action engine's guards and asks for confirmation.
  let { elevated }: { elevated: boolean } = $props();

  const PERIODS = [7, 30];
  const ROWS = 12;
  const ADMINS = "S-1-5-32-544";

  let data = $state<AccountsView | null>(null);
  let days = $state(30);
  let loading = $state(false);
  let error = $state("");
  let showDisabled = $state(false);
  let selected = $state<{ type: "account" | "member" | "session" | "event"; id: string } | null>(null);
  let only = $state<{ ids: string[]; title: string } | null>(null);
  let allEvents = $state(false);
  let hover = $state<number | null>(null);

  async function load(): Promise<void> {
    loading = true;
    try {
      data = await api.accounts(days);
      error = "";
    } catch (e) {
      error = String(e);
    } finally {
      loading = false;
    }
  }
  onMount(() => void load());

  function setDays(value: number): void {
    if (value === days) return;
    days = value;
    only = null;
    void load();
  }

  async function run(request: Parameters<typeof act>[0]): Promise<void> {
    const outcome = await act(request);
    if (outcome && !outcome.cancelled) await load();
  }

  // ------------------------------------------------------------------ words
  const number = (n: number) => new Intl.NumberFormat(locale()).format(n);
  const dayLabel = (key: string, style: "short" | "long") =>
    new Intl.DateTimeFormat(locale(), style === "short" ? { day: "numeric", month: "short" } : { dateStyle: "full" })
      .format(new Date(`${key}T12:00:00`));
  const bare = (account: string) => account.split("\\").pop() ?? account;

  const accounts = $derived(data?.accounts ?? []);
  const signins = $derived(data?.signins ?? null);
  const events = $derived(signins?.events ?? []);
  const sidName = (sid: string): string => {
    const found = accounts.find((a) => a.sid.toLowerCase() === sid.toLowerCase());
    if (found) return found.name;
    const member = [...(data?.administrators.members ?? []), ...(data?.remoteDesktopUsers.members ?? [])].find((m) => m.sid === sid);
    return member?.name || sid;
  };

  function warningText(w: AccountWarning): { title: string; text: string } {
    const p = { count: w.count, address: w.subject, names: w.detail, account: w.subject, by: w.detail, sid: w.subject };
    switch (w.code) {
      case "guessing_address":
        return w.subject
          ? { title: t("accounts.warn.guessing.title"), text: t("accounts.warn.guessing.text", p) }
          : { title: t("accounts.warn.guessingLocal.title"), text: t("accounts.warn.guessingLocal.text", p) };
      case "guessing_names":
        return { title: t("accounts.warn.names.title"), text: t("accounts.warn.names.text", p) };
      case "internet_signin":
        return { title: t("accounts.warn.internet.title"), text: t("accounts.warn.internet.text", { ...p, account: w.detail }) };
      case "log_cleared":
        return { title: t("accounts.warn.cleared.title"), text: t("accounts.warn.cleared.text", p) };
      case "admin_added":
        return { title: t("accounts.warn.newAdmin.title"), text: t("accounts.warn.newAdmin.text", { ...p, member: sidName(w.subject) }) };
      case "account_created":
        return { title: t("accounts.warn.created.title"), text: t("accounts.warn.created.text", p) };
      case "lockouts":
        return { title: t("accounts.warn.lockouts.title"), text: t("accounts.warn.lockouts.text", p) };
      case "no_password_required":
        return { title: t("accounts.warn.noPassword.title"), text: t("accounts.warn.noPassword.text", p) };
      case "guest_enabled":
        return { title: t("accounts.warn.guest.title"), text: t("accounts.warn.guest.text", p) };
      case "builtin_admin_enabled":
        return { title: t("accounts.warn.builtinAdmin.title"), text: t("accounts.warn.builtinAdmin.text", p) };
      case "unknown_admin":
        return { title: t("accounts.warn.unknownAdmin.title"), text: t("accounts.warn.unknownAdmin.text", p) };
    }
  }
  const SEVERITY_ICON: Record<string, string> = { bad: "\uEA39", warn: "\uE7BA", info: "\uE946" };

  const EVENT: Record<SigninEvent["kind"], Key> = {
    success: "accounts.ev.success", failure: "accounts.ev.failure", lockout: "accounts.ev.lockout", created: "accounts.ev.created",
    deleted: "accounts.ev.deleted", member_added: "accounts.ev.memberAdded", member_removed: "accounts.ev.memberRemoved",
    log_cleared: "accounts.ev.logCleared", remote_auth: "accounts.ev.remoteAuth", remote_logon: "accounts.ev.remoteLogon",
    remote_reconnect: "accounts.ev.remoteReconnect", session_logon: "accounts.ev.sessionLogon",
  };
  const LOGON: Record<string, Key> = {
    interactive: "accounts.logon.interactive", network: "accounts.logon.network", unlock: "accounts.logon.unlock",
    remote: "accounts.logon.remote", cached: "accounts.logon.cached", batch: "accounts.logon.other", service: "accounts.logon.other",
    other: "accounts.logon.other",
  };
  const REASON: Record<string, Key> = {
    bad_password: "accounts.reason.badPassword", no_such_user: "accounts.reason.noSuchUser", locked: "accounts.reason.locked",
    disabled: "accounts.reason.disabled", expired: "accounts.reason.expired", password_expired: "accounts.reason.passwordExpired",
    must_change: "accounts.reason.mustChange", not_allowed: "accounts.reason.notAllowed", clock: "accounts.reason.clock",
    other: "accounts.reason.other",
  };
  const MEMBER_KIND: Record<GroupMember["kind"], Key> = {
    user: "accounts.kind.user", group: "accounts.kind.group", alias: "accounts.kind.alias", well_known: "accounts.kind.wellKnown",
    deleted: "accounts.kind.deleted", unknown: "accounts.kind.unknown", other: "accounts.kind.other",
  };
  const STATE: Record<UserSession["state"], Key> = {
    active: "accounts.state.active", connected: "accounts.state.connected", disconnected: "accounts.state.disconnected",
    idle: "accounts.state.idle", other: "accounts.state.other",
  };
  const eventTone = (e: SigninEvent) =>
    e.kind === "log_cleared" || (e.public && e.kind !== "failure") ? "bad" : ["failure", "lockout", "member_added", "created"].includes(e.kind) ? "warn" : "";
  function eventLine(e: SigninEvent): string {
    const who = e.kind === "member_added" || e.kind === "member_removed" ? (e.member || sidName(e.memberSid)) : e.account;
    return who ? `${t(EVENT[e.kind])}: ${who}` : t(EVENT[e.kind]);
  }
  const from = (address: string) => (address ? address : t("accounts.thisComputer"));

  // ------------------------------------------------------------------ accounts and groups
  const disabledByVigil = $derived(new Map((data?.disabledByVigil ?? []).map((c) => [c.sid, c])));
  const enabledAdmins = $derived(accounts.filter((a) => a.admin && a.enabled));
  const order = (a: LocalAccount) => (a.current ? 0 : a.admin ? 1 : 2);
  const shownAccounts = $derived(accounts.filter((a) => a.enabled).sort((a, b) => order(a) - order(b) || a.name.localeCompare(b.name)));
  const hiddenAccounts = $derived(accounts.filter((a) => !a.enabled).sort((a, b) => a.name.localeCompare(b.name)));

  const canDisable = (a: LocalAccount) =>
    a.enabled && !a.current && !["default", "wdag"].includes(a.builtin) && !(a.admin && enabledAdmins.length <= 1);
  const personSid = (sid: string) => sid.startsWith("S-1-5-21-") || sid.startsWith("S-1-12-1-");
  function canRemove(group: LocalGroup, m: GroupMember): boolean {
    if (!personSid(m.sid) || m.current) return false;
    if (["group", "alias", "well_known"].includes(m.kind)) return false;
    if (["deleted", "unknown", "other"].includes(m.kind) && !m.local) return false;
    if (group.sid === ADMINS) {
      if (m.local && m.sid.endsWith("-500")) return false;
      if (m.enabled === true && enabledAdmins.length <= 1) return false;
    }
    return true;
  }
  const memberName = (m: GroupMember) => m.name || (m.kind === "deleted" ? t("accounts.memberDeleted") : t("accounts.memberUnknown"));
  const groups = $derived<{ key: AccountGroupKey; title: Key; note: Key; group: LocalGroup }[]>(data ? [
    { key: "administrators", title: "accounts.adminsTitle", note: "accounts.adminsNote", group: data.administrators },
    { key: "remote_desktop_users", title: "accounts.rdpTitle", note: "accounts.rdpNote", group: data.remoteDesktopUsers },
  ] : []);
  const removedIn = (sid: string) => (data?.removedByVigil ?? []).filter((c) => c.groupSid === sid);

  // ------------------------------------------------------------------ sessions
  const currentUser = $derived(data?.sessions.find((s) => s.current)?.user ?? "");
  const canSignOut = (s: UserSession) =>
    !s.current && !!s.user && s.user.toLowerCase() !== currentUser.toLowerCase() && (s.state === "disconnected" || s.protocol === "rdp");
  function how(s: UserSession): string {
    if (s.protocol === "rdp") return s.clientAddress ? t("accounts.how.rdpFrom", { address: s.clientAddress }) : t("accounts.how.rdp");
    return t("accounts.how.console");
  }

  // ------------------------------------------------------------------ activity
  const daily = $derived(signins?.daily ?? []);
  const evenCeiling = (value: number) => {
    const ceiling = niceCeiling(value);
    return ceiling % 2 ? Math.max(2, ceiling + 1) : ceiling;
  };
  const top = $derived(evenCeiling(Math.max(1, ...daily.map((d) => d.success + d.failure))));
  const labelEvery = $derived(Math.max(1, Math.ceil(daily.length / 6)));
  const hovered = $derived(hover !== null ? daily[hover] : null);
  const listed = $derived(only ? events.filter((e) => only?.ids.includes(e.id)) : events);
  const visibleEvents = $derived(allEvents ? listed : listed.slice(0, ROWS));
  function showWarning(w: AccountWarning): void {
    only = { ids: w.events, title: warningText(w).title };
    allEvents = false;
    selected = w.events[0] ? { type: "event", id: w.events[0] } : null;
  }

  // ------------------------------------------------------------------ details
  type Field = { label: string; value: string; mono?: boolean };
  const current = $derived.by((): { title: string; icon: string; fields: Field[] } | null => {
    if (!selected || !data) return null;
    const s = selected;
    if (s.type === "account") {
      const a = accounts.find((x) => x.sid === s.id);
      if (!a) return null;
      const f: Field[] = [];
      if (a.fullName) f.push({ label: t("accounts.field.fullName"), value: a.fullName });
      if (a.comment) f.push({ label: t("accounts.field.comment"), value: a.comment });
      f.push({ label: t("accounts.field.lastLogon"), value: a.lastLogon ? when(a.lastLogon) : t("accounts.neverSignedIn") });
      if (a.logons) f.push({ label: t("accounts.field.logons"), value: number(a.logons) });
      if (a.passwordSet) f.push({ label: t("accounts.field.passwordSet"), value: when(a.passwordSet) });
      if (a.badPasswords) f.push({ label: t("accounts.field.badPasswords"), value: number(a.badPasswords) });
      if (a.onlineName) f.push({ label: t("accounts.field.online"), value: a.onlineName });
      f.push({ label: t("accounts.field.sid"), value: a.sid, mono: true });
      return { title: a.name, icon: "\uE77B", fields: f };
    }
    if (s.type === "member") {
      const m = [...data.administrators.members, ...data.remoteDesktopUsers.members].find((x) => `${x.sid}` === s.id);
      if (!m) return null;
      const f: Field[] = [{ label: t("accounts.field.kind"), value: t(MEMBER_KIND[m.kind]) }];
      if (m.enabled !== null) f.push({ label: t("accounts.field.state"), value: t(m.enabled ? "common.enabled" : "common.disabled") });
      f.push({ label: t("accounts.field.sid"), value: m.sid, mono: true });
      return { title: memberName(m), icon: "\uE716", fields: f };
    }
    if (s.type === "session") {
      const x = data.sessions.find((y) => String(y.id) === s.id);
      if (!x) return null;
      const f: Field[] = [
        { label: t("accounts.field.state"), value: t(STATE[x.state]) },
        { label: t("accounts.field.how"), value: how(x) },
      ];
      if (x.clientName) f.push({ label: t("accounts.field.client"), value: x.clientName });
      if (x.logonTime) f.push({ label: t("accounts.field.logonTime"), value: when(x.logonTime) });
      if (x.disconnectTime) f.push({ label: t("accounts.field.disconnectTime"), value: when(x.disconnectTime) });
      f.push({ label: t("accounts.field.session"), value: `${x.id}${x.station ? ` (${x.station})` : ""}` });
      return { title: x.user, icon: "\uE7F4", fields: f };
    }
    const e = events.find((y) => y.id === s.id);
    if (!e) return null;
    const f: Field[] = [{ label: t("accounts.field.time"), value: when(e.time, true) }];
    if (e.account) f.push({ label: t("accounts.field.account"), value: e.account });
    if (e.logon) f.push({ label: t("accounts.field.how"), value: t(LOGON[e.logon] ?? "accounts.logon.other") });
    if (e.address || ["success", "failure"].includes(e.kind)) f.push({ label: t("accounts.field.address"), value: from(e.address) + (e.public ? ` (${t("accounts.internet")})` : "") });
    if (e.workstation) f.push({ label: t("accounts.field.workstation"), value: e.workstation });
    if (e.reason) f.push({ label: t("accounts.field.reason"), value: t(REASON[e.reason] ?? "accounts.reason.other") });
    if (e.status) f.push({ label: t("accounts.field.status"), value: e.status, mono: true });
    if (e.group) f.push({ label: t("accounts.field.group"), value: e.group });
    if (e.memberSid) f.push({ label: t("accounts.field.member"), value: e.member || sidName(e.memberSid) });
    if (e.by) f.push({ label: t("accounts.field.by"), value: e.by });
    if (e.process) f.push({ label: t("accounts.field.process"), value: e.process, mono: true });
    f.push({ label: t("accounts.field.event"), value: `${e.eventId} · ${e.log}` });
    return { title: eventLine(e), icon: "\uE823", fields: f };
  });
</script>

<div class="page scroll">
  <div class="page-head">
    <h1>{t("accounts.title")}</h1>
    <div class="segmented" role="radiogroup" aria-label={t("accounts.period")}>
      {#each PERIODS as p (p)}
        <button role="radio" aria-checked={days === p} class:on={days === p} onclick={() => setDays(p)}>{t("common.days", { count: p })}</button>
      {/each}
    </div>
    <span class="grow"></span>
    <span class="faint">{loading ? t("common.reading") : ""}</span>
    <div class="commandbar">
      <button class="command" onclick={() => act({ kind: "shell", op: "url", url: "ms-settings:otherusers" })}><i class="icon">{"\uE713"}</i>{t("accounts.otherUsers")}</button>
      {#if data?.lusrmgr}
        <button class="command" onclick={() => act({ kind: "shell", op: "console", name: "lusrmgr.msc" })}><i class="icon">{"\uE716"}</i>{t("accounts.lusrmgr")}</button>
      {/if}
      <span class="sep"></span>
      <button class="command" disabled={loading} onclick={load}><i class="icon">{"\uE72C"}</i>{t("common.refresh")}</button>
    </div>
  </div>
  <p class="faint lead">{t("accounts.note")}</p>

  {#if error}<p class="warn-text selectable">{error}</p>{/if}

  {#if data}
    {#if data.warnings.length}
      <section class="panel look">
        <h2>{t("accounts.lookTitle")}</h2>
        {#each data.warnings as w, index (index)}
          {@const words = warningText(w)}
          <div class="hint">
            <i class="icon sev {w.severity}">{SEVERITY_ICON[w.severity]}</i>
            <div class="hint-body">
              <b>{words.title}</b>
              <span class="selectable">{words.text}</span>
            </div>
            {#if w.events.length}<button class="link" onclick={() => showWarning(w)}>{t("accounts.showEvents")}</button>{/if}
          </div>
        {/each}
      </section>
    {:else}
      <section class="panel calm"><i class="icon ok">{"\uE73E"}</i><span>{t("accounts.allClear", { days })}</span></section>
    {/if}

    <div class="columns">
      <div class="main">
        <!-- Accounts -->
        <section class="panel section">
          <div class="section-head">
            <h2>{t("accounts.accountsTitle")}</h2>
            <span class="faint num">{accounts.length}</span>
            {#if data.domainJoined}<span class="faint">{t("accounts.domainNote")}</span>{/if}
          </div>
          {#each [...shownAccounts, ...(showDisabled ? hiddenAccounts : [])] as a (a.sid)}
            {@const vigil = disabledByVigil.get(a.sid)}
            <div class="row account" class:sel={selected?.type === "account" && selected.id === a.sid} class:off={!a.enabled}>
              <button class="row-main" onclick={() => (selected = { type: "account", id: a.sid })}>
                <i class="icon glyph">{a.admin ? "\uE7EF" : "\uE77B"}</i>
                <span class="who">
                  <span class="name">{a.name}</span>
                  {#if a.fullName}<span class="faint small">{a.fullName}</span>{/if}
                </span>
                <span class="badges">
                  {#if a.current}<span class="badge accent">{t("accounts.you")}</span>{/if}
                  {#if a.admin}<span class="badge">{t("accounts.badgeAdmin")}</span>{/if}
                  {#if a.remoteDesktop}<span class="badge">{t("accounts.badgeRemote")}</span>{/if}
                  {#if !a.enabled}<span class="badge">{t("accounts.badgeDisabled")}</span>{/if}
                  {#if a.enabled && !a.passwordRequired}<span class="badge bad">{t("accounts.badgeNoPassword")}</span>{/if}
                  {#if a.locked}<span class="badge warn">{t("accounts.badgeLocked")}</span>{/if}
                  {#if a.onlineProvider}<span class="badge">{t("accounts.badgeMicrosoft")}</span>{/if}
                  {#if a.builtin}<span class="badge">{t("accounts.badgeBuiltin")}</span>{/if}
                  {#if a.enabled && !a.passwordExpires && !a.onlineProvider}<span class="badge faint-badge">{t("accounts.badgeNeverExpires")}</span>{/if}
                </span>
                <span class="faint when">{a.lastLogon ? t("accounts.lastLogon", { when: when(a.lastLogon) }) : t("accounts.neverSignedIn")}</span>
              </button>
              <span class="row-actions">
                {#if vigil}
                  <button title={t("accounts.disabledByVigil", { when: when(vigil.time) })} disabled={!elevated}
                          onclick={() => run({ kind: "journal", op: "undo", id: vigil.recordId })}>{t("accounts.enableAgain")}</button>
                {:else if canDisable(a)}
                  <button disabled={!elevated} title={elevated ? "" : t("accounts.adminNote")}
                          onclick={() => run({ kind: "account", op: "disable", sid: a.sid })}><i class="icon">{"\uE8F8"}</i>{t("accounts.disable")}</button>
                {/if}
              </span>
            </div>
          {/each}
          {#if hiddenAccounts.length}
            <button class="link more" onclick={() => (showDisabled = !showDisabled)}>
              {showDisabled ? t("accounts.hideDisabled") : t("accounts.showDisabled", { count: hiddenAccounts.length })}</button>
          {/if}
        </section>

        <!-- Administrators and Remote Desktop Users -->
        {#each groups as g (g.key)}
          <section class="panel section">
            <div class="section-head">
              <h2>{t(g.title)}</h2>
              <span class="faint num">{g.group.members.length}</span>
            </div>
            <p class="faint note">{t(g.note)}</p>
            {#if g.group.error}<p class="warn-text selectable">{g.group.error}</p>{/if}
            {#each g.group.members as m (m.sid)}
              <div class="row member" class:sel={selected?.type === "member" && selected.id === m.sid}>
                <button class="row-main" onclick={() => (selected = { type: "member", id: m.sid })}>
                  <i class="icon glyph">{m.kind === "group" || m.kind === "alias" || m.kind === "well_known" ? "\uE716" : "\uE77B"}</i>
                  <span class="name" class:faint={!m.name}>{memberName(m)}</span>
                  <span class="badges">
                    {#if m.current}<span class="badge accent">{t("accounts.you")}</span>{/if}
                    <span class="badge faint-badge">{t(MEMBER_KIND[m.kind])}</span>
                    {#if m.enabled === false}<span class="badge">{t("accounts.badgeDisabled")}</span>{/if}
                  </span>
                </button>
                <span class="row-actions">
                  {#if canRemove(g.group, m)}
                    <button disabled={!elevated} title={elevated ? "" : t("accounts.adminNote")}
                            onclick={() => run({ kind: "account", op: "remove_member", sid: m.sid, group: g.key })}>{t("accounts.remove")}</button>
                  {/if}
                </span>
              </div>
            {:else}
              <p class="faint empty-line">{t("accounts.groupEmpty")}</p>
            {/each}
            {#each removedIn(g.group.sid) as c (c.recordId)}
              <div class="row member removed">
                <span class="row-main static">
                  <i class="icon glyph">{"\uE77B"}</i>
                  <span class="name faint">{c.name || c.sid}</span>
                  <span class="faint small">{t("accounts.removedByVigil", { when: when(c.time) })}</span>
                </span>
                <span class="row-actions">
                  <button disabled={!elevated} onclick={() => run({ kind: "journal", op: "undo", id: c.recordId })}><i class="icon">{"\uE8FA"}</i>{t("accounts.addBack")}</button>
                </span>
              </div>
            {/each}
          </section>
        {/each}

        <!-- Sessions -->
        <section class="panel section">
          <div class="section-head">
            <h2>{t("accounts.sessionsTitle")}</h2>
            <span class="faint num">{data.sessions.length}</span>
          </div>
          {#each data.sessions as s (s.id)}
            <div class="row session" class:sel={selected?.type === "session" && selected.id === String(s.id)}>
              <button class="row-main" onclick={() => (selected = { type: "session", id: String(s.id) })}>
                <i class="icon glyph">{"\uE7F4"}</i>
                <span class="name">{s.user}</span>
                <span class="badges">
                  {#if s.current}<span class="badge accent">{t("accounts.thisSession")}</span>{/if}
                  <span class="badge" class:warn={s.protocol === "rdp"}>{how(s)}</span>
                  <span class="badge faint-badge">{t(STATE[s.state])}</span>
                </span>
                <span class="faint when">{s.logonTime ? t("accounts.since", { when: when(s.logonTime) }) : ""}</span>
              </button>
              <span class="row-actions">
                {#if canSignOut(s)}
                  <button disabled={!elevated} title={elevated ? "" : t("accounts.adminNote")}
                          onclick={() => run({ kind: "account", op: "logoff", session: s.id })}><i class="icon">{"\uE7E8"}</i>{t("accounts.signOut")}</button>
                {/if}
              </span>
            </div>
          {:else}
            <p class="faint empty-line">{t("accounts.noSessions")}</p>
          {/each}
        </section>

        <!-- Sign-in activity -->
        <section class="panel section activity">
          <div class="section-head">
            <h2>{t("accounts.activityTitle")}</h2>
            {#if signins}
              <span class="faint">{t("accounts.signinsCount", { count: signins.success })} · {t("accounts.failedCount", { count: signins.failure })}</span>
              <span class="grow"></span>
              <span class="legend faint">
                <span><i class="swatch ok-sw"></i>{t("accounts.successful")}</span>
                <span><i class="swatch warn"></i>{t("accounts.failed")}</span>
              </span>
            {/if}
          </div>
          {#if data.signinsError}<p class="warn-text selectable">{data.signinsError}</p>{/if}
          {#if signins && !signins.securityReadable}<p class="faint note">{t("accounts.securityHidden")}</p>{/if}
          {#if signins}
            <div class="chart" role="group" aria-label={t("accounts.activityTitle")}>
              <div class="axis-y faint num"><span>{number(top)}</span><span>{number(top / 2)}</span><span>0</span></div>
              <div class="plot" onmouseleave={() => (hover = null)} role="presentation">
                <div class="grid-line" style:top="0"></div>
                <div class="grid-line" style:top="50%"></div>
                <div class="bars">
                  {#each daily as d, i (d.date)}
                    <span class="col" role="img" onmouseenter={() => (hover = i)}
                          aria-label={`${dayLabel(d.date, "long")}: ${t("accounts.signinsCount", { count: d.success })}, ${t("accounts.failedCount", { count: d.failure })}`}>
                      <span class="stack">
                        {#if d.success}<i class="seg ok-sw" style:height="{(d.success / top) * 100}%"></i>{/if}
                        {#if d.failure}<i class="seg warn" style:height="{(d.failure / top) * 100}%"></i>{/if}
                      </span>
                    </span>
                  {/each}
                </div>
                {#if hovered && hover !== null}
                  <div class="tip" style:left="{((hover + 0.5) / daily.length) * 100}%" class:right={hover > daily.length / 2}>
                    <b>{dayLabel(hovered.date, "long")}</b>
                    <span class="tip-row"><i class="swatch ok-sw"></i>{t("accounts.successful")}<b class="num">{hovered.success}</b></span>
                    <span class="tip-row"><i class="swatch warn"></i>{t("accounts.failed")}<b class="num">{hovered.failure}</b></span>
                  </div>
                {/if}
              </div>
              <div></div>
              <div class="axis-x faint">
                {#each daily as d, i (d.date)}
                  <span>{i === daily.length - 1 ? t("accounts.today") : (daily.length - 1 - i) % labelEvery === 0 && i < daily.length - labelEvery / 2 ? dayLabel(d.date, "short") : ""}</span>
                {/each}
              </div>
            </div>

            <div class="split">
              <div>
                <h3>{t("accounts.sourcesTitle")}</h3>
                {#each signins.sources.slice(0, 8) as src (src.address)}
                  <div class="line">
                    <span class="mono selectable">{from(src.address)}</span>
                    {#if src.public}<span class="badge bad"><i class="icon">{"\uE774"}</i>{t("accounts.internet")}</span>{/if}
                    <span class="num">{t("accounts.attempts", { count: src.count })}</span>
                    <span class="faint small tried" title={src.accounts.join(", ")}>{t("accounts.tried", { names: src.accounts.join(", ") })}</span>
                  </div>
                {:else}
                  <p class="faint">{signins.securityReadable ? t("accounts.noFailures") : t("accounts.failuresHidden")}</p>
                {/each}
              </div>
              <div>
                <h3>{t("accounts.remoteTitle")}</h3>
                {#each signins.remote.slice(0, 8) as r (r.events[0])}
                  <button class="line link-line" onclick={() => (selected = { type: "event", id: r.events[r.events.length - 1] })}>
                    <span class="faint when">{when(r.time)}</span>
                    <span class="name">{bare(r.account)}</span>
                    <span class="mono">{r.address}</span>
                    {#if r.public}<span class="badge bad"><i class="icon">{"\uE774"}</i>{t("accounts.internet")}</span>{/if}
                    <span class="faint small">{t(r.how === "network" ? "accounts.viaNetwork" : "accounts.viaRdp")}</span>
                  </button>
                {:else}
                  <p class="faint">{t("accounts.remoteNone")}</p>
                {/each}
              </div>
            </div>

            <div class="section-head events-head">
              <h3>{t("accounts.eventsTitle")}</h3>
              {#if only}
                <span class="faint">{t("accounts.showingWarning", { title: only.title })}</span>
                <button class="link" onclick={() => (only = null)}>{t("accounts.clearFilter")}</button>
              {/if}
            </div>
            {#each visibleEvents as e (e.id)}
              {@const tone = eventTone(e)}
              <button class="row event" class:sel={selected?.type === "event" && selected.id === e.id} onclick={() => (selected = { type: "event", id: e.id })}>
                <i class="icon sev {tone}">{tone === "bad" ? "\uEA39" : tone === "warn" ? "\uE7BA" : "\uE946"}</i>
                <span class="time">{when(e.time)}</span>
                <span class="what" title={eventLine(e)}>{eventLine(e)}</span>
                <span class="faint detail">{e.address ? e.address : e.reason ? t(REASON[e.reason] ?? "accounts.reason.other") : e.logon ? t(LOGON[e.logon] ?? "accounts.logon.other") : ""}</span>
              </button>
            {:else}
              <p class="faint empty-line">{t("accounts.noEvents")}</p>
            {/each}
            {#if listed.length > ROWS}
              <button class="link more" onclick={() => (allEvents = !allEvents)}>{allEvents ? t("accounts.showFewer") : t("accounts.showAll", { count: listed.length })}</button>
            {/if}
          {/if}
        </section>
      </div>

      <aside class="side">
        {#if current}
          <section class="panel detail-panel" aria-live="polite">
            <div class="detail-head">
              <i class="icon glyph">{current.icon}</i>
              <h3 class="selectable">{current.title}</h3>
            </div>
            <div class="grid">
              {#each current.fields as f, i (i)}
                <span class="faint">{f.label}</span>
                <span class="selectable" class:mono={f.mono}>{f.value}</span>
              {/each}
            </div>
          </section>
        {:else}
          <section class="panel detail-panel"><p class="faint">{t("accounts.select")}</p></section>
        {/if}
        {#if !elevated}<p class="faint side-note">{t("accounts.adminNote")}</p>{/if}
      </aside>
    </div>

    <div class="faint footer">
      {t("accounts.footer", { when: when(new Date(signins?.readMs ?? Date.now()).toISOString()) })}
      {#if signins?.truncated} · {t("accounts.truncated")}{/if}
      {#if signins?.unreadLogs.length} · {t("accounts.unread", { logs: signins.unreadLogs.join(", ") })}{/if}
      {#if data.errors.length} · <span class="selectable">{data.errors.join(" · ")}</span>{/if}
    </div>
  {:else if !error}
    <p class="faint empty">{t("common.reading")}</p>
  {/if}
</div>

<style>
  button:not(.command) > .icon { margin-right: 6px; }
  .scroll { overflow-y: auto; }
  .lead { margin: -6px 0 0; }
  .warn-text { color: var(--warn); margin: 0; }
  .grow { flex: 1; }
  .segmented {
    display: inline-flex; gap: 2px; padding: 2px; border-radius: var(--radius); background: var(--control);
    border: 1px solid var(--control-stroke);
  }
  .segmented button {
    min-height: 26px; padding: 2px 10px 3px; border: 1px solid transparent; background: transparent; color: var(--ink2);
    border-radius: 3px; font-size: 13px;
  }
  .segmented button:hover:not(:disabled) { background: var(--hover); color: var(--ink); }
  .segmented button.on {
    background: var(--surface); color: var(--ink); border-color: var(--control-stroke); font-weight: 600;
    box-shadow: 0 1px 2px rgba(0, 0, 0, 0.06);
  }

  .look { display: flex; flex-direction: column; gap: 10px; flex: none; }
  .hint { display: grid; grid-template-columns: 18px minmax(0, 1fr) auto; gap: 10px; align-items: start; }
  .hint-body { display: flex; flex-direction: column; gap: 2px; font-size: 13px; }
  .sev { font-size: 14px; line-height: 20px; color: var(--ink3); }
  .sev.warn { color: var(--warn); }
  .sev.bad { color: var(--bad); }
  .calm { display: flex; align-items: center; gap: 10px; flex: none; }
  .calm .ok { color: var(--ok); }
  .link {
    min-height: 0; padding: 2px 4px; border: 0; background: transparent; color: var(--accent); font-size: 13px; white-space: nowrap;
  }
  .link:hover:not(:disabled) { background: transparent; text-decoration: underline; }

  .columns { display: grid; grid-template-columns: minmax(0, 1fr) 340px; gap: 14px; align-items: start; }
  @media (max-width: 1100px) { .columns { grid-template-columns: minmax(0, 1fr); } }
  .main { display: flex; flex-direction: column; gap: 12px; min-width: 0; }
  .section { display: flex; flex-direction: column; padding: 12px 8px 8px; }
  .section-head { display: flex; align-items: baseline; gap: 8px; padding: 0 8px 6px; flex-wrap: wrap; }
  .note { margin: -2px 8px 6px; }
  .empty-line { margin: 4px 8px; }

  .row {
    position: relative; display: flex; align-items: center; gap: 8px; width: 100%; min-height: 34px; padding: 0 8px 0 0;
    border-radius: 4px; font-size: 13px;
  }
  .row:hover { background: var(--hover); }
  .row.sel { background: var(--table-select); }
  .row.off .name { color: var(--ink2); }
  .row-main {
    flex: 1; min-width: 0; display: flex; align-items: center; gap: 10px; min-height: 34px; padding: 4px 8px; border: 0;
    background: transparent; color: var(--ink); text-align: left; font-size: 13px;
  }
  .row-main:hover:not(:disabled) { background: transparent; }
  .row-main.static { cursor: default; }
  .row-actions { display: flex; gap: 6px; flex: none; }
  .row-actions button { min-height: 28px; font-size: 13px; }
  .glyph { font-size: 16px; color: var(--ink2); flex: none; width: 18px; }
  .who { display: flex; flex-direction: column; min-width: 120px; }
  .name { font-weight: 600; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; min-width: 0; }
  .small { font-size: 12px; }
  .badges { display: flex; flex-wrap: wrap; gap: 4px; flex: 1; min-width: 0; }
  .badge {
    display: inline-flex; align-items: center; gap: 4px; padding: 0 6px; border-radius: 4px; font-size: 12px; line-height: 20px;
    border: 1px solid var(--rule-strong); color: var(--ink2); white-space: nowrap;
  }
  .badge .icon { font-size: 11px; }
  .badge.accent { border-color: var(--accent); color: var(--accent); }
  .badge.bad { border-color: var(--bad); color: var(--bad); }
  .badge.warn { border-color: var(--warn); color: var(--warn); }
  .faint-badge { border-color: transparent; color: var(--ink3); padding: 0 2px; }
  .when { white-space: nowrap; flex: none; }
  .more { align-self: flex-start; margin: 4px 8px 0; }

  .legend { display: inline-flex; gap: 14px; flex-wrap: wrap; }
  .legend > span { display: inline-flex; align-items: center; gap: 6px; }
  .swatch { display: inline-block; width: 10px; height: 10px; border-radius: 2px; background: var(--ink3); }
  .ok-sw { background: var(--ink3); }
  .swatch.warn, .seg.warn { background: var(--warn); }
  .chart { display: grid; grid-template-columns: 32px minmax(0, 1fr); grid-template-rows: 120px auto; column-gap: 6px; padding: 0 8px 8px; }
  .axis-y { display: flex; flex-direction: column; justify-content: space-between; align-items: flex-end; font-size: 11px; line-height: 1; }
  .plot { position: relative; border-bottom: 1px solid var(--rule-strong); }
  .grid-line { position: absolute; left: 0; right: 0; border-top: 1px dashed var(--rule); pointer-events: none; }
  .bars { position: absolute; inset: 0; display: flex; align-items: stretch; }
  .col { flex: 1 1 0; min-width: 0; height: 100%; padding: 0 1px; display: flex; align-items: flex-end; }
  .col:hover { background: var(--hover); }
  .stack { display: flex; flex-direction: column-reverse; width: 100%; max-width: 18px; margin: 0 auto; height: 100%; gap: 1px; }
  .seg { display: block; width: 100%; min-height: 2px; border-radius: 1px; flex: none; }
  .axis-x { display: flex; font-size: 11px; line-height: 14px; padding-top: 2px; }
  .axis-x span { flex: 1 1 0; min-width: 0; white-space: nowrap; overflow: visible; text-align: center; }
  .axis-x span:last-child { text-align: right; }
  .tip {
    position: absolute; top: 4px; z-index: 3; transform: translateX(8px); display: flex; flex-direction: column; gap: 4px;
    min-width: 170px; padding: 8px 10px; font-size: 12px; pointer-events: none;
    background: var(--flyout); border: 1px solid var(--rule-strong); border-radius: 8px; box-shadow: var(--shadow-flyout);
  }
  .tip.right { transform: translateX(calc(-100% - 8px)); }
  .tip-row { display: flex; align-items: center; gap: 6px; }
  .tip-row b { margin-left: auto; padding-left: 12px; }

  .split { display: grid; grid-template-columns: minmax(0, 1fr) minmax(0, 1fr); gap: 16px; padding: 4px 8px 8px; }
  @media (max-width: 900px) { .split { grid-template-columns: minmax(0, 1fr); } }
  .split h3, .events-head h3 { font-size: 14px; margin: 0 0 6px; }
  .line { display: flex; align-items: center; gap: 8px; min-height: 28px; font-size: 13px; flex-wrap: wrap; }
  .link-line {
    width: 100%; border: 0; background: transparent; color: var(--ink); text-align: left; padding: 2px 4px; border-radius: 4px;
  }
  .link-line:hover:not(:disabled) { background: var(--hover); }
  .tried { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; max-width: 100%; }
  .events-head { padding-top: 8px; }
  .row.event {
    display: grid; grid-template-columns: 18px 150px minmax(0, 1fr) auto; gap: 10px; padding: 4px 8px; border: 0;
    background: transparent; color: var(--ink); text-align: left;
  }
  .row.event:hover:not(:disabled) { background: var(--hover); }
  .row.event.sel { background: var(--table-select); }
  .time { color: var(--ink2); white-space: nowrap; }
  .what { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; min-width: 0; }
  .detail { white-space: nowrap; overflow: hidden; text-overflow: ellipsis; max-width: 220px; }

  .side { display: flex; flex-direction: column; gap: 12px; position: sticky; top: 0; min-width: 0; }
  .detail-panel { display: flex; flex-direction: column; gap: 8px; }
  .detail-panel p { margin: 0; }
  .detail-head { display: flex; align-items: flex-start; gap: 8px; }
  .detail-head h3 { overflow-wrap: anywhere; }
  .grid { display: grid; grid-template-columns: 120px minmax(0, 1fr); gap: 4px 12px; font-size: 13px; }
  .grid .mono { overflow-wrap: anywhere; }
  .side-note { margin: 0 4px; }
  .footer { padding: 0 4px 4px; }
  .empty { padding: 30px; text-align: center; margin: 0; }
</style>
