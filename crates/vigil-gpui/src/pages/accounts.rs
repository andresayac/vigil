//! Accounts and sign-ins: what to look at, the local accounts, the Administrators and Remote
//! Desktop Users groups, the sessions, the sign-in activity (a chart per day, failure sources,
//! remote sign-ins and the events), and the selected entry's details. Disable, remove from a
//! group, sign out and undo go through the action service.

use std::sync::Arc;

use gpui_kit::prelude::FluentBuilder as _;
use gpui_kit::{
    AnyElement, Context, Div, ElementId, FontWeight, IntoElement, ParentElement, Render, Styled, Window, div, px,
};
use serde_json::{Value, json};
use vigil_core::state::AppState;

use crate::app::Ctx;
use crate::data::{self, Src};
use crate::format::num;
use crate::i18n::{t, t_or, tf, tn};
use crate::icons;
use crate::pages::common::{self, Acting, Acts, day_short, when, when_ms};
use crate::theme::{Tokens, tokens};
use crate::ui;
use crate::ui::kit::{self, BarColumn, J as _};

#[derive(Clone, PartialEq)]
enum Sel {
    Account(String),
    Member(String),
    Session(i64),
    Event(String),
}

pub struct AccountsPage {
    ctx: Ctx,
    days: u32,
    data: Option<Value>,
    loading: bool,
    error: Option<String>,
    show_disabled: bool,
    selected: Option<Sel>,
    only: Option<(Vec<String>, String)>,
    all_events: bool,
    acting: Acting,
}

impl Acts for AccountsPage {
    fn acting(&mut self) -> &mut Acting {
        &mut self.acting
    }
    fn core(&self) -> Option<Arc<AppState>> {
        self.ctx.core.clone()
    }
    fn after(&mut self, _: &mut Window, cx: &mut Context<Self>) {
        self.load(cx);
    }
}

fn bare(account: &str) -> &str {
    account.rsplit('\\').next().unwrap_or(account)
}

fn from(address: &str) -> String {
    if address.is_empty() {
        t("accounts.thisComputer")
    } else {
        address.to_string()
    }
}

fn logon_text(logon: &str) -> String {
    match logon {
        "interactive" | "network" | "unlock" | "remote" | "cached" => t(&format!("accounts.logon.{logon}")),
        _ => t("accounts.logon.other"),
    }
}

fn reason_text(reason: &str) -> String {
    let key = match reason {
        "bad_password" => "badPassword",
        "no_such_user" => "noSuchUser",
        "password_expired" => "passwordExpired",
        "must_change" => "mustChange",
        "not_allowed" => "notAllowed",
        "locked" | "disabled" | "expired" | "clock" => reason,
        _ => "other",
    };
    t(&format!("accounts.reason.{key}"))
}

fn event_key(kind: &str) -> String {
    let key = match kind {
        "member_added" => "memberAdded",
        "member_removed" => "memberRemoved",
        "log_cleared" => "logCleared",
        "remote_auth" => "remoteAuth",
        "remote_logon" => "remoteLogon",
        "remote_reconnect" => "remoteReconnect",
        "session_logon" => "sessionLogon",
        other => other,
    };
    t_or(&format!("accounts.ev.{key}"), kind)
}

impl AccountsPage {
    pub fn new(ctx: Ctx, cx: &mut Context<Self>) -> Self {
        let mut page = Self {
            ctx,
            days: 30,
            data: None,
            loading: false,
            error: None,
            show_disabled: false,
            selected: None,
            only: None,
            all_events: false,
            acting: Acting::default(),
        };
        page.load(cx);
        page
    }

    fn load(&mut self, cx: &mut Context<Self>) {
        self.loading = true;
        let core = self.ctx.core.clone();
        let days = self.days;
        common::read(
            cx,
            move || data::fetch(core.as_ref(), Src::Accounts(days)),
            |this: &mut Self, result, _| {
                this.loading = false;
                match result {
                    Ok(v) => {
                        this.data = Some(v);
                        this.error = None;
                    }
                    Err(e) => this.error = Some(e),
                }
            },
        );
    }

    fn sid_name(&self, sid: &str) -> String {
        let Some(d) = &self.data else { return sid.to_string() };
        if let Some(a) = d.a("accounts").iter().find(|a| a.s("sid").eq_ignore_ascii_case(sid)) {
            return a.s("name").to_string();
        }
        for group in ["administrators", "remoteDesktopUsers"] {
            if let Some(m) = d.at(group).a("members").iter().find(|m| m.s("sid") == sid) {
                return m.s("name").to_string();
            }
        }
        sid.to_string()
    }

    fn event_line(&self, e: &Value) -> String {
        let who = if matches!(e.s("kind"), "member_added" | "member_removed") {
            if e.has("member") {
                e.s("member").to_string()
            } else {
                self.sid_name(e.s("memberSid"))
            }
        } else {
            e.s("account").to_string()
        };
        let base = event_key(e.s("kind"));
        if who.is_empty() { base } else { format!("{base}: {who}") }
    }

    fn warning_text(&self, w: &Value) -> (String, String) {
        let count = w.n("count") as u64;
        let subject = w.s("subject");
        let detail = w.s("detail");
        let p: Vec<(&str, &str)> = vec![
            ("address", subject),
            ("names", detail),
            ("account", subject),
            ("by", detail),
            ("sid", subject),
        ];
        let key = match w.s("code") {
            "guessing_address" if !subject.is_empty() => "guessing",
            "guessing_address" => "guessingLocal",
            "guessing_names" => "names",
            "internet_signin" => "internet",
            "log_cleared" => "cleared",
            "admin_added" => "newAdmin",
            "account_created" => "created",
            "lockouts" => "lockouts",
            "no_password_required" => "noPassword",
            "guest_enabled" => "guest",
            "builtin_admin_enabled" => "builtinAdmin",
            "unknown_admin" => "unknownAdmin",
            other => return (other.to_string(), String::new()),
        };
        let title = tn(&format!("accounts.warn.{key}.title"), count, &p);
        let member = self.sid_name(subject);
        let mut text_params = p.clone();
        if key == "internet" {
            text_params = vec![
                ("address", subject),
                ("names", detail),
                ("account", detail),
                ("by", detail),
                ("sid", subject),
            ];
        }
        if key == "newAdmin" {
            text_params.push(("member", &member));
        }
        let text = tn(&format!("accounts.warn.{key}.text"), count, &text_params);
        (title, text)
    }

    fn select(&mut self, sel: Sel, cx: &mut Context<Self>) {
        self.selected = Some(sel);
        cx.notify();
    }

    fn send(&mut self, request: Value, window: &mut Window, cx: &mut Context<Self>) {
        common::send_json(self, request, window, cx);
    }

    fn badge_row(&self, badges: Vec<(String, Option<gpui_kit::Hsla>, bool)>, tk: &Tokens) -> Div {
        kit::row()
            .gap_1()
            .children(badges.into_iter().map(|(text, color, faint)| {
                if faint {
                    kit::faint(text, tk)
                } else {
                    kit::badge(text, color, tk)
                }
            }))
    }

    fn accounts_section(&self, d: &Value, cx: &mut Context<Self>, tk: &Tokens) -> Div {
        let accounts = d.a("accounts");
        let elevated = self.ctx.elevated;
        let enabled_admins = accounts.iter().filter(|a| a.b("admin") && a.b("enabled")).count();
        let mut on: Vec<&Value> = accounts.iter().filter(|a| a.b("enabled")).collect();
        on.sort_by_key(|a| {
            let rank = if a.b("current") {
                0
            } else if a.b("admin") {
                1
            } else {
                2
            };
            (rank, a.s("name").to_lowercase())
        });
        let mut off: Vec<&Value> = accounts.iter().filter(|a| !a.b("enabled")).collect();
        off.sort_by_key(|a| a.s("name").to_lowercase());
        let disabled_count = off.len();
        let mut list = on;
        if self.show_disabled {
            list.extend(off);
        }
        let mut panel = kit::panel(tk).child(
            kit::row()
                .child(kit::h2(t("accounts.accountsTitle")))
                .child(kit::faint(accounts.len().to_string(), tk)),
        );
        if d.b("domainJoined") {
            panel = panel.child(kit::faint(t("accounts.domainNote"), tk));
        }
        for (i, a) in list.into_iter().enumerate() {
            let sid = a.s("sid").to_string();
            let selected = self.selected == Some(Sel::Account(sid.clone()));
            let mut badges = Vec::new();
            if a.b("current") {
                badges.push((t("accounts.you"), Some(tk.accent), false));
            }
            if a.b("admin") {
                badges.push((t("accounts.badgeAdmin"), None, false));
            }
            if a.b("remoteDesktop") {
                badges.push((t("accounts.badgeRemote"), None, false));
            }
            if !a.b("enabled") {
                badges.push((t("accounts.badgeDisabled"), None, false));
            }
            if a.b("enabled") && !a.b("passwordRequired") {
                badges.push((t("accounts.badgeNoPassword"), Some(tk.bad), false));
            }
            if a.b("locked") {
                badges.push((t("accounts.badgeLocked"), Some(tk.warn), false));
            }
            if a.has("onlineProvider") {
                badges.push((t("accounts.badgeMicrosoft"), None, false));
            }
            if a.has("builtin") {
                badges.push((t("accounts.badgeBuiltin"), None, false));
            }
            if a.b("enabled") && !a.b("passwordExpires") && !a.has("onlineProvider") {
                badges.push((t("accounts.badgeNeverExpires"), None, true));
            }
            let last = if a.has("lastLogon") {
                tf("accounts.lastLogon", &[("when", &when(a.s("lastLogon")))])
            } else {
                t("accounts.neverSignedIn")
            };
            let weak = cx.entity().downgrade();
            let key = sid.clone();
            let mut row = kit::list_row(
                ElementId::NamedInteger("ac-acc".into(), i as u64),
                a.s("name").to_string(),
                selected,
                move |_, cx| {
                    let _ = weak.update(cx, |this, cx| this.select(Sel::Account(key.clone()), cx));
                },
                tk,
            )
            .child(kit::glyph(
                if a.b("admin") { icons::SHIELD } else { '\u{E77B}' },
                16.,
                tk.ink2,
            ))
            .child(
                div()
                    .flex_1()
                    .min_w_0()
                    .flex()
                    .flex_col()
                    .child(
                        kit::row()
                            .gap_1()
                            .child(
                                div()
                                    .font_weight(FontWeight::SEMIBOLD)
                                    .when(!a.b("enabled"), |this| this.text_color(tk.ink2))
                                    .child(a.s("name").to_string()),
                            )
                            .when(a.has("fullName"), |this| {
                                this.child(kit::faint(a.s("fullName").to_string(), tk))
                            }),
                    )
                    .child(self.badge_row(badges, tk)),
            )
            .child(kit::faint(last, tk));
            let vigil = d.a("disabledByVigil").iter().find(|v| v.s("sid") == sid).cloned();
            let can_disable = a.b("enabled")
                && !a.b("current")
                && !matches!(a.s("builtin"), "default" | "wdag")
                && !(a.b("admin") && enabled_admins <= 1);
            if let Some(v) = vigil {
                let request = json!({"kind": "journal", "op": "undo", "id": v.s("recordId")});
                row = row.child(
                    ui::button(
                        ElementId::NamedInteger("ac-again".into(), i as u64),
                        t("accounts.enableAgain"),
                    )
                    .disabled(!elevated)
                    .tip(tf("accounts.disabledByVigil", &[("when", &when(v.s("time")))]))
                    .on_click(cx.listener(move |this, _, window, cx| this.send(request.clone(), window, cx))),
                );
            } else if can_disable {
                let request = json!({"kind": "account", "op": "disable", "sid": sid});
                row = row.child(
                    ui::button(
                        ElementId::NamedInteger("ac-disable".into(), i as u64),
                        t("accounts.disable"),
                    )
                    .glyph('\u{E8F8}')
                    .disabled(!elevated)
                    .when(!elevated, |b| b.tip(t("accounts.adminNote")))
                    .on_click(cx.listener(move |this, _, window, cx| this.send(request.clone(), window, cx))),
                );
            }
            panel = panel.child(row);
        }
        if disabled_count > 0 {
            let label = if self.show_disabled {
                t("accounts.hideDisabled")
            } else {
                tn("accounts.showDisabled", disabled_count as u64, &[])
            };
            let weak = cx.entity().downgrade();
            panel = panel.child(kit::link(
                "ac-toggle-disabled",
                label,
                move |_, cx| {
                    let _ = weak.update(cx, |this, cx| {
                        this.show_disabled = !this.show_disabled;
                        cx.notify();
                    });
                },
                tk,
            ));
        }
        panel
    }

    fn group_section(&self, d: &Value, key: &str, group_name: &str, cx: &mut Context<Self>, tk: &Tokens) -> Div {
        let (title, note, field) = if key == "administrators" {
            ("accounts.adminsTitle", "accounts.adminsNote", "administrators")
        } else {
            ("accounts.rdpTitle", "accounts.rdpNote", "remoteDesktopUsers")
        };
        let group = d.at(field);
        let members = group.a("members");
        let elevated = self.ctx.elevated;
        let admins = group.s("sid") == "S-1-5-32-544";
        let enabled_admins = members
            .iter()
            .filter(|m| m.at("enabled").as_bool() == Some(true))
            .count();
        let mut panel = kit::panel(tk)
            .child(
                kit::row()
                    .child(kit::h2(t(title)))
                    .child(kit::faint(members.len().to_string(), tk)),
            )
            .child(kit::faint(t(note), tk));
        if group.has("error") {
            panel = panel.child(kit::colored(group.s("error").to_string(), tk.warn));
        }
        if members.is_empty() {
            panel = panel.child(kit::faint(t("accounts.groupEmpty"), tk));
        }
        for (i, m) in members.iter().enumerate() {
            let sid = m.s("sid").to_string();
            let kind = m.s("kind");
            let name = if m.has("name") {
                m.s("name").to_string()
            } else if kind == "deleted" {
                t("accounts.memberDeleted")
            } else {
                t("accounts.memberUnknown")
            };
            let kind_key = match kind {
                "well_known" => "wellKnown",
                "user" | "group" | "alias" | "deleted" | "unknown" => kind,
                _ => "other",
            };
            let mut badges = Vec::new();
            if m.b("current") {
                badges.push((t("accounts.you"), Some(tk.accent), false));
            }
            badges.push((t(&format!("accounts.kind.{kind_key}")), None, true));
            if m.at("enabled").as_bool() == Some(false) {
                badges.push((t("accounts.badgeDisabled"), None, false));
            }
            let can_remove = (sid.starts_with("S-1-5-21-") || sid.starts_with("S-1-12-1-"))
                && !m.b("current")
                && !matches!(kind, "group" | "alias" | "well_known")
                && !(matches!(kind, "deleted" | "unknown" | "other") && !m.b("local"))
                && !(admins && m.b("local") && sid.ends_with("-500"))
                && !(admins && m.at("enabled").as_bool() == Some(true) && enabled_admins <= 1);
            let selected = self.selected == Some(Sel::Member(sid.clone()));
            let weak = cx.entity().downgrade();
            let key_sid = sid.clone();
            let mut row = kit::list_row(
                ElementId::Name(format!("ac-m-{key}-{i}").into()),
                name.clone(),
                selected,
                move |_, cx| {
                    let _ = weak.update(cx, |this, cx| this.select(Sel::Member(key_sid.clone()), cx));
                },
                tk,
            )
            .child(kit::glyph(
                if matches!(kind, "group" | "alias" | "well_known") {
                    '\u{E716}'
                } else {
                    '\u{E77B}'
                },
                16.,
                tk.ink2,
            ))
            .child(
                div()
                    .flex_1()
                    .min_w_0()
                    .child(kit::body(name))
                    .child(self.badge_row(badges, tk)),
            );
            if can_remove {
                let request = json!({"kind": "account", "op": "remove_member", "sid": sid, "group": group_name});
                row = row.child(
                    ui::button(ElementId::Name(format!("ac-rm-{key}-{i}").into()), t("accounts.remove"))
                        .disabled(!elevated)
                        .when(!elevated, |b| b.tip(t("accounts.adminNote")))
                        .on_click(cx.listener(move |this, _, window, cx| this.send(request.clone(), window, cx))),
                );
            }
            panel = panel.child(row);
        }
        for (i, r) in d
            .a("removedByVigil")
            .iter()
            .filter(|r| r.s("groupSid") == group.s("sid"))
            .enumerate()
        {
            let request = json!({"kind": "journal", "op": "undo", "id": r.s("recordId")});
            let name = if r.has("name") { r.s("name") } else { r.s("sid") };
            panel = panel.child(
                kit::row()
                    .px_2()
                    .child(kit::glyph('\u{E77B}', 16., tk.ink3))
                    .child(div().flex_1().child(kit::faint(name.to_string(), tk)).child(kit::faint(
                        tf("accounts.removedByVigil", &[("when", &when(r.s("time")))]),
                        tk,
                    )))
                    .child(
                        ui::button(
                            ElementId::Name(format!("ac-back-{key}-{i}").into()),
                            t("accounts.addBack"),
                        )
                        .glyph('\u{E8FA}')
                        .disabled(!elevated)
                        .on_click(cx.listener(move |this, _, window, cx| this.send(request.clone(), window, cx))),
                    ),
            );
        }
        panel
    }

    fn sessions_section(&self, d: &Value, cx: &mut Context<Self>, tk: &Tokens) -> Div {
        let sessions = d.a("sessions");
        let elevated = self.ctx.elevated;
        let current_user = sessions
            .iter()
            .find(|s| s.b("current"))
            .map(|s| s.s("user").to_lowercase())
            .unwrap_or_default();
        let mut panel = kit::panel(tk).child(
            kit::row()
                .child(kit::h2(t("accounts.sessionsTitle")))
                .child(kit::faint(sessions.len().to_string(), tk)),
        );
        if sessions.is_empty() {
            panel = panel.child(kit::faint(t("accounts.noSessions"), tk));
        }
        for (i, s) in sessions.iter().enumerate() {
            let id = s.i("id");
            let how = how(s);
            let state = s.s("state");
            let state_key = if matches!(state, "active" | "connected" | "disconnected" | "idle") {
                state
            } else {
                "other"
            };
            let mut badges = Vec::new();
            if s.b("current") {
                badges.push((t("accounts.thisSession"), Some(tk.accent), false));
            }
            badges.push((how, (s.s("protocol") == "rdp").then_some(tk.warn), false));
            badges.push((t(&format!("accounts.state.{state_key}")), None, true));
            let weak = cx.entity().downgrade();
            let mut row = kit::list_row(
                ElementId::NamedInteger("ac-s".into(), i as u64),
                s.s("user").to_string(),
                self.selected == Some(Sel::Session(id)),
                move |_, cx| {
                    let _ = weak.update(cx, |this, cx| this.select(Sel::Session(id), cx));
                },
                tk,
            )
            .child(kit::glyph('\u{E7F4}', 16., tk.ink2))
            .child(
                div()
                    .flex_1()
                    .min_w_0()
                    .child(kit::body(s.s("user").to_string()))
                    .child(self.badge_row(badges, tk)),
            )
            .when(s.has("logonTime"), |this| {
                this.child(kit::faint(
                    tf("accounts.since", &[("when", &when(s.s("logonTime")))]),
                    tk,
                ))
            });
            let sign_out = !s.b("current")
                && s.has("user")
                && s.s("user").to_lowercase() != current_user
                && (state == "disconnected" || s.s("protocol") == "rdp");
            if sign_out {
                let request = json!({"kind": "account", "op": "logoff", "session": id});
                row = row.child(
                    ui::button(
                        ElementId::NamedInteger("ac-off".into(), i as u64),
                        t("accounts.signOut"),
                    )
                    .glyph('\u{E7E8}')
                    .disabled(!elevated)
                    .when(!elevated, |b| b.tip(t("accounts.adminNote")))
                    .on_click(cx.listener(move |this, _, window, cx| this.send(request.clone(), window, cx))),
                );
            }
            panel = panel.child(row);
        }
        panel
    }

    fn activity_section(&self, d: &Value, cx: &mut Context<Self>, tk: &Tokens) -> Div {
        let signins = d.at("signins");
        let mut panel = kit::panel(tk).child(kit::h2(t("accounts.activityTitle")));
        if signins.is_object() {
            panel = panel.child(
                kit::row()
                    .child(kit::faint(
                        format!(
                            "{} · {}",
                            tn("accounts.signinsCount", signins.n("success") as u64, &[]),
                            tn("accounts.failedCount", signins.n("failure") as u64, &[])
                        ),
                        tk,
                    ))
                    .child(div().flex_1())
                    .child(div().w(px(10.)).h(px(10.)).bg(tk.ink3))
                    .child(kit::faint(t("accounts.successful"), tk))
                    .child(div().w(px(10.)).h(px(10.)).bg(tk.warn))
                    .child(kit::faint(t("accounts.failed"), tk)),
            );
        }
        if d.has("signinsError") {
            panel = panel.child(kit::colored(d.s("signinsError").to_string(), tk.warn));
        }
        if !signins.is_object() {
            return panel;
        }
        if !signins.b("securityReadable") {
            panel = panel.child(kit::faint(t("accounts.securityHidden"), tk));
        }
        let daily = signins.a("daily");
        let max = daily
            .iter()
            .map(|x| x.n("success") + x.n("failure"))
            .fold(0.0, f64::max);
        let top = kit::chart_top(max);
        let labels = kit::day_labels(daily.len(), |i| day_short(daily[i].s("date")), &t("accounts.today"));
        let columns: Vec<BarColumn> = daily
            .iter()
            .zip(labels)
            .map(|(x, label)| BarColumn {
                key: x.s("date").to_string(),
                name: when(x.s("date")),
                segments: vec![(x.n("success"), tk.ink3), (x.n("failure"), tk.warn)],
                tip: vec![
                    format!("{}: {}", t("accounts.successful"), num(x.n("success"), 0)),
                    format!("{}: {}", t("accounts.failed"), num(x.n("failure"), 0)),
                ],
                mark: false,
                label,
            })
            .collect();
        panel = panel.child(kit::bar_chart("ac-chart", columns, top, 120., None, None, tk));

        // Sources of failures and remote sign-ins.
        let mut sources = div()
            .flex_1()
            .min_w_0()
            .flex()
            .flex_col()
            .gap_1()
            .child(kit::h3(t("accounts.sourcesTitle")));
        let list = signins.a("sources");
        if list.is_empty() {
            sources = sources.child(kit::faint(
                t(if signins.b("securityReadable") {
                    "accounts.noFailures"
                } else {
                    "accounts.failuresHidden"
                }),
                tk,
            ));
        }
        for s in list.iter().take(8) {
            let names = s.strs("accounts").join(", ");
            sources = sources.child(
                kit::row()
                    .gap_2()
                    .child(kit::mono(from(s.s("address"))))
                    .when(s.b("public"), |this| {
                        this.child(kit::badge(t("accounts.internet"), Some(tk.bad), tk))
                    })
                    .child(kit::body(tn("accounts.attempts", s.n("count") as u64, &[])))
                    .child(kit::faint(tf("accounts.tried", &[("names", &names)]), tk)),
            );
        }
        let mut remote = div()
            .flex_1()
            .min_w_0()
            .flex()
            .flex_col()
            .gap_1()
            .child(kit::h3(t("accounts.remoteTitle")));
        let list = signins.a("remote");
        if list.is_empty() {
            remote = remote.child(kit::faint(t("accounts.remoteNone"), tk));
        }
        for (i, r) in list.iter().take(8).enumerate() {
            let last = r.strs("events").last().map(|s| s.to_string()).unwrap_or_default();
            let weak = cx.entity().downgrade();
            remote = remote.child(
                kit::list_row(
                    ElementId::NamedInteger("ac-remote".into(), i as u64),
                    format!("{} {}", bare(r.s("account")), r.s("address")),
                    self.selected == Some(Sel::Event(last.clone())),
                    move |_, cx| {
                        let _ = weak.update(cx, |this, cx| this.select(Sel::Event(last.clone()), cx));
                    },
                    tk,
                )
                .child(kit::faint(when(r.s("time")), tk))
                .child(kit::body(bare(r.s("account")).to_string()))
                .child(kit::mono(r.s("address").to_string()))
                .when(r.b("public"), |this| {
                    this.child(kit::badge(t("accounts.internet"), Some(tk.bad), tk))
                })
                .child(kit::faint(
                    t(if r.s("how") == "network" {
                        "accounts.viaNetwork"
                    } else {
                        "accounts.viaRdp"
                    }),
                    tk,
                )),
            );
        }
        panel = panel.child(div().flex().flex_wrap().gap_4().child(sources).child(remote));

        // Events.
        panel = panel.child(kit::h3(t("accounts.eventsTitle")));
        if let Some((_, title)) = &self.only {
            let weak = cx.entity().downgrade();
            panel = panel.child(
                kit::row()
                    .child(kit::faint(tf("accounts.showingWarning", &[("title", title)]), tk))
                    .child(kit::link(
                        "ac-clear",
                        t("accounts.clearFilter"),
                        move |_, cx| {
                            let _ = weak.update(cx, |this, cx| {
                                this.only = None;
                                cx.notify();
                            });
                        },
                        tk,
                    )),
            );
        }
        let listed: Vec<&Value> = signins
            .a("events")
            .iter()
            .filter(|e| {
                self.only
                    .as_ref()
                    .is_none_or(|(ids, _)| ids.iter().any(|id| id == e.s("id")))
            })
            .collect();
        if listed.is_empty() {
            panel = panel.child(kit::faint(t("accounts.noEvents"), tk));
        }
        let total = listed.len();
        let visible = if self.all_events {
            listed
        } else {
            listed.into_iter().take(12).collect()
        };
        for (i, e) in visible.into_iter().enumerate() {
            let kind = e.s("kind");
            let (g, c) = if kind == "log_cleared" || (e.b("public") && kind != "failure") {
                (icons::ERROR, tk.bad)
            } else if matches!(kind, "failure" | "lockout" | "member_added" | "created") {
                (icons::WARNING, tk.warn)
            } else {
                (icons::INFO, tk.ink3)
            };
            let detail = if e.has("address") {
                e.s("address").to_string()
            } else if e.has("reason") {
                reason_text(e.s("reason"))
            } else if e.has("logon") {
                logon_text(e.s("logon"))
            } else {
                String::new()
            };
            let id = e.s("id").to_string();
            let line = self.event_line(e);
            let weak = cx.entity().downgrade();
            panel = panel.child(
                kit::list_row(
                    ElementId::NamedInteger("ac-ev".into(), i as u64),
                    line.clone(),
                    self.selected == Some(Sel::Event(id.clone())),
                    move |_, cx| {
                        let _ = weak.update(cx, |this, cx| this.select(Sel::Event(id.clone()), cx));
                    },
                    tk,
                )
                .child(kit::glyph(g, 14., c))
                .child(div().w(px(150.)).flex_none().child(when(e.s("time"))))
                .child(
                    div()
                        .flex_1()
                        .min_w_0()
                        .overflow_hidden()
                        .text_ellipsis()
                        .whitespace_nowrap()
                        .child(line),
                )
                .child(
                    kit::faint(detail, tk)
                        .max_w(px(220.))
                        .overflow_hidden()
                        .text_ellipsis()
                        .whitespace_nowrap(),
                ),
            );
        }
        if total > 12 {
            let weak = cx.entity().downgrade();
            let label = if self.all_events {
                t("accounts.showFewer")
            } else {
                tn("accounts.showAll", total as u64, &[])
            };
            panel = panel.child(kit::link(
                "ac-more",
                label,
                move |_, cx| {
                    let _ = weak.update(cx, |this, cx| {
                        this.all_events = !this.all_events;
                        cx.notify();
                    });
                },
                tk,
            ));
        }
        panel
    }

    fn side(&self, d: &Value, tk: &Tokens) -> Div {
        let mut panel = kit::panel(tk);
        let mut facts: Vec<(String, String, bool)> = Vec::new();
        let (glyph, title) = match &self.selected {
            Some(Sel::Account(sid)) => {
                let Some(a) = d.a("accounts").iter().find(|a| a.s("sid") == sid) else {
                    return panel.child(kit::faint(t("accounts.select"), tk));
                };
                let mut add = |label: &str, value: String, mono: bool| {
                    if !value.is_empty() {
                        facts.push((t(&format!("accounts.field.{label}")), value, mono));
                    }
                };
                add("fullName", a.s("fullName").to_string(), false);
                add("comment", a.s("comment").to_string(), false);
                add(
                    "lastLogon",
                    if a.has("lastLogon") {
                        when(a.s("lastLogon"))
                    } else {
                        t("accounts.neverSignedIn")
                    },
                    false,
                );
                add(
                    "logons",
                    if a.has("logons") {
                        num(a.n("logons"), 0)
                    } else {
                        String::new()
                    },
                    false,
                );
                add("passwordSet", when(a.s("passwordSet")), false);
                add(
                    "badPasswords",
                    if a.has("badPasswords") {
                        num(a.n("badPasswords"), 0)
                    } else {
                        String::new()
                    },
                    false,
                );
                add("online", a.s("onlineName").to_string(), false);
                add("sid", a.s("sid").to_string(), true);
                ('\u{E77B}', a.s("name").to_string())
            }
            Some(Sel::Member(sid)) => {
                let member = ["administrators", "remoteDesktopUsers"]
                    .iter()
                    .flat_map(|g| d.at(g).a("members").iter())
                    .find(|m| m.s("sid") == sid);
                let Some(m) = member else {
                    return panel.child(kit::faint(t("accounts.select"), tk));
                };
                let kind = match m.s("kind") {
                    "well_known" => "wellKnown",
                    k @ ("user" | "group" | "alias" | "deleted" | "unknown") => k,
                    _ => "other",
                };
                facts.push((t("accounts.field.kind"), t(&format!("accounts.kind.{kind}")), false));
                if let Some(enabled) = m.at("enabled").as_bool() {
                    facts.push((
                        t("accounts.field.state"),
                        t(if enabled { "common.enabled" } else { "common.disabled" }),
                        false,
                    ));
                }
                facts.push((t("accounts.field.sid"), m.s("sid").to_string(), true));
                ('\u{E716}', m.s("name").to_string())
            }
            Some(Sel::Session(id)) => {
                let Some(s) = d.a("sessions").iter().find(|s| s.i("id") == *id) else {
                    return panel.child(kit::faint(t("accounts.select"), tk));
                };
                let state = s.s("state");
                let state_key = if matches!(state, "active" | "connected" | "disconnected" | "idle") {
                    state
                } else {
                    "other"
                };
                facts.push((
                    t("accounts.field.state"),
                    t(&format!("accounts.state.{state_key}")),
                    false,
                ));
                facts.push((t("accounts.field.how"), how(s), false));
                if s.has("clientName") {
                    facts.push((t("accounts.field.client"), s.s("clientName").to_string(), false));
                }
                if s.has("logonTime") {
                    facts.push((t("accounts.field.logonTime"), when(s.s("logonTime")), false));
                }
                if s.has("disconnectTime") {
                    facts.push((t("accounts.field.disconnectTime"), when(s.s("disconnectTime")), false));
                }
                let mut session = s.i("id").to_string();
                if s.has("station") {
                    session = format!("{session} ({})", s.s("station"));
                }
                facts.push((t("accounts.field.session"), session, false));
                ('\u{E7F4}', s.s("user").to_string())
            }
            Some(Sel::Event(id)) => {
                let Some(e) = d.at("signins").a("events").iter().find(|e| e.s("id") == id) else {
                    return panel.child(kit::faint(t("accounts.select"), tk));
                };
                let mut add = |label: &str, value: String, mono: bool| {
                    facts.push((t(&format!("accounts.field.{label}")), value, mono));
                };
                add("time", when(e.s("time")), false);
                if e.has("account") {
                    add("account", e.s("account").to_string(), false);
                }
                if e.has("logon") {
                    add("how", logon_text(e.s("logon")), false);
                }
                if e.has("address") || matches!(e.s("kind"), "success" | "failure") {
                    let mut address = from(e.s("address"));
                    if e.b("public") {
                        address = format!("{address} ({})", t("accounts.internet"));
                    }
                    add("address", address, false);
                }
                if e.has("workstation") {
                    add("workstation", e.s("workstation").to_string(), false);
                }
                if e.has("reason") {
                    add("reason", reason_text(e.s("reason")), false);
                }
                if e.has("status") {
                    add("status", e.s("status").to_string(), true);
                }
                if e.has("group") {
                    add("group", e.s("group").to_string(), false);
                }
                if e.has("memberSid") {
                    let member = if e.has("member") {
                        e.s("member").to_string()
                    } else {
                        self.sid_name(e.s("memberSid"))
                    };
                    add("member", member, false);
                }
                if e.has("by") {
                    add("by", e.s("by").to_string(), false);
                }
                if e.has("process") {
                    add("process", e.s("process").to_string(), true);
                }
                add(
                    "event",
                    format!("{} · {}", kit::text(e.at("eventId")), e.s("log")),
                    false,
                );
                ('\u{E823}', self.event_line(e))
            }
            None => return panel.child(kit::faint(t("accounts.select"), tk)),
        };
        panel = panel.child(kit::row().child(kit::glyph(glyph, 18., tk.ink2)).child(kit::h3(title)));
        for (i, (label, value, mono)) in facts.into_iter().enumerate() {
            panel = panel.child(kit::kv_text(
                ElementId::NamedInteger("ac-f".into(), i as u64),
                label,
                value,
                mono,
                120.,
                tk,
            ));
        }
        panel
    }
}

fn how(s: &Value) -> String {
    if s.s("protocol") == "rdp" {
        if s.has("clientAddress") {
            tf("accounts.how.rdpFrom", &[("address", s.s("clientAddress"))])
        } else {
            t("accounts.how.rdp")
        }
    } else {
        t("accounts.how.console")
    }
}

impl Render for AccountsPage {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let tk = *tokens(cx);
        let weak = cx.entity().downgrade();
        let periods: Vec<(u32, String)> = [7u32, 30]
            .iter()
            .map(|d| (*d, tn("common.days", u64::from(*d), &[])))
            .collect();
        let lusrmgr = self.data.as_ref().is_some_and(|d| d.b("lusrmgr"));
        let mut head = kit::row()
            .child(ui::page_title(t("accounts.title")))
            .child(ui::segmented(
                "ac-period",
                t("accounts.period"),
                periods,
                self.days,
                move |d, _, cx| {
                    let _ = weak.update(cx, |this, cx| {
                        if this.days != d {
                            this.days = d;
                            this.only = None;
                            this.load(cx);
                        }
                    });
                },
                &tk,
            ))
            .child(div().flex_1());
        if self.loading {
            head = head.child(kit::faint(t("common.reading"), &tk));
        }
        head = head.child(
            ui::command("ac-users", icons::SETTINGS, t("accounts.otherUsers")).on_click(cx.listener(
                |this, _, window, cx| {
                    this.send(
                        json!({"kind": "shell", "op": "url", "url": "ms-settings:otherusers"}),
                        window,
                        cx,
                    )
                },
            )),
        );
        if lusrmgr {
            head = head.child(
                ui::command("ac-lusrmgr", '\u{E716}', t("accounts.lusrmgr")).on_click(cx.listener(
                    |this, _, window, cx| {
                        this.send(
                            json!({"kind": "shell", "op": "console", "name": "lusrmgr.msc"}),
                            window,
                            cx,
                        )
                    },
                )),
            );
        }
        head = head.child(ui::separator(&tk)).child(
            ui::command("ac-refresh", icons::REFRESH, t("common.refresh"))
                .disabled(self.loading)
                .on_click(cx.listener(|this, _, _, cx| this.load(cx))),
        );
        let mut page = kit::page("accounts")
            .child(head)
            .child(kit::faint(t("accounts.note"), &tk))
            .children(self.acting.bar("ac-result", &tk));
        if let Some(e) = &self.error {
            page = page.child(kit::colored(e.clone(), tk.warn));
        }
        let Some(d) = self.data.clone() else {
            if self.error.is_none() {
                page = page.child(
                    div()
                        .flex()
                        .justify_center()
                        .child(kit::faint(t("common.reading"), &tk)),
                );
            }
            return page;
        };
        // What to look at.
        let warnings = d.a("warnings");
        let mut look = kit::panel(&tk);
        if warnings.is_empty() {
            look = look.child(
                kit::row()
                    .child(kit::glyph(icons::CHECK, 16., tk.ok))
                    .child(kit::body(tf("accounts.allClear", &[("days", &self.days.to_string())]))),
            );
        } else {
            look = look.child(kit::h2(t("accounts.lookTitle")));
            for (i, w) in warnings.iter().enumerate() {
                let (g, c) = match w.s("severity") {
                    "bad" => (icons::ERROR, tk.bad),
                    "warn" => (icons::WARNING, tk.warn),
                    _ => (icons::INFO, tk.ink3),
                };
                let (title, text) = self.warning_text(w);
                let events: Vec<String> = w.strs("events").into_iter().map(str::to_string).collect();
                let weak = cx.entity().downgrade();
                let filter_title = title.clone();
                look = look.child(
                    div()
                        .flex()
                        .gap_2()
                        .items_start()
                        .child(div().pt(px(2.)).child(kit::glyph(g, 16., c)))
                        .child(
                            div()
                                .flex_1()
                                .min_w_0()
                                .child(kit::body(title).font_weight(FontWeight::SEMIBOLD))
                                .child(
                                    kit::sel(ElementId::NamedInteger("ac-w".into(), i as u64), text).text_size(px(13.)),
                                )
                                .when(!events.is_empty(), |this| {
                                    this.child(kit::link(
                                        ElementId::NamedInteger("ac-w-ev".into(), i as u64),
                                        t("accounts.showEvents"),
                                        move |_, cx| {
                                            let _ = weak.update(cx, |this, cx| {
                                                this.selected = events.first().cloned().map(Sel::Event);
                                                this.only = Some((events.clone(), filter_title.clone()));
                                                this.all_events = false;
                                                cx.notify();
                                            });
                                        },
                                        &tk,
                                    ))
                                }),
                        ),
                );
            }
        }
        page = page.child(look);
        let main = div()
            .flex()
            .flex_col()
            .gap_3()
            .child(self.accounts_section(&d, cx, &tk))
            .child(self.group_section(&d, "administrators", "administrators", cx, &tk))
            .child(self.group_section(&d, "rdp", "remote_desktop_users", cx, &tk))
            .child(self.sessions_section(&d, cx, &tk))
            .child(self.activity_section(&d, cx, &tk));
        let side: AnyElement = div()
            .flex()
            .flex_col()
            .gap_2()
            .child(self.side(&d, &tk))
            .when(!self.ctx.elevated, |this| {
                this.child(kit::faint(t("accounts.adminNote"), &tk))
            })
            .into_any_element();
        let wide = f32::from(window.viewport_size().width) >= 1100.;
        page = if wide {
            page.child(
                div()
                    .flex()
                    .gap_3()
                    .items_start()
                    .child(main.flex_1().min_w_0())
                    .child(div().w(px(340.)).flex_none().child(side)),
            )
        } else {
            page.child(main).child(side)
        };
        let signins = d.at("signins");
        let read = if signins.has("readMs") {
            signins.i("readMs")
        } else {
            crate::format::now_ms()
        };
        let mut footer = tf("accounts.footer", &[("when", &when_ms(read))]);
        if signins.b("truncated") {
            footer = format!("{footer} · {}", t("accounts.truncated"));
        }
        let unread = signins.strs("unreadLogs");
        if !unread.is_empty() {
            footer = format!("{footer} · {}", tf("accounts.unread", &[("logs", &unread.join(", "))]));
        }
        let errors = d.strs("errors");
        if !errors.is_empty() {
            footer = format!("{footer} · {}", errors.join(" · "));
        }
        page.child(kit::faint(footer, &tk))
    }
}
