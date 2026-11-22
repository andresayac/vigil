//! Security posture: the score, then each Windows security setting by group with its state, what
//! it means and the fix Vigil can apply (checked against a fresh read and confirmed natively).

use std::sync::Arc;

use gpui_kit::prelude::FluentBuilder as _;
use gpui_kit::{Context, ElementId, Hsla, IntoElement, ParentElement, Render, Styled, Window, div, px, relative};
use serde_json::{Value, json};
use vigil_core::state::AppState;

use crate::app::Ctx;
use crate::data::{self, Src};
use crate::format::num;
use crate::i18n::{t, t_or, tf, tn};
use crate::icons;
use crate::pages::common::{self, Acting, Acts};
use crate::theme::{Tokens, tokens};
use crate::ui;
use crate::ui::kit::{self, J as _};

const GROUPS: [&str; 6] = ["device", "data", "signin", "network", "apps", "protection"];

pub struct PosturePage {
    ctx: Ctx,
    data: Option<Value>,
    loading: bool,
    error: Option<String>,
    acting: Acting,
}

impl Acts for PosturePage {
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

fn fix_label(op: &str) -> String {
    t(match op {
        "uac-default" => "posture.fix.uacDefault",
        "rdp-nla" => "posture.fix.rdpNla",
        "autorun-off" => "posture.fix.autorunOff",
        "driver-blocklist-on" | "lsa-on" => "posture.fix.turnOn",
        _ => "posture.fix.turnOff",
    })
}

fn open_label(target: &str) -> String {
    match target {
        "page:firewall" => tf("posture.openPage", &[("page", &t("page.firewall"))]),
        "page:protection" => tf("posture.openPage", &[("page", &t("page.protection"))]),
        _ => t("posture.openSettings"),
    }
}

fn look(c: &Value, tk: &Tokens) -> (char, Option<Hsla>) {
    match c.s("state") {
        "on" => (icons::CHECK, Some(tk.ok)),
        "partial" => (icons::WARNING, Some(tk.warn)),
        "off" if c.n("weight") >= 2.0 => (icons::ERROR, Some(tk.bad)),
        "off" => (icons::WARNING, Some(tk.warn)),
        "unknown" => ('\u{E9CE}', None),
        _ => ('\u{E738}', None),
    }
}

fn value_key(id: &str, detail: &str) -> Option<&'static str> {
    Some(match (id, detail) {
        ("secure_boot", "legacy_bios") => "posture.value.legacyBios",
        ("memory_integrity", "pending_restart") | ("credential_guard", "pending_restart") => {
            "posture.value.afterRestart"
        }
        ("credential_guard", "edition") | ("rdp", "edition") => "posture.value.notInEdition",
        ("driver_blocklist", "default") => "posture.value.onDefault",
        ("bitlocker", "data_drives") => "posture.value.systemDriveOnly",
        ("bitlocker", "encrypting") => "posture.value.encrypting",
        ("bitlocker", "suspended") => "posture.value.suspended",
        ("bitlocker", "not_available") | ("defender", "unavailable") => "posture.value.notAvailable",
        ("bitlocker", "needs_admin") => "posture.value.needsAdmin",
        ("uac", "") => "posture.value.uacDefault",
        ("uac", "always") => "posture.value.uacAlways",
        ("uac", "no_dimming") => "posture.value.uacNoDimming",
        ("uac", "never_notify") => "posture.value.uacNever",
        ("rdp", "closed") | ("smb1", "disabled") | ("smb1", "driver_off") | ("powershell2", "disabled") => "common.off",
        ("rdp", "open_nla") => "posture.value.rdpNla",
        ("rdp", "open_no_nla") => "posture.value.rdpNoNla",
        ("remote_registry", "disabled") => "posture.value.serviceDisabled",
        ("remote_registry", "manual") => "posture.value.serviceManual",
        ("remote_registry", "running") => "posture.value.serviceRunning",
        ("remote_registry", "automatic") => "posture.value.serviceAutomatic",
        ("remote_registry", "missing") => "posture.value.notInstalled",
        ("smb1", "removed") | ("powershell2", "removed") => "posture.value.removed",
        ("smb1", "enabled") => "common.on",
        ("smb1", "client") => "posture.value.smb1Client",
        ("firewall", "") => "posture.value.allProfiles",
        ("powershell2", "enabled") => "posture.value.installed",
        ("autorun", "") => "posture.value.autorunOff",
        ("autorun", "default") => "posture.value.windowsDefault",
        ("autorun", "some_drives") => "posture.value.autorunSome",
        ("autorun", "all_drives") => "posture.value.autorunOn",
        ("defender", "") => "posture.value.defenderOn",
        ("defender", "realtime_off") => "posture.value.realtimeOff",
        ("defender_updates", "other") => "posture.value.otherAntivirus",
        ("defender_updates", "unavailable") => "posture.value.notApplicable",
        ("windows_update", "no_record") => "posture.value.noRecord",
        _ => return None,
    })
}

fn note_key(id: &str, detail: &str) -> Option<&'static str> {
    Some(match (id, detail) {
        ("secure_boot", "legacy_bios") => "posture.note.legacyBios",
        ("secure_boot", "uefi_off") => "posture.note.secureBootOff",
        ("tpm", "old_version") => "posture.note.tpmOld",
        ("tpm", "absent") => "posture.note.tpmAbsent",
        ("memory_integrity", "pending_restart") | ("credential_guard", "pending_restart") => {
            "posture.note.afterRestart"
        }
        ("memory_integrity", "") => "posture.note.memoryIntegrityOff",
        ("lsa", "old_windows") => "posture.note.lsaOldWindows",
        ("bitlocker", "needs_admin") => "posture.note.bitlockerAdmin",
        ("bitlocker", "data_drives") => "posture.note.dataDrives",
        ("bitlocker", "suspended") => "posture.note.suspended",
        ("bitlocker", "not_available") => "posture.note.bitlockerMissing",
        ("uac", "never_notify") | ("uac", "disabled") => "posture.note.uacSilent",
        ("uac", "no_dimming") => "posture.note.uacNoDimming",
        ("rdp", "open_no_nla") => "posture.note.rdpNoNla",
        ("smb1", "client") => "posture.note.smb1Client",
        ("autorun", "default") => "posture.note.autorunDefault",
        ("defender", "other") => "posture.note.otherAntivirus",
        ("windows_update", "no_record") => "posture.note.noUpdateRecord",
        _ => return None,
    })
}

fn value(c: &Value) -> String {
    let (id, state, detail, facts) = (c.s("id"), c.s("state"), c.s("detail"), c.at("facts"));
    if state == "unknown" && !matches!(detail, "needs_admin" | "no_record") {
        return t("posture.value.unknown");
    }
    match id {
        "tpm" => {
            return if state == "off" {
                t("posture.value.notFound")
            } else {
                tf("posture.value.tpm", &[("version", facts.s("version"))])
            };
        }
        "firewall" if state == "off" => {
            let profiles: Vec<String> = facts
                .s("profiles")
                .split(',')
                .map(str::trim)
                .filter(|p| !p.is_empty())
                .map(|p| t_or(&format!("posture.profile.{p}"), p))
                .collect();
            return tf("posture.value.offFor", &[("profiles", &profiles.join(", "))]);
        }
        "smartscreen" => {
            let base = t(if state == "off" { "common.off" } else { "common.on" });
            return if detail == "policy" {
                tf("posture.value.withPolicy", &[("value", &base)])
            } else {
                base
            };
        }
        "defender" if detail == "other" => return facts.s("names").to_string(),
        "defender_updates" if !facts.at("days").is_null() => {
            let days = kit::text(facts.at("days")).parse::<u64>().unwrap_or(0);
            return if days == 0 {
                t("posture.value.updatedToday")
            } else {
                tn("posture.value.daysOld", days, &[])
            };
        }
        "windows_update" if !facts.at("days").is_null() => {
            let days = kit::text(facts.at("days")).parse::<u64>().unwrap_or(0);
            return if days == 0 {
                t("posture.value.today")
            } else {
                tn("posture.value.daysAgo", days, &[])
            };
        }
        _ => {}
    }
    if let Some(key) = value_key(id, detail) {
        return t(key);
    }
    match state {
        "na" => t("posture.value.notApplicable"),
        "off" => t("common.off"),
        "partial" => t("posture.value.partly"),
        _ => t("common.on"),
    }
}

fn note(c: &Value) -> String {
    let (id, state, detail) = (c.s("id"), c.s("state"), c.s("detail"));
    if state == "on" && id != "defender" {
        return String::new();
    }
    if let Some(key) = note_key(id, detail) {
        return tf(key, &[("drives", c.at("facts").s("drives"))]);
    }
    if id == "windows_update" && matches!(state, "off" | "partial") {
        return t("posture.note.updateOld");
    }
    String::new()
}

fn drive(v: &Value) -> String {
    let state = if v.s("protection") == "on" {
        t("posture.drive.protected")
    } else {
        match v.s("encryption") {
            e @ ("encrypted" | "decrypted" | "encrypting" | "decrypting" | "paused") => {
                t(&format!("posture.drive.{e}"))
            }
            _ => t("posture.value.unknown"),
        }
    };
    let letter = v.s("letter").trim_end_matches(':');
    let name = if letter.is_empty() {
        t("posture.drive.noLetter")
    } else {
        letter.to_string()
    };
    let kind = match v.s("kind") {
        "os" => t("posture.drive.system"),
        "removable" => t("posture.drive.removable"),
        _ => String::new(),
    };
    if kind.is_empty() {
        tf("posture.drive.line", &[("name", &name), ("state", &state)])
    } else {
        tf(
            "posture.drive.lineKind",
            &[("name", &name), ("kind", &kind), ("state", &state)],
        )
    }
}

impl PosturePage {
    pub fn new(ctx: Ctx, cx: &mut Context<Self>) -> Self {
        let mut page = Self {
            ctx,
            data: None,
            loading: false,
            error: None,
            acting: Acting::default(),
        };
        page.load(cx);
        page
    }

    fn load(&mut self, cx: &mut Context<Self>) {
        self.loading = true;
        let core = self.ctx.core.clone();
        common::read(
            cx,
            move || data::fetch(core.as_ref(), Src::Posture),
            |this: &mut Self, result, _| {
                this.loading = false;
                match result {
                    Ok(v) => this.data = Some(v),
                    Err(e) => this.error = Some(e),
                }
            },
        );
    }

    fn open(&mut self, target: &str, window: &mut Window, cx: &mut Context<Self>) {
        if let Some(page) = target.strip_prefix("page:") {
            self.ctx.go(page, window, cx);
        } else if let Some(name) = target.strip_prefix("tool:") {
            common::send_json(self, json!({"kind": "shell", "op": "tool", "name": name}), window, cx);
        } else {
            common::send_json(self, json!({"kind": "shell", "op": "url", "url": target}), window, cx);
        }
    }
}

impl Render for PosturePage {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let tk = *tokens(cx);
        let data = self.data.clone().unwrap_or(Value::Null);
        let checks = data.a("checks");
        let elevated = self.ctx.elevated;
        let busy = self.acting.busy;
        let mut page = kit::page("posture")
            .child(
                kit::row()
                    .child(ui::page_title(t("page.posture")))
                    .child(div().flex_1())
                    .child(ui::command("po-open", '\u{E8A7}', t("posture.openSecurity")).on_click(
                        cx.listener(|this, _, window, cx| this.open("windowsdefender://devicesecurity", window, cx)),
                    ))
                    .child(ui::separator(&tk))
                    .child(
                        ui::command("po-refresh", icons::REFRESH, t("common.refresh"))
                            .disabled(self.loading)
                            .on_click(cx.listener(|this, _, _, cx| this.load(cx))),
                    ),
            )
            .child(kit::muted(t("posture.lead"), &tk))
            .children(self.acting.bar("po-result", &tk));
        let score = data.at("score");
        let mut summary = kit::panel(&tk);
        if score.is_object() {
            let counted = score.n("counted");
            let share = |v: f64| if counted > 0.0 { (v / counted) as f32 } else { 0.0 };
            summary = summary
                .child(
                    div()
                        .flex()
                        .items_end()
                        .gap_1()
                        .child(
                            div()
                                .text_size(px(44.))
                                .font_weight(gpui_kit::FontWeight::SEMIBOLD)
                                .child(num(score.n("percent"), 0)),
                        )
                        .child(div().pb(px(10.)).text_size(px(20.)).text_color(tk.ink2).child("%")),
                )
                .child(kit::h2(tn(
                    "posture.scoreTitle",
                    counted as u64,
                    &[("on", &num(score.n("on"), 0))],
                )))
                .child(
                    div()
                        .flex()
                        .w_full()
                        .max_w(px(520.))
                        .h(px(6.))
                        .rounded(px(3.))
                        .bg(tk.sunken)
                        .overflow_hidden()
                        .child(div().h_full().w(relative(share(score.n("on")))).bg(tk.ok))
                        .child(div().h_full().w(relative(share(score.n("partial")))).bg(tk.warn))
                        .child(div().h_full().w(relative(share(score.n("off")))).bg(tk.bad)),
                )
                .child(kit::muted(
                    tf(
                        "posture.scoreParts",
                        &[
                            ("partial", &num(score.n("partial"), 0)),
                            ("off", &num(score.n("off"), 0)),
                        ],
                    ),
                    &tk,
                ))
                .child(kit::faint(t("posture.scoreFormula"), &tk));
        } else if self.loading {
            summary = summary.child(kit::muted(t("common.reading"), &tk));
        }
        if let Some(e) = &self.error {
            summary = summary.child(kit::colored(e.clone(), tk.bad));
        }
        page = page.child(summary);
        if !elevated && checks.iter().any(|c| c.b("needsAdmin") || !c.a("fixes").is_empty()) {
            page = page.child(kit::faint(t("posture.adminNote"), &tk));
        }
        let mut n = 0u64;
        for group in GROUPS {
            let members: Vec<&Value> = checks.iter().filter(|c| c.s("group") == group).collect();
            if members.is_empty() {
                continue;
            }
            let mut card = kit::panel(&tk).child(kit::h2(t(&format!("posture.group.{group}"))));
            for c in members {
                n += 1;
                let (g, color) = look(c, &tk);
                let id = c.s("id");
                let mut text = div()
                    .flex_1()
                    .min_w_0()
                    .flex()
                    .flex_col()
                    .child(kit::body(t_or(&format!("posture.name.{id}"), id)).text_size(px(14.)))
                    .child(kit::faint(t_or(&format!("posture.about.{id}"), ""), &tk));
                let note = note(c);
                if !note.is_empty() {
                    text = text.child(kit::muted(note, &tk));
                }
                if id == "bitlocker" {
                    text = text.children(data.a("volumes").iter().map(|v| kit::faint(drive(v), &tk)));
                }
                let colored = !matches!(c.s("state"), "unknown" | "na");
                let mut actions = kit::row().justify_end().w(px(230.)).flex_none();
                for (i, op) in c.strs("fixes").into_iter().enumerate() {
                    let op_owned = op.to_string();
                    let id = ElementId::Name(format!("po-fix-{n}-{i}").into());
                    let button = if i == 0 {
                        ui::accent_button(id, fix_label(op))
                    } else {
                        ui::button(id, fix_label(op))
                    };
                    actions = actions.child(
                        button
                            .disabled(!elevated || busy)
                            .when(!elevated, |b| b.tip(t("posture.needsAdmin")))
                            .on_click(cx.listener(move |this, _, window, cx| {
                                common::send_json(this, json!({"kind": "posture", "op": op_owned}), window, cx)
                            })),
                    );
                }
                if c.has("open") {
                    let target = c.s("open").to_string();
                    actions = actions.child(
                        ui::button(ElementId::Name(format!("po-open-{n}").into()), open_label(&target))
                            .on_click(cx.listener(move |this, _, window, cx| this.open(&target, window, cx))),
                    );
                }
                card = card.child(
                    div()
                        .flex()
                        .gap_3()
                        .items_start()
                        .py_2()
                        .border_t_1()
                        .border_color(tk.rule)
                        .child(
                            div()
                                .w(px(20.))
                                .pt(px(2.))
                                .child(kit::glyph(g, 16., color.unwrap_or(tk.ink3))),
                        )
                        .child(text)
                        .child(
                            div()
                                .w(px(200.))
                                .flex_none()
                                .text_size(px(13.))
                                .when_some(color.filter(|_| colored), |this, c| this.text_color(c))
                                .child(kit::sel(ElementId::Name(format!("po-v-{n}").into()), value(c))),
                        )
                        .child(actions),
                );
            }
            page = page.child(card);
        }
        page
    }
}
