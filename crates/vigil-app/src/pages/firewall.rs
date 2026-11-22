//! Firewall rules: the profiles, every rule with filters (flagged, open to the internet, remote
//! access, missing program, Vigil's, direction, disabled), a search and the selected rule's
//! details; enable, disable and delete go through the action service.

use std::sync::Arc;

use gpui_kit::component::input::InputState;
use gpui_kit::component::table::TableState;
use gpui_kit::prelude::FluentBuilder as _;
use gpui_kit::{
    Context, ElementId, Entity, FocusHandle, InteractiveElement as _, IntoElement, ParentElement, Render,
    StatefulInteractiveElement as _, Styled, Subscription, Window, div, px,
};
use serde_json::{Value, json};
use vigil_core::state::AppState;

use crate::app::Ctx;
use crate::data::{self, Src};
use crate::i18n::{t, tf};
use crate::icons;
use crate::pages::common::{self, Acting, Acts};
use crate::theme::{Tokens, tokens};
use crate::ui;
use crate::ui::grid::{self, Grid, GridCell, GridCol, GridRow};
use crate::ui::kit::{self, J as _};

const CHIPS: [(&str, &str); 9] = [
    ("all", "firewall.chipAll"),
    ("flagged", "firewall.chipFlagged"),
    ("open", "firewall.chipOpen"),
    ("remote", "firewall.chipRemote"),
    ("missing", "firewall.chipMissing"),
    ("vigil", "firewall.chipVigil"),
    ("in", "firewall.inbound"),
    ("out", "firewall.outbound"),
    ("disabled", "firewall.chipDisabled"),
];

pub struct FirewallPage {
    ctx: Ctx,
    data: Option<Value>,
    filter: &'static str,
    loading: bool,
    error: Option<String>,
    table: Entity<TableState<Grid>>,
    search: Entity<InputState>,
    acting: Acting,
    focus: FocusHandle,
    _subscriptions: Vec<Subscription>,
}

impl Acts for FirewallPage {
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

fn row_id(rule: &Value, index: usize) -> String {
    if rule.b("duplicate") {
        format!("{}#{index}", rule.s("key"))
    } else {
        rule.s("key").to_string()
    }
}

fn has_flag(rule: &Value, code: &str) -> bool {
    rule.a("flags").iter().any(|f| f.s("code") == code)
}

fn warned(rule: &Value) -> bool {
    rule.a("flags").iter().any(|f| f.b("warn"))
}

fn chip_test(chip: &str, r: &Value) -> bool {
    match chip {
        "flagged" => warned(r),
        "open" => has_flag(r, "open_public"),
        "remote" => has_flag(r, "remote_access"),
        "missing" => has_flag(r, "missing_program"),
        "vigil" => r.b("vigil"),
        "in" => r.s("direction") == "in",
        "out" => r.s("direction") == "out",
        "disabled" => !r.b("enabled"),
        _ => true,
    }
}

fn any_value(s: &str) -> bool {
    let s = s.trim();
    s.is_empty() || s == "*" || s.eq_ignore_ascii_case("any")
}

fn flag_text(f: &Value) -> String {
    match f.s("code") {
        "open_public" => t("firewall.flagOpen"),
        "remote_access" => {
            let port = f.i("port");
            let service = match port {
                3389 => t("firewall.svcRdp"),
                22 => "SSH".into(),
                23 => "Telnet".into(),
                5900 => "VNC".into(),
                5985 | 5986 => "WinRM".into(),
                _ => String::new(),
            };
            tf(
                "firewall.flagRemote",
                &[("port", &port.to_string()), ("service", &service)],
            )
        }
        "writable_program" => t("firewall.flagWritable"),
        _ => t("firewall.flagMissing"),
    }
}

fn program_text(r: &Value) -> String {
    if r.has("program") {
        r.s("program").to_string()
    } else if r.has("service") {
        tf("firewall.service", &[("name", r.s("service"))])
    } else {
        t("firewall.allPrograms")
    }
}

fn ports_text(r: &Value) -> String {
    let ports = if r.s("direction") == "out" {
        r.s("remotePorts")
    } else {
        r.s("localPorts")
    };
    if any_value(ports) {
        if r.i("protocol") == 256 {
            t("firewall.any")
        } else {
            r.s("protocolName").to_string()
        }
    } else {
        let list: Vec<&str> = ports.split(',').map(str::trim).collect();
        format!("{} {}", r.s("protocolName"), list.join(", "))
    }
}

fn address_text(v: &str) -> String {
    if any_value(v) {
        t("firewall.any")
    } else {
        v.replace(',', ", ")
    }
}

fn profiles_text(r: &Value) -> String {
    let profiles = r.strs("profiles");
    if profiles.len() >= 3 {
        return t("firewall.allProfiles");
    }
    profiles
        .iter()
        .map(|p| match *p {
            "domain" => t("firewall.pDomain"),
            "private" => t("firewall.pPrivate"),
            "public" => t("firewall.pPublic"),
            _ => t("firewall.any"),
        })
        .collect::<Vec<_>>()
        .join(", ")
}

impl FirewallPage {
    pub fn new(ctx: Ctx, window: &mut Window, cx: &mut Context<Self>) -> Self {
        let cols = vec![
            GridCol::new("name", t("firewall.colName"), 280.),
            GridCol::new("program", t("firewall.colProgram"), 240.),
            GridCol::new("direction", t("firewall.colDirection"), 90.),
            GridCol::new("action", t("firewall.colAction"), 70.),
            GridCol::new("ports", t("firewall.colPorts"), 120.),
            GridCol::new("remote", t("firewall.colRemote"), 130.),
            GridCol::new("profiles", t("firewall.colProfiles"), 110.),
            GridCol::new("enabled", t("firewall.colEnabled"), 70.),
        ];
        let table = grid::new_state(t("firewall.empty"), cols, window, cx);
        let (search, searching) = grid::search(&table, t("firewall.search"), window, cx);
        let subscriptions = vec![searching, cx.observe(&table, |_, _, cx| cx.notify())];
        let mut page = Self {
            ctx,
            data: None,
            filter: "all",
            loading: false,
            error: None,
            table,
            search,
            acting: Acting::default(),
            focus: cx.focus_handle(),
            _subscriptions: subscriptions,
        };
        window.focus(&page.focus, cx);
        page.load(cx);
        page
    }

    fn load(&mut self, cx: &mut Context<Self>) {
        self.loading = true;
        let core = self.ctx.core.clone();
        common::read(
            cx,
            move || data::fetch(core.as_ref(), Src::Firewall),
            |this: &mut Self, result, cx| {
                this.loading = false;
                match result {
                    Ok(v) => {
                        this.data = Some(v);
                        this.error = None;
                    }
                    Err(e) => this.error = Some(e),
                }
                this.fill(cx);
            },
        );
    }

    fn fill(&mut self, cx: &mut Context<Self>) {
        let tk = *tokens(cx);
        let rules = self.data.as_ref().map(|d| d.a("rules").to_vec()).unwrap_or_default();
        let mut ordered: Vec<(usize, &Value)> = rules.iter().enumerate().collect();
        ordered.sort_by_key(|(_, r)| (!warned(r), r.s("name").to_lowercase()));
        let rows = ordered
            .into_iter()
            .filter(|(_, r)| chip_test(self.filter, r))
            .map(|(i, r)| {
                let warn = warned(r);
                let mut name = GridCell::text(r.s("name")).ranked(if warn { 0.0 } else { 1.0 });
                name.sort = grid::SortKey::Text(format!("{}{}", if warn { 0 } else { 1 }, r.s("name").to_lowercase()));
                if warn {
                    name = name.glyph(icons::WARNING, tk.warn);
                } else if !r.a("flags").is_empty() {
                    name = name.glyph(icons::INFO, tk.ink3);
                }
                let dim = !r.b("enabled");
                let cells = vec![
                    name,
                    GridCell::text(program_text(r)),
                    GridCell::text(t(if r.s("direction") == "out" {
                        "firewall.outbound"
                    } else {
                        "firewall.inbound"
                    })),
                    GridCell::text(t(if r.s("action") == "allow" {
                        "firewall.allow"
                    } else {
                        "firewall.block"
                    })),
                    GridCell::text(ports_text(r)),
                    GridCell::text(address_text(r.s("remoteAddresses"))),
                    GridCell::text(profiles_text(r)),
                    GridCell::text(t(if r.b("enabled") { "common.yes" } else { "common.no" }))
                        .ranked(if r.b("enabled") { 0.0 } else { 1.0 }),
                ];
                let search = format!(
                    "{} {} {} {} {} {} {} {}",
                    r.s("name"),
                    r.s("group"),
                    r.s("program"),
                    r.s("service"),
                    r.s("localPorts"),
                    r.s("remotePorts"),
                    r.s("remoteAddresses"),
                    r.s("description")
                );
                let mut row = GridRow::new(row_id(r, i), cells, search);
                row.dim = dim;
                row
            })
            .collect();
        grid::fill(&self.table, rows, cx);
    }

    fn current(&self, cx: &gpui_kit::App) -> Option<Value> {
        let key = grid::selected(&self.table, cx)?;
        let rules = self.data.as_ref()?.a("rules");
        rules
            .iter()
            .enumerate()
            .find(|(i, r)| row_id(r, *i) == key)
            .map(|(_, r)| r.clone())
    }

    fn run(&mut self, op: &str, window: &mut Window, cx: &mut Context<Self>) {
        let Some(rule) = self.current(cx) else { return };
        common::send_json(
            self,
            json!({"kind": "firewall-rule", "op": op, "key": rule.s("key")}),
            window,
            cx,
        );
    }

    fn info(&self, rule: &Value, tk: &Tokens) -> gpui_kit::Div {
        let mut panel = kit::panel(tk).child(kit::row().child(kit::h3(rule.s("name").to_string())).child(kit::faint(
            format!(
                "{} · {} · {}",
                t(if rule.s("direction") == "out" {
                    "firewall.outbound"
                } else {
                    "firewall.inbound"
                }),
                t(if rule.s("action") == "allow" {
                    "firewall.allow"
                } else {
                    "firewall.block"
                }),
                t(if rule.b("enabled") {
                    "common.enabled"
                } else {
                    "common.disabled"
                })
            ),
            tk,
        )));
        for f in rule.a("flags") {
            let (g, c) = if f.b("warn") {
                (icons::WARNING, tk.warn)
            } else {
                (icons::INFO, tk.ink2)
            };
            panel = panel.child(
                kit::row()
                    .child(kit::glyph(g, 14., c))
                    .child(kit::colored(flag_text(f), c)),
            );
        }
        if rule.has("description") {
            panel = panel.child(kit::muted(rule.s("description").to_string(), tk));
        }
        let mut program = if rule.has("program") {
            rule.s("program").to_string()
        } else {
            t("firewall.allPrograms")
        };
        if rule.has("program") && !rule.b("programExists") {
            program = format!("{program} · {}", t("firewall.notFound"));
        }
        let mut facts = vec![
            (t("firewall.program"), program),
            (
                t("firewall.group"),
                if rule.has("group") {
                    rule.s("group").to_string()
                } else {
                    "—".into()
                },
            ),
        ];
        if rule.has("service") {
            facts.push((t("firewall.serviceLabel"), rule.s("service").to_string()));
        }
        facts.push((
            t("firewall.protocol"),
            if rule.i("protocol") == 256 {
                t("firewall.any")
            } else {
                rule.s("protocolName").to_string()
            },
        ));
        for (key, field) in [
            ("firewall.localPorts", "localPorts"),
            ("firewall.remotePorts", "remotePorts"),
            ("firewall.localAddresses", "localAddresses"),
            ("firewall.remoteAddresses", "remoteAddresses"),
        ] {
            facts.push((t(key), address_text(rule.s(field))));
        }
        facts.push((t("firewall.colProfiles"), profiles_text(rule)));
        let interfaces = rule.s("interfaceTypes");
        facts.push((
            t("firewall.interfaces"),
            if any_value(interfaces) || interfaces == "All" {
                t("firewall.any")
            } else {
                interfaces.to_string()
            },
        ));
        if rule.b("edgeTraversal") {
            facts.push((t("firewall.edge"), t("firewall.edgeOn")));
        }
        for (i, (k, v)) in facts.into_iter().enumerate() {
            panel = panel.child(kit::kv_text(
                ElementId::NamedInteger("fw-f".into(), i as u64),
                k,
                v,
                false,
                130.,
                tk,
            ));
        }
        for (flag, key) in [
            ("duplicate", "firewall.duplicateNote"),
            ("builtin", "firewall.builtinNote"),
            ("appPackage", "firewall.packageNote"),
            ("vigil", "firewall.vigilNote"),
        ] {
            if rule.has(flag) {
                panel = panel.child(kit::faint(t(key), tk));
            }
        }
        if !self.ctx.elevated {
            panel = panel.child(kit::faint(t("firewall.adminNote"), tk));
        }
        panel
    }
}

impl Render for FirewallPage {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let tk = *tokens(cx);
        let data = self.data.clone().unwrap_or(Value::Null);
        let rules = data.a("rules");
        let current = self.current(cx);
        let actionable = current.as_ref().is_some_and(|r| !r.b("duplicate")) && self.ctx.elevated && !self.acting.busy;
        let enabled = current.as_ref().is_some_and(|r| r.b("enabled"));
        let builtin = current.as_ref().is_some_and(|r| r.b("builtin"));
        let location = current
            .as_ref()
            .filter(|r| r.b("programExists"))
            .map(|r| r.s("program").to_string())
            .filter(|p| p.len() > 2 && p.as_bytes()[1] == b':' && p.as_bytes()[0].is_ascii_alphabetic())
            .unwrap_or_default();
        let mut chips = kit::row();
        for (key, label) in CHIPS {
            let n = rules.iter().filter(|r| chip_test(key, r)).count();
            if key != "all" && n == 0 {
                continue;
            }
            let weak = cx.entity().downgrade();
            chips = chips.child(kit::chip(
                ElementId::Name(format!("fw-chip-{key}").into()),
                t(label),
                Some(n),
                self.filter == key,
                false,
                move |_, cx| {
                    let _ = weak.update(cx, |this, cx| {
                        this.filter = key;
                        this.fill(cx);
                    });
                },
                &tk,
            ));
        }
        let profiles = data.a("profiles");
        let mut cards = div().flex().flex_wrap().gap_3();
        for p in profiles {
            let name = match p.s("name") {
                "domain" => t("firewall.profileDomain"),
                "private" => t("firewall.profilePrivate"),
                _ => t("firewall.profilePublic"),
            };
            let (g, c, state) = if p.b("enabled") {
                (icons::CHECK, tk.ok, t("firewall.profileOn"))
            } else {
                (icons::CANCEL, tk.bad, t("firewall.profileOff"))
            };
            let action = |v: &str| {
                t(if v == "allow" {
                    "firewall.allow"
                } else {
                    "firewall.block"
                })
            };
            let inbound = if p.b("blockAllInbound") {
                kit::faint(t("firewall.blockAll"), &tk)
            } else {
                let text = tf("firewall.incoming", &[("action", &action(p.s("defaultInbound")))]);
                let warn = p.b("enabled") && p.s("defaultInbound") == "allow";
                kit::faint(text, &tk).when(warn, |this| this.text_color(tk.warn))
            };
            cards = cards.child(
                kit::panel(&tk)
                    .min_w(px(220.))
                    .flex_1()
                    .gap_1()
                    .child(
                        kit::row()
                            .child(kit::body(name).font_weight(gpui_kit::FontWeight::SEMIBOLD))
                            .when(p.b("active"), |this| {
                                this.child(kit::faint(t("firewall.connected"), &tk))
                            }),
                    )
                    .child(
                        kit::row()
                            .gap_1()
                            .child(kit::glyph(g, 14., c))
                            .child(kit::colored(state, c)),
                    )
                    .child(kit::row().gap_1().child(inbound).child(kit::faint(
                        format!(
                            "· {}",
                            tf("firewall.outgoing", &[("action", &action(p.s("defaultOutbound")))])
                        ),
                        &tk,
                    ))),
            );
        }
        let summary = data.at("summary");
        let shown = self.table.read(cx).delegate().row_count();
        let footer = match &self.error {
            Some(e) => e.clone(),
            None => tf(
                "firewall.summary",
                &[
                    ("shown", &shown.to_string()),
                    ("total", &rules.len().to_string()),
                    ("flagged", &(summary.n("flagged") as u64).to_string()),
                    ("missing", &(summary.n("missing") as u64).to_string()),
                ],
            ),
        };
        let root = div()
            .track_focus(&self.focus)
            .size_full()
            .flex()
            .flex_col()
            .gap_2()
            .px(px(20.))
            .pt(px(12.))
            .pb(px(12.));
        common::list_keys(root, |p: &FirewallPage| p.table.clone(), cx)
            .child(
                div()
                    .flex()
                    .justify_center()
                    .child(div().w_full().max_w(px(640.)).child(ui::search_box(&self.search, &tk))),
            )
            .child(
                kit::row().child(ui::page_title(t("page.firewall"))).child(
                    ui::CommandBar::new("fw-bar")
                        .cmd(
                            ui::cmd("fw-enable", icons::CHECK, t("firewall.enable"))
                                .disabled(!(actionable && !enabled))
                                .on_click(cx.listener(|this, _, window, cx| this.run("enable", window, cx))),
                        )
                        .cmd(
                            ui::cmd("fw-disable", icons::END_TASK, t("firewall.disable"))
                                .disabled(!(actionable && enabled))
                                .on_click(cx.listener(|this, _, window, cx| this.run("disable", window, cx))),
                        )
                        .cmd(
                            ui::cmd("fw-delete", icons::DELETE, t("firewall.delete"))
                                .disabled(!(actionable && !builtin))
                                .on_click(cx.listener(|this, _, window, cx| this.run("delete", window, cx))),
                        )
                        .separator()
                        .cmd({
                            let path = location.clone();
                            ui::cmd("fw-location", icons::FOLDER, t("proc.location"))
                                .disabled(location.is_empty())
                                .on_click(cx.listener(move |this, _, window, cx| {
                                    common::send_json(
                                        this,
                                        json!({"kind": "shell", "op": "location", "path": path}),
                                        window,
                                        cx,
                                    )
                                }))
                        })
                        .cmd(
                            ui::cmd("fw-console", '\u{E8A7}', t("firewall.openConsole")).on_click(cx.listener(
                                |this, _, window, cx| {
                                    common::send_json(
                                        this,
                                        json!({"kind": "shell", "op": "console", "name": "wf.msc"}),
                                        window,
                                        cx,
                                    )
                                },
                            )),
                        )
                        .separator()
                        .cmd(
                            ui::cmd("fw-refresh", icons::REFRESH, t("common.refresh"))
                                .disabled(self.loading)
                                .on_click(cx.listener(|this, _, _, cx| this.load(cx))),
                        ),
                ),
            )
            .child(kit::faint(t("firewall.note"), &tk))
            .children(self.acting.bar("fw-result", &tk))
            .child(cards)
            .child(chips)
            .child(
                grid::frame(&tk)
                    .min_h(px(160.))
                    .child(grid::table(&self.table, t("page.firewall"))),
            )
            .when_some(current, |this, rule| {
                this.child(
                    div()
                        .id("fw-info")
                        .max_h(px(240.))
                        .overflow_y_scroll()
                        .child(self.info(&rule, &tk)),
                )
            })
            .child(kit::faint(footer, &tk))
    }
}
