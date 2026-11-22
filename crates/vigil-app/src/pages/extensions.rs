//! Browser extensions: every extension of every browser profile with what it may do and where it
//! came from, and the browser policies that install or allow extensions. Opening a browser's
//! extensions page or folder and removing a policy go through the action service.

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;

use gpui_kit::component::input::InputState;
use gpui_kit::component::menu::{DropdownMenu as _, PopupMenuItem};
use gpui_kit::component::table::TableState;
use gpui_kit::prelude::FluentBuilder as _;
use gpui_kit::{
    Context, Div, ElementId, Entity, FocusHandle, Image, InteractiveElement as _, IntoElement, ParentElement, Render,
    StatefulInteractiveElement as _, Styled, Subscription, Window, div, px,
};
use serde_json::{Value, json};
use vigil_core::state::AppState;

use crate::app::Ctx;
use crate::data::{self, Src};
use crate::i18n::{t, t_or, tf};
use crate::icons;
use crate::pages::common::{self, Acting, Acts};
use crate::theme::{Tokens, tokens};
use crate::ui::grid::{self, Grid, GridCell, GridCol, GridRow};
use crate::ui::kit::{self, J as _};
use crate::ui::{self, FButton, Kind};

/// Flags that always get the warning colour: a harmful mark, forced by a policy, developer mode, or
/// from outside the store. Broad permissions of a store extension are ordinary and stay grey, so the
/// warnings keep meaning something.
const WARN_FLAGS: [&str; 6] = [
    "store_flagged",
    "delisted",
    "policy",
    "outside_store",
    "unpacked",
    "not_signed",
];

/// Permissions that warn only on an extension from outside the store that also reaches every site.
const RISKY_OUTSIDE: [&str; 2] = ["native", "debugger"];

/// Not installed from the browser's store (another source, developer mode, or unsigned).
fn from_outside(flags: &[&str]) -> bool {
    flags
        .iter()
        .any(|f| matches!(*f, "outside_store" | "unpacked" | "not_signed"))
}

/// Whether one of an extension's flags gets the warning colour.
fn is_warn(flag: &str, flags: &[&str]) -> bool {
    WARN_FLAGS.contains(&flag) || (RISKY_OUTSIDE.contains(&flag) && flags.contains(&"all_sites") && from_outside(flags))
}

const CHIPS: [(&str, &str); 6] = [
    ("all", "ext.chipAll"),
    ("allSites", "ext.chipAllSites"),
    ("outside", "ext.chipOutside"),
    ("policy", "ext.chipPolicy"),
    ("disabled", "ext.chipDisabled"),
    ("mv2", "ext.chipMv2"),
];

const PERMISSIONS: [&str; 18] = [
    "tabs",
    "history",
    "cookies",
    "webRequest",
    "webRequestBlocking",
    "declarativeNetRequest",
    "nativeMessaging",
    "debugger",
    "proxy",
    "management",
    "downloads",
    "clipboardRead",
    "privacy",
    "scripting",
    "webNavigation",
    "topSites",
    "bookmarks",
    "storage",
];

fn camel(snake: &str) -> String {
    let mut out = String::new();
    let mut up = false;
    for c in snake.chars() {
        if c == '_' {
            up = true;
        } else if up {
            out.extend(c.to_uppercase());
            up = false;
        } else {
            out.push(c);
        }
    }
    out
}

/// The flags, the warning ones first, each with whether it warns.
fn ordered_flags(e: &Value) -> Vec<(String, bool)> {
    let flags = e.strs("flags");
    let mut out: Vec<(String, bool)> = flags
        .iter()
        .filter(|f| is_warn(f, &flags))
        .map(|f| (f.to_string(), true))
        .collect();
    out.extend(
        flags
            .iter()
            .filter(|f| !is_warn(f, &flags))
            .map(|f| (f.to_string(), false)),
    );
    out
}

fn has_warn(e: &Value) -> bool {
    let flags = e.strs("flags");
    flags.iter().any(|f| is_warn(f, &flags))
}

fn chip_test(chip: &str, e: &Value) -> bool {
    let flags = e.strs("flags");
    match chip {
        "allSites" => flags.contains(&"all_sites"),
        "outside" => from_outside(&flags),
        "policy" => flags.contains(&"policy"),
        "disabled" => !e.b("enabled"),
        "mv2" => flags.contains(&"mv2"),
        _ => true,
    }
}

fn profile_key(e: &Value) -> String {
    format!("p:{}|{}|{}", e.s("browser"), e.s("account"), e.s("profileDir"))
}

fn profile_label(e: &Value) -> String {
    [e.s("profile"), e.s("account")]
        .iter()
        .filter(|s| !s.is_empty())
        .copied()
        .collect::<Vec<_>>()
        .join(" · ")
}

fn source_text(source: &str) -> String {
    let key = match source {
        "outside_store" => "outsideStore",
        "store" | "external" | "policy" | "unpacked" | "component" => source,
        _ => "unknown",
    };
    t(&format!("ext.source.{key}"))
}

pub struct ExtensionsPage {
    ctx: Ctx,
    data: Option<Value>,
    icons: HashMap<String, Arc<Image>>,
    view_policies: bool,
    chip: &'static str,
    place: String,
    show_components: bool,
    loading: bool,
    error: Option<String>,
    table: Entity<TableState<Grid>>,
    policies: Entity<TableState<Grid>>,
    search: Entity<InputState>,
    acting: Acting,
    focus: FocusHandle,
    _subscriptions: Vec<Subscription>,
}

impl Acts for ExtensionsPage {
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

impl ExtensionsPage {
    pub fn new(ctx: Ctx, window: &mut Window, cx: &mut Context<Self>) -> Self {
        let cols = vec![
            GridCol::new("name", t("ext.colName"), 260.),
            GridCol::new("browser", t("ext.colBrowser"), 90.),
            GridCol::new("profile", t("ext.colProfile"), 140.),
            GridCol::new("version", t("ext.colVersion"), 90.),
            GridCol::new("state", t("ext.colState"), 70.),
            GridCol::new("source", t("ext.colSource"), 140.),
            GridCol::new("flags", t("ext.colFlags"), 240.),
        ];
        let table = grid::new_state(t("ext.empty"), cols, window, cx);
        let pcols = vec![
            GridCol::new("policy", t("ext.colPolicy"), 240.),
            GridCol::new("browser", t("ext.colBrowser"), 90.),
            GridCol::new("scope", t("ext.colAppliesTo"), 110.),
            GridCol::new("kind", t("ext.colKind"), 160.),
            GridCol::new("value", t("ext.colValue"), 320.),
        ];
        let policies = grid::new_state(t("ext.noPolicies"), pcols, window, cx);
        let (search, searching) = grid::search(&table, t("ext.search"), window, cx);
        let policies_for_search = policies.clone();
        let mirror = cx.subscribe(
            &search,
            move |_, input, event: &gpui_kit::component::input::InputEvent, cx| {
                if matches!(event, gpui_kit::component::input::InputEvent::Change) {
                    let text = input.read(cx).value().to_string();
                    policies_for_search.update(cx, |table, cx| {
                        table.delegate_mut().set_filter(&text);
                        table.refresh(cx);
                        cx.notify();
                    });
                }
            },
        );
        let subscriptions = vec![
            searching,
            mirror,
            cx.observe(&table, |_, _, cx| cx.notify()),
            cx.observe(&policies, |_, _, cx| cx.notify()),
        ];
        let mut page = Self {
            ctx,
            data: None,
            icons: HashMap::new(),
            view_policies: false,
            chip: "all",
            place: String::new(),
            show_components: false,
            loading: false,
            error: None,
            table,
            policies,
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
            move || {
                let data = data::fetch(core.as_ref(), Src::Extensions);
                let keys: Vec<String> = data
                    .as_ref()
                    .map(|d| {
                        d.a("extensions")
                            .iter()
                            .filter(|e| e.has("icon"))
                            .map(|e| e.s("key").to_string())
                            .collect()
                    })
                    .unwrap_or_default();
                let icons: HashMap<String, Arc<Image>> = data::fetch(core.as_ref(), Src::ExtensionIcons(keys))
                    .ok()
                    .and_then(|v| v.as_object().cloned())
                    .map(|o| {
                        o.iter()
                            .filter_map(|(k, v)| kit::image(v.as_str()?).map(|i| (k.clone(), i)))
                            .collect()
                    })
                    .unwrap_or_default();
                (data, icons)
            },
            |this: &mut Self, (result, icons), cx| {
                this.loading = false;
                this.icons = icons;
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

    fn visible(&self) -> Vec<Value> {
        self.data
            .as_ref()
            .map(|d| {
                d.a("extensions")
                    .iter()
                    .filter(|e| self.show_components || !e.b("component"))
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    fn in_place(&self, e: &Value) -> bool {
        if self.place.is_empty() {
            true
        } else if let Some(browser) = self.place.strip_prefix("b:") {
            e.s("browser") == browser
        } else {
            profile_key(e) == self.place
        }
    }

    fn place_browser(&self) -> String {
        if self.place.is_empty() {
            return String::new();
        }
        self.place[2..].split('|').next().unwrap_or("").to_string()
    }

    fn fill(&mut self, cx: &mut Context<Self>) {
        let tk = *tokens(cx);
        let rows = self
            .visible()
            .iter()
            .filter(|e| self.in_place(e) && chip_test(self.chip, e))
            .map(|e| {
                let warn = has_warn(e);
                let flags = ordered_flags(e);
                let short: Vec<String> = flags
                    .iter()
                    .map(|(f, _)| t_or(&format!("ext.short.{}", camel(f)), f))
                    .collect();
                let mut name = GridCell::text(e.s("name")).image(self.icons.get(e.s("key")).cloned());
                if warn {
                    name = name.glyph(icons::WARNING, tk.warn);
                }
                // Warnings in the warning colour; ordinary permissions in neutral grey.
                let flag_cell = GridCell::text(short.join(", ")).color(if warn { tk.warn } else { tk.ink2 });
                let cells = vec![
                    name,
                    GridCell::text(e.s("browser")),
                    GridCell::text(profile_label(e)),
                    GridCell::text(e.s("version")),
                    GridCell::text(t(if e.b("enabled") { "common.on" } else { "common.off" }))
                        .ranked(if e.b("enabled") { 0.0 } else { 1.0 }),
                    GridCell::text(source_text(e.s("source"))),
                    flag_cell,
                ];
                let search = format!(
                    "{} {} {} {} {} {}",
                    e.s("name"),
                    e.s("id"),
                    e.s("browser"),
                    e.s("profile"),
                    e.s("description"),
                    e.strs("hosts").join(" ")
                );
                let mut row = GridRow::new(e.s("key").to_string(), cells, search);
                row.dim = !e.b("enabled");
                row
            })
            .collect();
        let any = self.data.as_ref().is_some_and(|d| !d.a("extensions").is_empty());
        self.table.update(cx, |table, _| {
            table
                .delegate_mut()
                .set_empty(t(if any { "ext.empty" } else { "ext.noBrowsers" }))
        });
        grid::fill(&self.table, rows, cx);
        let browser = self.place_browser();
        let mut policies: Vec<Value> = self
            .data
            .as_ref()
            .map(|d| {
                d.a("policies")
                    .iter()
                    .filter(|p| browser.is_empty() || p.s("browser") == browser)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default();
        policies.sort_by_key(|p| {
            (
                !p.b("flagged"),
                p.s("browser").to_string(),
                p.s("name").to_lowercase(),
                p.s("data").to_string(),
            )
        });
        let prows = policies
            .iter()
            .map(|p| {
                let mut name = GridCell::text(p.s("name"));
                if p.b("flagged") {
                    name = name.glyph(icons::WARNING, tk.warn);
                }
                let scope = t(match p.s("scope") {
                    "machine" => "ext.scopeMachine",
                    "user" => "ext.scopeUser",
                    _ => "ext.scopeFile",
                });
                let cells = vec![
                    name,
                    GridCell::text(p.s("browser")),
                    GridCell::text(scope),
                    GridCell::text(t_or(&format!("ext.kind.{}", camel(p.s("kind"))), &t("ext.kind.other"))),
                    GridCell::text(p.s("data")).mono(),
                ];
                let search = format!("{} {} {} {}", p.s("name"), p.s("data"), p.s("browser"), p.s("key"));
                GridRow::new(p.s("id").to_string(), cells, search)
            })
            .collect();
        grid::fill(&self.policies, prows, cx);
    }

    fn current(&self, cx: &gpui_kit::App) -> Option<Value> {
        let key = grid::selected(&self.table, cx)?;
        self.data
            .as_ref()?
            .a("extensions")
            .iter()
            .find(|e| e.s("key") == key)
            .cloned()
    }

    fn current_policy(&self, cx: &gpui_kit::App) -> Option<Value> {
        let id = grid::selected(&self.policies, cx)?;
        self.data
            .as_ref()?
            .a("policies")
            .iter()
            .find(|p| p.s("id") == id)
            .cloned()
    }

    fn send(&mut self, request: Value, window: &mut Window, cx: &mut Context<Self>) {
        common::send_json(self, request, window, cx);
    }

    fn extension_pane(&self, e: &Value, tk: &Tokens) -> Div {
        let mut pane = kit::panel(tk).child(kit::h3(e.s("name").to_string()));
        let line: Vec<String> = [
            e.s("version").to_string(),
            format!("{} · {}", e.s("browser"), profile_label(e)),
        ]
        .into_iter()
        .filter(|s| !s.is_empty())
        .collect();
        pane = pane.child(kit::faint(line.join(" · "), tk));
        if e.has("description") {
            pane = pane.child(kit::body(e.s("description").to_string()));
        }
        for (f, warn) in ordered_flags(e) {
            let (g, c) = if warn {
                (icons::WARNING, tk.warn)
            } else {
                (icons::INFO, tk.ink2)
            };
            pane = pane.child(
                div()
                    .flex()
                    .gap_2()
                    .items_start()
                    .child(div().pt(px(2.)).child(kit::glyph(g, 14., c)))
                    .child(kit::body(t_or(&format!("ext.flag.{}", camel(&f)), &f)).flex_1()),
            );
        }
        let state = if e.b("enabled") {
            t("common.on")
        } else if !e.a("disableReasons").is_empty() {
            e.strs("disableReasons")
                .iter()
                .map(|r| t_or(&format!("ext.reason.{}", camel(r)), &t("ext.reason.other")))
                .collect::<Vec<_>>()
                .join("; ")
        } else {
            t("common.off")
        };
        let installed = if e.i("installedMs") > 0 {
            common::when(&kit::local_iso(e.i("installedMs")))
                .split(' ')
                .next()
                .unwrap_or("")
                .to_string()
        } else {
            "—".into()
        };
        let mut facts: Vec<(String, String, bool)> = vec![
            (t("ext.colState"), state, false),
            (t("ext.installed"), installed, false),
            (t("ext.colSource"), source_text(e.s("source")), false),
        ];
        let id = e.s("id").to_lowercase();
        let forced: Vec<String> = self
            .data
            .as_ref()
            .map(|d| {
                d.a("policies")
                    .iter()
                    .filter(|p| {
                        p.s("browser") == e.s("browser")
                            && p.strs("extensionIds").iter().any(|x| x.to_lowercase() == id)
                    })
                    .map(|p| format!("{}\\{}", p.s("key"), p.s("value")))
                    .collect()
            })
            .unwrap_or_default();
        if !forced.is_empty() {
            facts.push((t("ext.forcedBy"), forced.join("\n"), true));
        }
        facts.push((t("ext.id"), e.s("id").to_string(), true));
        if e.has("updateUrl") {
            facts.push((t("ext.updateUrl"), e.s("updateUrl").to_string(), false));
        }
        if e.n("manifestVersion") > 0.0 {
            facts.push((t("ext.manifest"), kit::text(e.at("manifestVersion")), false));
        }
        let perms: Vec<String> = e
            .strs("permissions")
            .iter()
            .map(|p| {
                if PERMISSIONS.contains(p) {
                    format!("{} ({p})", t(&format!("ext.perm.{p}")))
                } else {
                    p.to_string()
                }
            })
            .collect();
        facts.push((
            t("ext.permissions"),
            if perms.is_empty() {
                "—".into()
            } else {
                perms.join("\n")
            },
            false,
        ));
        let hosts = e.strs("hosts");
        facts.push((
            t("ext.sites"),
            if hosts.is_empty() {
                "—".into()
            } else {
                hosts.join("\n")
            },
            true,
        ));
        let folder = if !e.has("path") {
            "—".to_string()
        } else if e.b("pathExists") {
            e.s("path").to_string()
        } else {
            tf("ext.missing", &[("path", e.s("path"))])
        };
        facts.push((t("ext.folder"), folder, false));
        for (i, (k, v, mono)) in facts.into_iter().enumerate() {
            pane = pane.child(kit::kv_text(
                ElementId::NamedInteger("ex-f".into(), i as u64),
                k,
                v,
                mono,
                150.,
                tk,
            ));
        }
        if e.has("account") {
            pane = pane.child(kit::faint(tf("ext.otherAccount", &[("account", e.s("account"))]), tk));
        }
        if e.strs("flags").contains(&"policy") {
            pane = pane.child(kit::faint(t("ext.policyForced"), tk));
        }
        if !e.b("component") && !e.has("account") {
            pane = pane.child(kit::faint(tf("ext.removeHint", &[("browser", e.s("browser"))]), tk));
        }
        pane
    }

    fn policy_pane(&self, p: &Value, tk: &Tokens) -> Div {
        let scope = t(match p.s("scope") {
            "machine" => "ext.scopeMachine",
            "user" => "ext.scopeUser",
            _ => "ext.scopeFile",
        });
        let kind = t_or(&format!("ext.kind.{}", camel(p.s("kind"))), &t("ext.kind.other"));
        let mut pane = kit::panel(tk)
            .child(kit::h3(p.s("name").to_string()))
            .child(kit::faint(format!("{} · {scope} · {kind}", p.s("browser")), tk));
        if p.b("flagged") {
            pane = pane.child(
                kit::row()
                    .child(kit::glyph(icons::WARNING, 14., tk.warn))
                    .child(kit::colored(t("ext.policyFlagged"), tk.warn)),
            );
        }
        let mut facts = vec![(
            t("ext.colValue"),
            if p.has("data") {
                p.s("data").to_string()
            } else {
                "—".into()
            },
        )];
        let names: Vec<String> = p
            .strs("extensionIds")
            .iter()
            .map(|id| {
                self.data
                    .as_ref()
                    .and_then(|d| d.a("extensions").iter().find(|e| e.s("id").eq_ignore_ascii_case(id)))
                    .map(|e| e.s("name").to_string())
                    .unwrap_or_else(|| id.to_string())
            })
            .collect();
        if !names.is_empty() {
            facts.push((t("ext.forces"), names.join(", ")));
        }
        if p.s("scope") == "file" {
            facts.push((t("ext.file"), p.s("key").to_string()));
        } else {
            facts.push((t("ext.registry"), format!("{}\\{}", p.s("key"), p.s("value"))));
        }
        for (i, (k, v)) in facts.into_iter().enumerate() {
            pane = pane.child(kit::kv_text(
                ElementId::NamedInteger("ex-p".into(), i as u64),
                k,
                v,
                true,
                150.,
                tk,
            ));
        }
        let note = if p.s("scope") == "file" {
            Some("ext.fileNote")
        } else if !p.b("removable") {
            Some("ext.keepNote")
        } else if p.s("scope") == "machine" && !self.ctx.elevated {
            Some("ext.adminNote")
        } else {
            None
        };
        pane.children(note.map(|n| kit::faint(t(n), tk)))
    }
}

impl Render for ExtensionsPage {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let tk = *tokens(cx);
        let data = self.data.clone().unwrap_or(Value::Null);
        let visible = self.visible();
        let policies = data.a("policies");
        let flagged = policies.iter().filter(|p| p.b("flagged")).count();
        let current = self.current(cx);
        let policy = self.current_policy(cx);
        let busy = self.acting.busy;
        let weak = cx.entity().downgrade();
        let views = ui::segmented(
            "ex-view",
            t("page.extensions"),
            vec![
                (false, format!("{} {}", t("ext.viewExtensions"), visible.len())),
                (true, format!("{} {}", t("ext.viewPolicies"), policies.len())),
            ],
            self.view_policies,
            move |v, _, cx| {
                let _ = weak.update(cx, |this, cx| {
                    this.view_policies = v;
                    cx.notify();
                });
            },
            &tk,
        );
        let mut head = kit::row().child(ui::page_title(t("page.extensions"))).child(views);
        let mut bar = ui::CommandBar::new("ex-bar");
        if self.view_policies {
            let removable = policy.as_ref().is_some_and(|p| {
                p.b("removable") && p.s("scope") != "file" && (p.s("scope") == "user" || self.ctx.elevated)
            }) && !busy;
            let id = policy.as_ref().map(|p| p.s("id").to_string()).unwrap_or_default();
            bar = bar.cmd(
                ui::cmd("ex-remove", icons::DELETE, t("ext.removePolicy"))
                    .disabled(!removable)
                    .on_click(cx.listener(move |this, _, window, cx| {
                        this.send(json!({"kind": "browser-policy", "op": "remove", "id": id}), window, cx)
                    })),
            );
        } else {
            let browser = self.place_browser();
            let can_page = match &current {
                Some(e) => !e.has("account"),
                None => !browser.is_empty(),
            };
            let page_request = match &current {
                Some(e) => json!({"kind": "extension", "op": "page", "key": e.s("key")}),
                None => json!({"kind": "extension", "op": "page", "browser": browser}),
            };
            let folder = current
                .as_ref()
                .filter(|e| e.has("path") && e.b("pathExists"))
                .map(|e| e.s("key").to_string());
            bar = bar
                .cmd(
                    ui::cmd("ex-page", '\u{E8A7}', t("ext.openPage"))
                        .disabled(!can_page)
                        .on_click(cx.listener(move |this, _, window, cx| this.send(page_request.clone(), window, cx))),
                )
                .cmd(
                    ui::cmd("ex-folder", icons::FOLDER, t("ext.openFolder"))
                        .disabled(folder.is_none())
                        .on_click(cx.listener(move |this, _, window, cx| {
                            if let Some(key) = &folder {
                                this.send(json!({"kind": "extension", "op": "folder", "key": key}), window, cx)
                            }
                        })),
                );
        }
        bar = bar.separator().cmd(
            ui::cmd("ex-refresh", icons::REFRESH, t("common.refresh"))
                .disabled(self.loading)
                .on_click(cx.listener(|this, _, _, cx| this.load(cx))),
        );
        head = head.child(bar);

        // Where: browsers and their profiles.
        let mut places: Vec<(String, String)> = Vec::new();
        let browsers: BTreeSet<&str> = visible.iter().map(|e| e.s("browser")).collect();
        for b in browsers {
            places.push((format!("b:{b}"), b.to_string()));
            let mut profiles: Vec<(String, String)> = Vec::new();
            for e in visible.iter().filter(|e| e.s("browser") == b) {
                let key = profile_key(e);
                if !profiles.iter().any(|(k, _)| *k == key) {
                    profiles.push((key, format!("{b} · {}", profile_label(e))));
                }
            }
            if profiles.len() > 1 {
                places.extend(profiles);
            }
        }
        let mut filters = kit::row();
        if places.len() > 1 {
            let label = places
                .iter()
                .find(|(k, _)| *k == self.place)
                .map(|(_, l)| l.clone())
                .unwrap_or_else(|| t("ext.everywhere"));
            let weak = cx.entity().downgrade();
            let current_place = self.place.clone();
            filters = filters.child(
                FButton::new("ex-where", Kind::Standard)
                    .label(label)
                    .accessible_name(t("ext.where"))
                    .chevron()
                    .dropdown_menu(move |menu, _, _| {
                        let mut menu = menu;
                        for (key, label) in std::iter::once((String::new(), t("ext.everywhere"))).chain(places.clone())
                        {
                            let weak = weak.clone();
                            let on = key == current_place;
                            menu = menu.item(PopupMenuItem::new(label).checked(on).on_click(move |_, _, cx| {
                                let _ = weak.update(cx, |this, cx| {
                                    this.place = key.clone();
                                    this.fill(cx);
                                });
                            }));
                        }
                        menu
                    }),
            );
        }
        if !self.view_policies {
            let placed: Vec<&Value> = visible.iter().filter(|e| self.in_place(e)).collect();
            for (key, label) in CHIPS {
                let n = placed.iter().filter(|e| chip_test(key, e)).count();
                if key != "all" && n == 0 {
                    continue;
                }
                let weak = cx.entity().downgrade();
                filters = filters.child(kit::chip(
                    ElementId::Name(format!("ex-chip-{key}").into()),
                    t(label),
                    Some(n),
                    self.chip == key,
                    false,
                    move |_, cx| {
                        let _ = weak.update(cx, |this, cx| {
                            this.chip = key;
                            this.fill(cx);
                        });
                    },
                    &tk,
                ));
            }
            let components = data.a("extensions").iter().filter(|e| e.b("component")).count();
            if components > 0 {
                let weak = cx.entity().downgrade();
                filters = filters.child(ui::check_box(
                    "ex-components",
                    self.show_components,
                    false,
                    crate::i18n::tn("ext.showComponents", components as u64, &[]),
                    move |on, _, cx| {
                        let _ = weak.update(cx, |this, cx| {
                            this.show_components = on;
                            this.fill(cx);
                        });
                    },
                    &tk,
                ));
            }
        }
        let (table, pane, footer) = if self.view_policies {
            let footer = match &self.error {
                Some(e) => e.clone(),
                None => tf(
                    "ext.policySummary",
                    &[
                        ("total", &policies.len().to_string()),
                        ("flagged", &flagged.to_string()),
                    ],
                ),
            };
            (self.policies.clone(), policy.map(|p| self.policy_pane(&p, &tk)), footer)
        } else {
            let shown = self.table.read(cx).delegate().row_count();
            let profiles: u64 = data.a("browsers").iter().map(|b| b.n("profiles") as u64).sum();
            let mut footer = match &self.error {
                Some(e) => e.clone(),
                None => tf(
                    "ext.summary",
                    &[
                        ("shown", &shown.to_string()),
                        ("total", &visible.len().to_string()),
                        ("profiles", &profiles.to_string()),
                    ],
                ),
            };
            if self.data.is_some() && !data.b("otherAccounts") && !self.ctx.elevated {
                footer = format!("{footer} · {}", t("ext.adminForOthers"));
            }
            (
                self.table.clone(),
                current.map(|e| self.extension_pane(&e, &tk)),
                footer,
            )
        };
        let lead = t(if self.view_policies {
            "ext.policyNote"
        } else {
            "ext.note"
        });
        let root = div()
            .track_focus(&self.focus)
            .size_full()
            .flex()
            .flex_col()
            .gap_2()
            .px(px(20.))
            .pt(px(12.))
            .pb(px(12.));
        let list_table = table.clone();
        common::list_keys(root, move |_: &ExtensionsPage| list_table.clone(), cx)
            .child(
                div()
                    .flex()
                    .justify_center()
                    .child(div().w_full().max_w(px(640.)).child(ui::search_box(&self.search, &tk))),
            )
            .child(head)
            .child(kit::faint(lead, &tk))
            .children(self.acting.bar("ex-result", &tk))
            .child(filters)
            .child(
                div()
                    .flex_1()
                    .min_h_0()
                    .flex()
                    .gap_3()
                    .child(grid::sort_row(&table, cx))
                    .child(grid::frame(&tk).child(grid::table(&table, t("page.extensions"))))
                    .when_some(pane, |this, pane| {
                        this.child(
                            div()
                                .id("ex-pane")
                                .w(px(380.))
                                .flex_none()
                                .overflow_y_scroll()
                                .child(pane),
                        )
                    }),
            )
            .child(kit::faint(footer, &tk))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn warns(flags: &[&str]) -> Vec<String> {
        ordered_flags(&json!({ "flags": flags }))
            .into_iter()
            .filter(|(_, warn)| *warn)
            .map(|(f, _)| f)
            .collect()
    }

    #[test]
    fn only_real_risks_get_the_warning_colour() {
        // A store extension with broad permissions: ordinary, all grey.
        let store = [
            "all_sites",
            "history",
            "tabs",
            "cookies",
            "web_request",
            "native",
            "debugger",
            "proxy",
        ];
        assert!(warns(&store).is_empty());
        assert!(!has_warn(&json!({ "flags": store })));
        // Harmful mark, policy, developer mode, outside the store: always.
        for flag in [
            "store_flagged",
            "delisted",
            "policy",
            "unpacked",
            "outside_store",
            "not_signed",
        ] {
            assert_eq!(warns(&[flag, "tabs"]), [flag]);
        }
        // nativeMessaging or debugger warn only from outside the store with access to every site.
        assert_eq!(
            warns(&["outside_store", "all_sites", "native", "debugger", "proxy"]),
            ["outside_store", "native", "debugger"]
        );
        assert_eq!(warns(&["outside_store", "native"]), ["outside_store"]);
        assert_eq!(warns(&["unpacked", "all_sites", "debugger"]), ["unpacked", "debugger"]);
        // Warnings come first, the order of the rest is kept.
        let ordered: Vec<String> = ordered_flags(&json!({ "flags": ["tabs", "policy", "history"] }))
            .into_iter()
            .map(|(f, _)| f)
            .collect();
        assert_eq!(ordered, ["policy", "tabs", "history"]);
    }

    #[test]
    fn filters_keep_working() {
        let e = |flags: &[&str], enabled: bool| json!({ "flags": flags, "enabled": enabled });
        assert!(chip_test("allSites", &e(&["all_sites"], true)));
        assert!(!chip_test("allSites", &e(&["tabs"], true)));
        for outside in ["outside_store", "unpacked", "not_signed"] {
            assert!(chip_test("outside", &e(&[outside], true)));
        }
        assert!(!chip_test("outside", &e(&["policy", "all_sites"], true)));
        assert!(chip_test("policy", &e(&["policy"], true)));
        assert!(chip_test("disabled", &e(&[], false)) && !chip_test("disabled", &e(&[], true)));
        assert!(chip_test("mv2", &e(&["mv2"], true)));
        assert!(chip_test("all", &e(&[], true)));
    }
}
