//! Storage: the drives, cleanup of what Windows and apps leave behind (measured first, cleaned
//! through the action service), and the space analysis of a drive or folder with a treemap and
//! the largest files (sent to the Recycle Bin through the action service), and duplicate files
//! (copies chosen here go to the Recycle Bin after the core checks them again).

use std::collections::BTreeSet;
use std::sync::Arc;

use futures::StreamExt as _;
use futures::channel::mpsc;
use gpui_kit::base::Button as BaseButton;
use gpui_kit::component::menu::{DropdownMenu as _, PopupMenuItem};
use gpui_kit::prelude::FluentBuilder as _;
use gpui_kit::{
    AppContext as _, Context, Div, ElementId, FontWeight, InteractiveElement as _, IntoElement, ParentElement, Render,
    Role, SharedString, StatefulInteractiveElement as _, Styled, Window, div, px, relative,
};
use serde_json::{Value, json};
use vigil_core::state::AppState;

use crate::app::Ctx;
use crate::data::{self, Src};
use crate::format::{num, pct, size};
use crate::i18n::{t, tf, tn};
use crate::pages::common::{self, Acting, Acts, when};
use crate::theme::{RADIUS_CARD, Tokens, tokens};
use crate::ui::kit::{self, J as _};
use crate::ui::{self, FButton, Kind};

pub struct StoragePage {
    ctx: Ctx,
    drives: Vec<Value>,
    tab_space: bool,
    targets: Vec<Value>,
    checked: BTreeSet<String>,
    focus_key: Option<String>,
    measuring: bool,
    status: String,
    root: String,
    scan: Option<Value>,
    /// The folders opened in the space analysis, the scan's root first. Shared: a frame clones the
    /// handle, not the tree.
    path: Vec<Arc<Value>>,
    /// The layout of the open folder (its children by size and the treemap's rectangles), kept
    /// until another folder opens.
    layout: Option<(usize, Arc<Layout>)>,
    scanning: bool,
    scan_status: String,
    files: BTreeSet<String>,
    removed: BTreeSet<String>,
    acting: Acting,
    /// What the last request was, so the page reads what it changed.
    last: &'static str,
    /// The Duplicates tab is open (it takes precedence over `tab_space`).
    tab_dupes: bool,
    dup_root: String,
    /// Files smaller than this many MB are not compared.
    dup_min_mb: u64,
    dup_scan: Option<Value>,
    dup_scanning: bool,
    dup_status: String,
    /// The copies chosen for the Recycle Bin.
    dup_checked: BTreeSet<String>,
    /// Copies already sent to the Recycle Bin (hidden until the next search).
    dup_removed: BTreeSet<String>,
}

impl Acts for StoragePage {
    fn acting(&mut self) -> &mut Acting {
        &mut self.acting
    }
    fn core(&self) -> Option<Arc<AppState>> {
        self.ctx.core.clone()
    }
    fn after(&mut self, _: &mut Window, cx: &mut Context<Self>) {
        match self.last {
            "clean" => {
                self.load_drives(cx);
                self.measure(cx);
            }
            "recycle" => {
                self.removed.extend(std::mem::take(&mut self.files));
                self.load_drives(cx);
            }
            "duplicates" => {
                self.dup_removed.extend(std::mem::take(&mut self.dup_checked));
                self.load_drives(cx);
            }
            _ => {}
        }
    }
}

impl StoragePage {
    pub fn new(ctx: Ctx, cx: &mut Context<Self>) -> Self {
        let mut page = Self {
            ctx,
            drives: Vec::new(),
            tab_space: false,
            targets: Vec::new(),
            checked: BTreeSet::new(),
            focus_key: None,
            measuring: false,
            status: String::new(),
            root: String::new(),
            scan: None,
            path: Vec::new(),
            layout: None,
            scanning: false,
            scan_status: t("storage.chooseHint"),
            files: BTreeSet::new(),
            removed: BTreeSet::new(),
            acting: Acting::default(),
            last: "",
            tab_dupes: false,
            dup_root: String::new(),
            dup_min_mb: 1,
            dup_scan: None,
            dup_scanning: false,
            dup_status: t("dupes.hint"),
            dup_checked: BTreeSet::new(),
            dup_removed: BTreeSet::new(),
        };
        page.dup_root = if page.ctx.core.is_some() {
            vigil_core::duplicates::default_folder()
        } else {
            data::demo("duplicates").s("root").to_string()
        };
        page.load_drives(cx);
        page.measure(cx);
        page
    }

    fn load_drives(&mut self, cx: &mut Context<Self>) {
        let core = self.ctx.core.clone();
        common::read(
            cx,
            move || data::fetch(core.as_ref(), Src::Volumes),
            |this: &mut Self, result, _| {
                this.drives = result.ok().and_then(|v| v.as_array().cloned()).unwrap_or_default();
                if this.root.is_empty()
                    && let Some(first) = this.drives.first()
                {
                    this.root = first.s("mount").to_string();
                }
            },
        );
    }

    fn usable(&self, target: &Value) -> bool {
        target.n("size") > 0.0 && (!target.b("admin") || self.ctx.elevated)
    }

    fn measure(&mut self, cx: &mut Context<Self>) {
        if self.measuring {
            return;
        }
        self.measuring = true;
        self.status = t("storage.looking");
        let (tx, mut rx) = mpsc::unbounded::<String>();
        let core = self.ctx.core.clone();
        let task = cx.background_spawn(async move {
            match core {
                Some(st) => serde_json::to_value(vigil_core::api::cleanup_measure(&st, &|line| {
                    let _ = tx.unbounded_send(line.to_string());
                }))
                .map_err(|e| e.to_string()),
                None => Ok(data::demo("cleanup")),
            }
        });
        cx.spawn(async move |this, cx| {
            let follow = this.clone();
            let mut cx2 = cx.clone();
            let progress = async move {
                while let Some(line) = rx.next().await {
                    let _ = follow.update(&mut cx2, |page, cx| {
                        page.status = line;
                        cx.notify();
                    });
                }
            };
            let (result, ()) = futures::join!(task, progress);
            let _ = this.update(cx, |page, cx| {
                page.measuring = false;
                match result {
                    Ok(v) => {
                        page.targets = v.as_array().cloned().unwrap_or_default();
                        page.checked = page
                            .targets
                            .iter()
                            .filter(|x| x.b("selected") && page.usable(x))
                            .map(|x| x.s("key").to_string())
                            .collect();
                        let total: f64 = page
                            .targets
                            .iter()
                            .filter(|x| !x.b("admin") || page.ctx.elevated)
                            .map(|x| x.n("size"))
                            .sum();
                        page.status = tn(
                            "storage.measured",
                            page.targets.len() as u64,
                            &[("size", &size(total, 1))],
                        );
                    }
                    Err(e) => page.status = tf("storage.measureFailed", &[("error", &e)]),
                }
                cx.notify();
            });
        })
        .detach();
    }

    fn analyze(&mut self, target: String, cx: &mut Context<Self>) {
        if self.scanning || target.is_empty() {
            return;
        }
        self.scanning = true;
        self.root = target.clone();
        self.scan_status = tf("storage.reading", &[("target", &target)]);
        let (tx, mut rx) = mpsc::unbounded::<String>();
        let core = self.ctx.core.clone();
        let task = cx.background_spawn(async move {
            match core {
                Some(st) => vigil_core::api::space_scan(&st, &target, &|line| {
                    let _ = tx.unbounded_send(line.to_string());
                })
                .and_then(|scan| serde_json::to_value(scan).map_err(|e| e.to_string())),
                None => Ok(data::demo("space")),
            }
        });
        cx.spawn(async move |this, cx| {
            let follow = this.clone();
            let mut cx2 = cx.clone();
            let progress = async move {
                while let Some(line) = rx.next().await {
                    let _ = follow.update(&mut cx2, |page, cx| {
                        page.scan_status = line;
                        cx.notify();
                    });
                }
            };
            let (result, ()) = futures::join!(task, progress);
            let _ = this.update(cx, |page, cx| {
                page.scanning = false;
                match result {
                    Ok(scan) => {
                        let root = scan.at("root");
                        let mut parts = vec![tf(
                            "storage.scanSummary",
                            &[
                                ("files", &num(scan.n("files"), 0)),
                                ("folders", &num(scan.n("folders"), 0)),
                                ("size", &size(root.n("size"), 1)),
                                ("seconds", &num(scan.n("seconds"), 1)),
                            ],
                        )];
                        if scan.b("cancelled") {
                            parts.push(t("storage.stoppedEarly"));
                        }
                        if scan.n("errors") > 0.0 {
                            parts.push(tn("storage.unreadable", scan.n("errors") as u64, &[]));
                        }
                        if scan.n("mergedBelow") > 0.0 {
                            parts.push(tf("storage.grouped", &[("size", &size(scan.n("mergedBelow"), 0))]));
                        }
                        page.scan_status = parts.join(" · ");
                        page.path = vec![Arc::new(root.clone())];
                        page.files.clear();
                        page.removed.clear();
                        page.scan = Some(scan);
                    }
                    Err(e) => page.scan_status = tf("storage.analyzeFailed", &[("error", &e)]),
                }
                cx.notify();
            });
        })
        .detach();
    }

    fn choose_folder(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let picked = cx.prompt_for_paths(gpui_kit::PathPromptOptions {
            files: false,
            directories: true,
            multiple: false,
            prompt: Some(t("storage.chooseFolder").into()),
        });
        cx.spawn_in(window, async move |this, cx| {
            let Ok(Ok(Some(paths))) = picked.await else { return };
            let Some(path) = paths.into_iter().next() else { return };
            let _ = this.update(cx, |this, cx| this.analyze(path.display().to_string(), cx));
        })
        .detach();
    }

    fn drive_cards(&self, cx: &mut Context<Self>, tk: &Tokens) -> Div {
        let mut row = div().flex().flex_wrap().gap_3();
        for (i, d) in self.drives.iter().take(6).enumerate() {
            let mount = d.s("mount").to_string();
            let total = d.n("total");
            let fraction = if total > 0.0 { d.n("used") / total } else { 0.0 };
            let weak = cx.entity().downgrade();
            let target = mount.clone();
            let tk2 = *tk;
            row = row.child(
                BaseButton::new(ElementId::NamedInteger("st-drive".into(), i as u64))
                    .role(Role::Button)
                    .accessibility_label(SharedString::from(tf("storage.analyzeDrive", &[("drive", &mount)])))
                    .w(px(280.))
                    .flex()
                    .flex_col()
                    .items_start()
                    .gap_1()
                    .p_3()
                    .bg(tk.surface)
                    .border_1()
                    .border_color(tk.rule)
                    .rounded(RADIUS_CARD)
                    .hover(move |s| s.bg(tk2.hover))
                    .on_click(move |_, _, cx| {
                        let _ = weak.update(cx, |this, cx| {
                            this.tab_space = true;
                            this.tab_dupes = false;
                            this.analyze(target.clone(), cx);
                        });
                    })
                    .child(
                        div()
                            .w_full()
                            .flex()
                            .gap_2()
                            .child(
                                div()
                                    .font_weight(FontWeight::SEMIBOLD)
                                    .child(mount.trim_end_matches('\\').to_string()),
                            )
                            .child(kit::muted(d.s("label").to_string(), tk))
                            .child(div().flex_1())
                            .child(kit::faint(tf("overview.free", &[("size", &size(d.n("free"), 1))]), tk)),
                    )
                    .child(kit::usage_bar(fraction, tk))
                    .child(kit::faint(
                        format!(
                            "{} · {}",
                            tf(
                                "storage.used",
                                &[("used", &size(d.n("used"), 1)), ("total", &size(total, 1))]
                            ),
                            d.s("fs")
                        ),
                        tk,
                    )),
            );
        }
        row
    }

    fn clean_tab(&self, cx: &mut Context<Self>, window: &Window, tk: &Tokens) -> Div {
        let mut groups: Vec<(String, Vec<&Value>)> = Vec::new();
        for target in &self.targets {
            let g = target.s("group").to_string();
            match groups.iter_mut().find(|(name, _)| *name == g) {
                Some((_, list)) => list.push(target),
                None => groups.push((g, vec![target])),
            }
        }
        let mut list = div().flex().flex_col();
        for (g, mut members) in groups {
            members.sort_by(|a, b| b.n("size").total_cmp(&a.n("size")));
            let total: f64 = members.iter().map(|m| m.n("size")).sum();
            list = list.child(
                div()
                    .flex()
                    .px_2()
                    .py_1()
                    .bg(tk.surface2)
                    .font_weight(FontWeight::SEMIBOLD)
                    .text_size(px(13.))
                    .child(div().flex_1().child(g))
                    .child(div().w(px(110.)).child(size(total, 1)))
                    .child(div().w(px(90.))),
            );
            for target in members {
                let key = target.s("key").to_string();
                let usable = self.usable(target);
                let mut tip = target.s("description").to_string();
                if target.has("note") {
                    tip = format!("{tip}\n{}", vigil_core::display::shown(target.s("note")));
                }
                if target.b("admin") && !self.ctx.elevated {
                    tip = format!("{tip}\n{}", t("storage.needsAdmin"));
                }
                let weak = cx.entity().downgrade();
                let focus = cx.entity().downgrade();
                let check_key = key.clone();
                let focus_key = key.clone();
                list = list.child(
                    div()
                        .id(ElementId::Name(format!("st-t-{key}").into()))
                        .flex()
                        .items_center()
                        .px_2()
                        .h(px(28.))
                        .text_size(px(13.))
                        .when(self.focus_key.as_deref() == Some(key.as_str()), |this| {
                            this.bg(tk.table_select)
                        })
                        .when(!usable, |this| this.text_color(tk.ink3))
                        .tooltip(move |window, cx| {
                            gpui_kit::component::tooltip::Tooltip::new(tip.clone()).build(window, cx)
                        })
                        .on_click(move |_, _, cx| {
                            let _ = focus.update(cx, |this, cx| {
                                this.focus_key = Some(focus_key.clone());
                                cx.notify();
                            });
                        })
                        .child(div().flex_1().child(ui::check_box(
                            ElementId::Name(format!("st-c-{key}").into()),
                            self.checked.contains(&key),
                            !usable,
                            target.s("label").to_string(),
                            move |on, _, cx| {
                                let _ = weak.update(cx, |this, cx| {
                                    if on {
                                        this.checked.insert(check_key.clone());
                                    } else {
                                        this.checked.remove(&check_key);
                                    }
                                    this.focus_key = Some(check_key.clone());
                                    cx.notify();
                                });
                            },
                            tk,
                        )))
                        .child(div().w(px(110.)).child(size(target.n("size"), 1)))
                        .child(div().w(px(90.)).text_color(tk.ink3).child(if target.n("files") > 0.0 {
                            num(target.n("files"), 0)
                        } else {
                            String::new()
                        })),
                );
            }
        }
        let focused = self
            .focus_key
            .as_ref()
            .and_then(|k| self.targets.iter().find(|x| x.s("key") == k));
        let chosen: Vec<&Value> = self
            .targets
            .iter()
            .filter(|x| self.checked.contains(x.s("key")) && self.usable(x))
            .collect();
        let chosen_total: f64 = chosen.iter().map(|x| x.n("size")).sum();
        let keys: Vec<String> = chosen.iter().map(|x| x.s("key").to_string()).collect();
        let mut left = kit::panel(tk)
            .child(
                kit::row()
                    .child(kit::h2(t("storage.junk")))
                    .child(div().flex_1())
                    .child(
                        ui::button("st-again", t("storage.scanAgain"))
                            .disabled(self.measuring)
                            .on_click(cx.listener(|this, _, _, cx| this.measure(cx))),
                    ),
            )
            .child(kit::muted(self.status.clone(), tk))
            .child(list);
        if let Some(f) = focused {
            let mut text = format!("{} {}", f.s("description"), f.s("note")).trim().to_string();
            if f.n("minAgeHours") > 0.0 {
                text = format!("{text} {}", tn("storage.minAge", f.n("minAgeHours") as u64, &[]));
            }
            left = left.child(kit::body(text));
            let roots = f.strs("roots");
            if !roots.is_empty() {
                let mut paths = roots.iter().take(4).copied().collect::<Vec<_>>().join("; ");
                if roots.len() > 4 {
                    paths.push_str(" …");
                }
                left = left.child(kit::faint(tf("storage.location", &[("paths", &paths)]), tk));
            }
        }
        left = left.child(
            kit::row()
                .child(
                    kit::body(if chosen.is_empty() {
                        t("storage.nothingSelected")
                    } else {
                        tf("storage.selected", &[("size", &size(chosen_total, 1))])
                    })
                    .font_weight(FontWeight::SEMIBOLD),
                )
                .child(div().flex_1())
                .child(
                    ui::accent_button("st-clean", t("storage.clean"))
                        .disabled(keys.is_empty() || self.measuring || self.acting.busy)
                        .on_click(cx.listener(move |this, _, window, cx| {
                            if this.acting.busy {
                                return;
                            }
                            this.last = "clean";
                            common::send_json(this, json!({"kind": "cleanup", "keys": keys}), window, cx);
                        })),
                ),
        );
        let disabled = !self.ctx.elevated || self.acting.busy;
        let right = kit::panel(tk)
            .child(kit::h2(t("storage.deeper")))
            .child(kit::h3(t("storage.componentStore")))
            .child(kit::muted(t("storage.componentStoreNote"), tk))
            .child(
                div().flex().child(
                    ui::button("st-component", t("storage.componentStoreClean"))
                        .disabled(disabled)
                        .on_click(cx.listener(|this, _, window, cx| {
                            if this.acting.busy {
                                return;
                            }
                            this.last = "";
                            common::send_json(
                                this,
                                json!({"kind": "tuning", "op": "disk.component_cleanup", "params": {}}),
                                window,
                                cx,
                            );
                        })),
                ),
            )
            .child(kit::h3(t("storage.diskCleanup")))
            .child(kit::muted(t("storage.diskCleanupNote"), tk))
            .child(div().flex().child(
                ui::button("st-cleanmgr", t("storage.diskCleanupOpen")).on_click(cx.listener(|this, _, window, cx| {
                    if this.acting.busy {
                        return;
                    }
                    this.last = "";
                    common::send_json(
                        this,
                        json!({"kind": "shell", "op": "tool", "name": "cleanmgr.exe"}),
                        window,
                        cx,
                    );
                })),
            ))
            .child(kit::h3(t("storage.settings")))
            .child(kit::muted(t("storage.settingsNote"), tk))
            .child(
                div()
                    .flex()
                    .child(ui::button("st-sense", t("storage.settingsOpen")).on_click(cx.listener(
                        |this, _, window, cx| {
                            if this.acting.busy {
                                return;
                            }
                            this.last = "";
                            common::send_json(
                                this,
                                json!({"kind": "shell", "op": "url", "url": "ms-settings:storagesense"}),
                                window,
                                cx,
                            );
                        },
                    ))),
            )
            .child(kit::faint(t("storage.hibernationHint"), tk));
        kit::columns(0.6, left, right, window)
    }

    fn space_tab(&mut self, cx: &mut Context<Self>, window: &Window, tk: &Tokens) -> Div {
        let drives: Vec<(String, String)> = self
            .drives
            .iter()
            .filter(|d| !d.b("network"))
            .map(|d| {
                (
                    d.s("mount").to_string(),
                    format!("{} {}", d.s("mount").trim_end_matches('\\'), d.s("label")),
                )
            })
            .collect();
        let mut options = drives.clone();
        if !self.root.is_empty() && !drives.iter().any(|(m, _)| *m == self.root) {
            options.push((self.root.clone(), self.root.clone()));
        }
        let label = options
            .iter()
            .find(|(m, _)| *m == self.root)
            .map(|(_, l)| l.clone())
            .unwrap_or_default();
        let weak = cx.entity().downgrade();
        let root = self.root.clone();
        let controls = kit::row()
            .child(
                FButton::new("st-root", Kind::Standard)
                    .label(label)
                    .accessible_name(t("storage.driveOrFolder"))
                    .chevron()
                    .min_w(px(200.))
                    .dropdown_menu(move |menu, _, _| {
                        let mut menu = menu;
                        for (mount, label) in options.clone() {
                            let weak = weak.clone();
                            let on = mount == root;
                            menu = menu.item(PopupMenuItem::new(label).checked(on).on_click(move |_, _, cx| {
                                let _ = weak.update(cx, |this, cx| {
                                    this.root = mount.clone();
                                    cx.notify();
                                });
                            }));
                        }
                        menu
                    }),
            )
            .child(
                ui::button("st-choose", t("storage.chooseFolder"))
                    .disabled(self.scanning)
                    .on_click(cx.listener(|this, _, window, cx| this.choose_folder(window, cx))),
            )
            .child(
                ui::accent_button("st-analyze", t("storage.analyze"))
                    .disabled(self.scanning)
                    .on_click(cx.listener(|this, _, _, cx| {
                        let root = this.root.clone();
                        this.analyze(root, cx)
                    })),
            )
            .child(
                ui::button("st-stop", t("storage.stop"))
                    .disabled(!self.scanning)
                    .on_click(cx.listener(|this, _, _, _| {
                        if let Some(core) = &this.ctx.core {
                            vigil_core::api::space_cancel(core);
                        }
                    })),
            )
            .child(
                kit::faint(self.scan_status.clone(), tk)
                    .flex_1()
                    .min_w_0()
                    .overflow_hidden()
                    .text_ellipsis()
                    .whitespace_nowrap(),
            );
        let mut tab = div().flex().flex_col().gap_3().child(controls);
        let Some(node) = self.path.last().cloned() else {
            return tab;
        };
        let layout = self.layout_of(&node);
        let crumb = node.s("path").to_string();
        tab = tab.child(
            kit::row()
                .child(
                    ui::button("st-up", t("storage.up"))
                        .disabled(self.path.len() < 2)
                        .on_click(cx.listener(|this, _, _, cx| {
                            this.path.pop();
                            cx.notify();
                        })),
                )
                .child(kit::muted(crumb, tk)),
        );
        let weak = cx.entity().downgrade();
        let map = treemap(
            &node,
            &layout,
            Arc::new(move |index: usize, _, cx| {
                let _ = weak.update(cx, |this, cx| this.open_child(index, cx));
            }),
            tk,
        );
        let total = node.n("size").max(1.0);
        let children: Vec<(usize, &Value)> = layout
            .order
            .iter()
            .filter_map(|&index| node.a("children").get(index).map(|child| (index, child)))
            .collect();
        let mut table = div()
            .id("st-children")
            .max_h(px(360.))
            .overflow_y_scroll()
            .flex()
            .flex_col()
            .text_size(px(13.))
            .child(
                div()
                    .flex()
                    .px_2()
                    .text_size(px(12.))
                    .text_color(tk.ink3)
                    .child(div().flex_1().child(t("storage.name")))
                    .child(div().w(px(90.)).child(t("storage.size")))
                    .child(div().w(px(64.)).child(t("storage.share")))
                    .child(div().w(px(80.)).child(t("storage.files"))),
            );
        for (i, &(index, child)) in children.iter().enumerate() {
            let dir = child.b("isDir");
            let drill = dir && !child.a("children").is_empty();
            let weak = cx.entity().downgrade();
            let tip = vigil_core::display::shown(child.s("path"));
            table = table.child(
                div()
                    .id(ElementId::NamedInteger("st-child".into(), i as u64))
                    .flex()
                    .px_2()
                    .h(px(26.))
                    .items_center()
                    .when(i % 2 == 1, |this| this.bg(tk.surface2))
                    .tooltip(move |window, cx| {
                        gpui_kit::component::tooltip::Tooltip::new(tip.clone()).build(window, cx)
                    })
                    .when(drill, |this| {
                        this.on_click(move |event, _, cx| {
                            if event.click_count() >= 2 {
                                let _ = weak.update(cx, |this, cx| this.open_child(index, cx));
                            }
                        })
                    })
                    .child(
                        div()
                            .flex_1()
                            .min_w_0()
                            .overflow_hidden()
                            .text_ellipsis()
                            .whitespace_nowrap()
                            .child(vigil_core::display::shown_line(&format!(
                                "{}{}",
                                child.s("name"),
                                if dir { "\\" } else { "" }
                            ))),
                    )
                    .child(div().w(px(90.)).child(size(child.n("size"), 1)))
                    .child(div().w(px(64.)).child(pct(child.n("size") / total * 100.0, 1)))
                    .child(
                        div()
                            .w(px(80.))
                            .child(if dir { num(child.n("files"), 0) } else { String::new() }),
                    ),
            );
        }
        if node.n("other") > 0.0 {
            table = table.child(
                div()
                    .flex()
                    .px_2()
                    .h(px(26.))
                    .items_center()
                    .child(div().flex_1().child(t("treemap.other")))
                    .child(div().w(px(90.)).child(size(node.n("other"), 1)))
                    .child(div().w(px(64.)).child(pct(node.n("other") / total * 100.0, 1)))
                    .child(div().w(px(80.))),
            );
        }
        tab = tab.child(kit::columns(0.6, map, kit::panel(tk).p_2().child(table), window));

        // The largest files.
        let files: Vec<Value> = self
            .scan
            .as_ref()
            .map(|s| {
                s.a("largestFiles")
                    .iter()
                    .filter(|f| !self.removed.contains(f.s("path")))
                    .cloned()
                    .collect()
            })
            .unwrap_or_default();
        let one = (self.files.len() == 1)
            .then(|| self.files.iter().next().cloned())
            .flatten();
        let chosen: Vec<String> = self.files.iter().cloned().collect();
        let mut panel = kit::panel(tk).child(
            kit::row()
                .child(kit::h3(t("storage.largest")))
                .child(div().flex_1())
                .child(
                    ui::button("st-location", t("proc.location"))
                        .disabled(one.is_none() || self.acting.busy)
                        .on_click(cx.listener(move |this, _, window, cx| {
                            if let Some(path) = &one {
                                if this.acting.busy {
                                    return;
                                }
                                this.last = "";
                                common::send_json(
                                    this,
                                    json!({"kind": "shell", "op": "location", "path": path}),
                                    window,
                                    cx,
                                );
                            }
                        })),
                )
                .child(
                    ui::button("st-recycle", t("storage.recycle"))
                        .danger(true)
                        .disabled(chosen.is_empty() || self.acting.busy)
                        .on_click(cx.listener(move |this, _, window, cx| {
                            if this.acting.busy {
                                return;
                            }
                            this.last = "recycle";
                            common::send_json(this, json!({"kind": "recycle", "paths": chosen}), window, cx);
                        })),
                ),
        );
        let mut list = div()
            .id("st-files")
            .max_h(px(320.))
            .overflow_y_scroll()
            .flex()
            .flex_col();
        for (i, f) in files.iter().enumerate() {
            let path = f.s("path").to_string();
            // Names come from the disk: invisible and direction-changing characters are shown.
            let (folder, name) = path
                .rsplit_once('\\')
                .map(|(a, b)| (vigil_core::display::shown_line(a), vigil_core::display::shown_line(b)))
                .unwrap_or_default();
            let weak = cx.entity().downgrade();
            let key = path.clone();
            list = list.child(
                div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .h(px(28.))
                    .text_size(px(13.))
                    .child(ui::check_box(
                        ElementId::NamedInteger("st-file".into(), i as u64),
                        self.files.contains(&path),
                        false,
                        size(f.n("size"), 1),
                        move |on, _, cx| {
                            let _ = weak.update(cx, |this, cx| {
                                if on {
                                    this.files.insert(key.clone());
                                } else {
                                    this.files.remove(&key);
                                }
                                cx.notify();
                            });
                        },
                        tk,
                    ))
                    .child(
                        div()
                            .w(px(200.))
                            .flex_none()
                            .overflow_hidden()
                            .text_ellipsis()
                            .whitespace_nowrap()
                            .child(name),
                    )
                    .child(
                        kit::faint(folder, tk)
                            .flex_1()
                            .min_w_0()
                            .overflow_hidden()
                            .text_ellipsis()
                            .whitespace_nowrap(),
                    )
                    .child(
                        kit::faint(
                            if f.i("modifiedMs") > 0 {
                                when(&kit::local_iso(f.i("modifiedMs")))
                            } else {
                                String::new()
                            },
                            tk,
                        )
                        .w(px(130.)),
                    ),
            );
        }
        panel = panel.child(list);
        tab.child(panel)
    }
}

/// Groups shown at most (the ones that waste the most first).
const DUP_GROUPS_SHOWN: usize = 200;

impl StoragePage {
    /// Searches the chosen folder for duplicates (the core remembers the groups it found: only
    /// those copies can be sent to the Recycle Bin).
    fn find_dupes(&mut self, cx: &mut Context<Self>) {
        if self.dup_scanning || self.dup_root.is_empty() {
            return;
        }
        self.dup_scanning = true;
        self.dup_status = tf(
            "dupes.reading",
            &[("folder", &vigil_core::display::shown_line(&self.dup_root))],
        );
        let (tx, mut rx) = mpsc::unbounded::<String>();
        let core = self.ctx.core.clone();
        let root = self.dup_root.clone();
        let min_mb = self.dup_min_mb;
        let task = cx.background_spawn(async move {
            match core {
                Some(st) => vigil_core::duplicates::find(&st, &root, min_mb, &move |line| {
                    let _ = tx.unbounded_send(line.to_string());
                })
                .and_then(|scan| serde_json::to_value(scan).map_err(|e| e.to_string())),
                None => Ok(data::demo("duplicates")),
            }
        });
        cx.spawn(async move |this, cx| {
            let follow = this.clone();
            let mut cx2 = cx.clone();
            let progress = async move {
                while let Some(line) = rx.next().await {
                    let _ = follow.update(&mut cx2, |page, cx| {
                        page.dup_status = line;
                        cx.notify();
                    });
                }
            };
            let (result, ()) = futures::join!(task, progress);
            let _ = this.update(cx, |page, cx| {
                page.dup_scanning = false;
                match result {
                    Ok(scan) => {
                        let mut parts = vec![tf(
                            "dupes.summary",
                            &[
                                ("groups", &num(scan.a("groups").len() as f64, 0)),
                                ("size", &size(scan.n("wasted"), 1)),
                                ("files", &num(scan.n("files"), 0)),
                                ("seconds", &num(scan.n("seconds"), 1)),
                            ],
                        )];
                        if scan.b("cancelled") {
                            parts.push(t("storage.stoppedEarly"));
                        }
                        if scan.b("capped") {
                            parts.push(t("dupes.capped"));
                        }
                        if scan.b("groupsCapped") {
                            parts.push(t("dupes.groupsCapped"));
                        }
                        if scan.n("cloudSkipped") > 0.0 {
                            parts.push(tn("dupes.cloudSkipped", scan.n("cloudSkipped") as u64, &[]));
                        }
                        if scan.n("errors") > 0.0 {
                            parts.push(tn("dupes.unreadable", scan.n("errors") as u64, &[]));
                        }
                        page.dup_status = parts.join(" · ");
                        page.dup_checked.clear();
                        page.dup_removed.clear();
                        page.dup_scan = Some(scan);
                    }
                    Err(e) => page.dup_status = tf("dupes.failed", &[("error", &e)]),
                }
                cx.notify();
            });
        })
        .detach();
    }

    fn choose_dup_folder(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let picked = cx.prompt_for_paths(gpui_kit::PathPromptOptions {
            files: false,
            directories: true,
            multiple: false,
            prompt: Some(t("dupes.chooseFolder").into()),
        });
        cx.spawn_in(window, async move |this, cx| {
            let Ok(Ok(Some(paths))) = picked.await else { return };
            let Some(path) = paths.into_iter().next() else { return };
            let _ = this.update(cx, |this, cx| {
                this.dup_root = path.display().to_string();
                this.find_dupes(cx);
            });
        })
        .detach();
    }

    /// The copies of a group still shown (not sent to the Recycle Bin yet).
    fn dup_files<'a>(&self, group: &'a Value) -> Vec<&'a Value> {
        group
            .a("files")
            .iter()
            .filter(|f| !self.dup_removed.contains(f.s("path")))
            .collect()
    }

    /// Chooses every copy but the oldest of each group (the original is usually the oldest).
    fn choose_all_but_oldest(&mut self) {
        let Some(scan) = self.dup_scan.clone() else { return };
        self.dup_checked.clear();
        for group in scan.a("groups").iter().take(DUP_GROUPS_SHOWN) {
            let files = self.dup_files(group);
            if files.len() < 2 {
                continue;
            }
            let oldest = files
                .iter()
                .min_by_key(|f| (f.i("modifiedMs"), f.s("path").to_lowercase()))
                .map(|f| f.s("path").to_string())
                .unwrap_or_default();
            for f in files {
                if f.s("path") != oldest {
                    self.dup_checked.insert(f.s("path").to_string());
                }
            }
        }
    }

    fn dupes_tab(&mut self, cx: &mut Context<Self>, tk: &Tokens) -> Div {
        let weak = cx.entity().downgrade();
        let min = self.dup_min_mb;
        let controls = kit::row()
            .child(kit::body(t("dupes.folder")).font_weight(FontWeight::SEMIBOLD))
            .child(
                kit::muted(self.dup_root.clone(), tk)
                    .min_w_0()
                    .overflow_hidden()
                    .text_ellipsis()
                    .whitespace_nowrap(),
            )
            .child(
                ui::button("dp-choose", t("dupes.chooseFolder"))
                    .disabled(self.dup_scanning)
                    .on_click(cx.listener(|this, _, window, cx| this.choose_dup_folder(window, cx))),
            )
            .child(
                FButton::new("dp-min", Kind::Standard)
                    .label(tf("dupes.minSize", &[("size", &size((min << 20) as f64, 0))]))
                    .accessible_name(t("dupes.minSizeName"))
                    .chevron()
                    .dropdown_menu(move |menu, _, _| {
                        let mut menu = menu;
                        for mb in [0u64, 1, 10, 100, 1024] {
                            let weak = weak.clone();
                            let label = if mb == 0 {
                                t("dupes.anySize")
                            } else {
                                tf("dupes.minSize", &[("size", &size((mb << 20) as f64, 0))])
                            };
                            menu = menu.item(PopupMenuItem::new(label).checked(mb == min).on_click(move |_, _, cx| {
                                let _ = weak.update(cx, |this, cx| {
                                    this.dup_min_mb = mb;
                                    cx.notify();
                                });
                            }));
                        }
                        menu
                    }),
            )
            .child(
                ui::accent_button("dp-find", t("dupes.find"))
                    .disabled(self.dup_scanning || self.dup_root.is_empty())
                    .on_click(cx.listener(|this, _, _, cx| this.find_dupes(cx))),
            )
            .child(
                ui::button("dp-stop", t("storage.stop"))
                    .disabled(!self.dup_scanning)
                    .on_click(cx.listener(|this, _, _, _| {
                        if let Some(core) = &this.ctx.core {
                            vigil_core::duplicates::cancel(core);
                        }
                    })),
            );
        let tab = div()
            .flex()
            .flex_col()
            .gap_3()
            .child(controls)
            .child(kit::faint(t("dupes.note"), tk))
            .child(
                kit::faint(self.dup_status.clone(), tk)
                    .min_w_0()
                    .overflow_hidden()
                    .text_ellipsis()
                    .whitespace_nowrap(),
            );
        let Some(scan) = self.dup_scan.clone() else {
            return tab;
        };
        let groups: Vec<&Value> = scan
            .a("groups")
            .iter()
            .filter(|g| self.dup_files(g).len() >= 2)
            .take(DUP_GROUPS_SHOWN)
            .collect();
        let chosen: Vec<String> = self.dup_checked.iter().cloned().collect();
        let chosen_size: f64 = scan
            .a("groups")
            .iter()
            .map(|g| {
                g.a("files")
                    .iter()
                    .filter(|f| self.dup_checked.contains(f.s("path")))
                    .count() as f64
                    * g.n("size")
            })
            .sum();
        let one = (chosen.len() == 1).then(|| chosen[0].clone());
        let mut panel = kit::panel(tk).child(
            kit::row()
                .child(kit::h3(t("dupes.groupsTitle")))
                .child(div().flex_1())
                .child(
                    ui::button("dp-auto", t("dupes.chooseCopies"))
                        .disabled(groups.is_empty() || self.acting.busy)
                        .on_click(cx.listener(|this, _, _, cx| {
                            this.choose_all_but_oldest();
                            cx.notify();
                        })),
                )
                .child(
                    ui::button("dp-clear", t("dupes.clearChoice"))
                        .disabled(chosen.is_empty() || self.acting.busy)
                        .on_click(cx.listener(|this, _, _, cx| {
                            this.dup_checked.clear();
                            cx.notify();
                        })),
                )
                .child(
                    ui::button("dp-location", t("proc.location"))
                        .disabled(one.is_none() || self.acting.busy)
                        .on_click(cx.listener(move |this, _, window, cx| {
                            if let Some(path) = &one {
                                if this.acting.busy {
                                    return;
                                }
                                this.last = "";
                                common::send_json(
                                    this,
                                    json!({"kind": "shell", "op": "location", "path": path}),
                                    window,
                                    cx,
                                );
                            }
                        })),
                )
                .child(
                    ui::button("dp-recycle", t("dupes.recycle"))
                        .danger(true)
                        .disabled(chosen.is_empty() || self.acting.busy || self.ctx.core.is_none())
                        .on_click(cx.listener(move |this, _, window, cx| {
                            if this.acting.busy {
                                return;
                            }
                            this.last = "duplicates";
                            common::send_json(this, json!({"kind": "duplicates", "paths": chosen}), window, cx);
                        })),
                ),
        );
        if groups.is_empty() {
            panel = panel.child(kit::faint(t("dupes.none"), tk));
            return tab.child(panel);
        }
        panel = panel.child(kit::faint(
            if self.dup_checked.is_empty() {
                t("dupes.chooseHint")
            } else {
                tn(
                    "dupes.chosen",
                    self.dup_checked.len() as u64,
                    &[("size", &size(chosen_size, 1))],
                )
            },
            tk,
        ));
        let mut list = div()
            .id("dp-groups")
            .max_h(px(520.))
            .overflow_y_scroll()
            .flex()
            .flex_col()
            .gap_2();
        let mut row_index = 0u64;
        for group in groups {
            let files = self.dup_files(group);
            let unchecked = files.iter().filter(|f| !self.dup_checked.contains(f.s("path"))).count();
            list = list.child(
                div()
                    .flex()
                    .gap_2()
                    .px_2()
                    .py_1()
                    .bg(tk.surface2)
                    .text_size(px(13.))
                    .font_weight(FontWeight::SEMIBOLD)
                    .child(div().flex_1().child(tn(
                        "dupes.groupLine",
                        files.len() as u64,
                        &[("size", &size(group.n("size"), 1))],
                    )))
                    .child(kit::faint(
                        tf(
                            "dupes.groupFree",
                            &[("size", &size(group.n("size") * (files.len() as f64 - 1.0), 1))],
                        ),
                        tk,
                    )),
            );
            for f in files {
                let path = f.s("path").to_string();
                let (folder, name) = path
                    .rsplit_once('\\')
                    .map(|(a, b)| (a.to_string(), b.to_string()))
                    .unwrap_or_else(|| (String::new(), path.clone()));
                let checked = self.dup_checked.contains(&path);
                // The last copy left unchosen in a group cannot be chosen: one copy always stays.
                let last = !checked && unchecked <= 1;
                let weak = cx.entity().downgrade();
                let key = path.clone();
                let tip = vigil_core::display::shown(&path);
                list = list.child(
                    div()
                        .id(ElementId::NamedInteger("dp-row".into(), row_index))
                        .flex()
                        .items_center()
                        .gap_2()
                        .h(px(28.))
                        .px_2()
                        .text_size(px(13.))
                        .tooltip(move |window, cx| {
                            gpui_kit::component::tooltip::Tooltip::new(tip.clone()).build(window, cx)
                        })
                        .child(ui::check_box(
                            ElementId::NamedInteger("dp-file".into(), row_index),
                            checked,
                            last,
                            vigil_core::display::shown_line(&name),
                            move |on, _, cx| {
                                let _ = weak.update(cx, |this, cx| {
                                    if on {
                                        this.dup_checked.insert(key.clone());
                                    } else {
                                        this.dup_checked.remove(&key);
                                    }
                                    cx.notify();
                                });
                            },
                            tk,
                        ))
                        .child(
                            kit::faint(folder, tk)
                                .flex_1()
                                .min_w_0()
                                .overflow_hidden()
                                .text_ellipsis()
                                .whitespace_nowrap(),
                        )
                        .child(
                            kit::faint(
                                if f.i("modifiedMs") > 0 {
                                    when(&kit::local_iso(f.i("modifiedMs")))
                                } else {
                                    String::new()
                                },
                                tk,
                            )
                            .w(px(130.)),
                        ),
                );
                row_index += 1;
            }
        }
        panel = panel.child(list);
        tab.child(panel)
    }
}

/// Opens child `index` of the folder shown.
type Open = Arc<dyn Fn(usize, &mut Window, &mut gpui_kit::App)>;

/// One tile of the treemap: a child of the folder (`None`: the small entries grouped as "other"),
/// its size and its rectangle in a 1.6 × 1 box.
#[derive(Debug, Clone, PartialEq)]
struct Tile {
    child: Option<usize>,
    bytes: f64,
    rect: (f64, f64, f64, f64),
}

/// What the space analysis shows of one folder: its children largest first (indexes into
/// `children`) and the treemap's tiles. Computed once per folder, not every frame.
#[derive(Debug, Clone, Default, PartialEq)]
struct Layout {
    order: Vec<usize>,
    tiles: Vec<Tile>,
}

/// The box the treemap is laid out in (the usual shape of the panel); tiles are placed by fractions.
const TREEMAP_BOX: (f64, f64) = (1.6, 1.0);

impl Layout {
    fn of(node: &Value) -> Layout {
        let children = node.a("children");
        let mut order: Vec<usize> = (0..children.len()).collect();
        order.sort_by(|&a, &b| children[b].n("size").total_cmp(&children[a].n("size")));
        let mut entries: Vec<(f64, Option<usize>)> = order
            .iter()
            .filter(|&&i| children[i].n("size") > 0.0)
            .map(|&i| (children[i].n("size"), Some(i)))
            .collect();
        if node.n("other") > 0.0 {
            entries.push((node.n("other"), None));
        }
        entries.sort_by(|a, b| b.0.total_cmp(&a.0));
        let total: f64 = entries.iter().map(|e| e.0).sum();
        let tiles = if total > 0.0 {
            let (w, h) = TREEMAP_BOX;
            let areas: Vec<f64> = entries.iter().map(|e| e.0 * w * h / total).collect();
            squarify(&areas, w, h)
                .into_iter()
                .zip(entries)
                .map(|(rect, (bytes, child))| Tile { child, bytes, rect })
                .collect()
        } else {
            Vec::new()
        };
        Layout { order, tiles }
    }
}

/// A squarified treemap of a folder's children (and what was merged as "Other").
fn treemap(node: &Value, layout: &Layout, open: Open, tk: &Tokens) -> gpui_kit::Stateful<Div> {
    let frame = div()
        .id("treemap")
        .role(Role::Group)
        .aria_label(t("storage.tabSpace"))
        .relative()
        .w_full()
        .h(px(360.))
        .rounded(px(7.))
        .bg(tk.sunken)
        .border_1()
        .border_color(tk.rule)
        .overflow_hidden();
    if layout.tiles.is_empty() {
        return frame
            .flex()
            .items_center()
            .justify_center()
            .child(kit::faint(t("treemap.empty"), tk));
    }
    let (w, h) = TREEMAP_BOX;
    let children = node.a("children");
    let mut map = frame;
    for (index, tile) in layout.tiles.iter().enumerate() {
        let (x, y, rw, rh) = tile.rect;
        let bytes = tile.bytes;
        let child = tile.child.and_then(|i| children.get(i));
        let fill = match child {
            None => tk.ink3.opacity(0.35),
            Some(c) if !c.b("isDir") => tk.chart2.opacity(0.55),
            Some(_) => tk.chart_cpu.opacity(0.78 - (index % 5) as f32 * 0.08),
        };
        let name = child
            .map(|c| vigil_core::display::shown_line(c.s("name")))
            .unwrap_or_else(|| t("treemap.other"));
        let tip = format!(
            "{}\n{}",
            child
                .map(|c| vigil_core::display::shown(c.s("path")))
                .unwrap_or_else(|| t("treemap.other")),
            size(bytes, 1)
        );
        let drill = tile
            .child
            .filter(|_| child.is_some_and(|c| c.b("isDir") && !c.a("children").is_empty()));
        let open = open.clone();
        let wide = rw / w > 0.07;
        let tall = rh / h > 0.08;
        map = map.child(
            div()
                .id(ElementId::NamedInteger("tm".into(), index as u64))
                .absolute()
                .left(relative((x / w) as f32))
                .top(relative((y / h) as f32))
                .w(relative((rw / w) as f32))
                .h(relative((rh / h) as f32))
                .bg(fill)
                .border_1()
                .border_color(tk.surface)
                .px(px(6.))
                .py(px(4.))
                .overflow_hidden()
                .text_size(px(12.))
                .font_weight(FontWeight::SEMIBOLD)
                .text_color(tk.ink)
                .hover(|s| s.opacity(0.85))
                .role(Role::Button)
                .aria_label(SharedString::from(tip.replace('\n', " ")))
                .tooltip(move |window, cx| gpui_kit::component::tooltip::Tooltip::new(tip.clone()).build(window, cx))
                .when_some(drill, |this, child| {
                    this.on_click(move |_, window, cx| open(child, window, cx))
                })
                .when(wide && tall, |this| {
                    this.child(div().overflow_hidden().text_ellipsis().whitespace_nowrap().child(name))
                        .when(rh / h > 0.13, |this| {
                            this.child(div().font_weight(FontWeight::NORMAL).opacity(0.9).child(size(bytes, 1)))
                        })
                }),
        );
    }
    map
}

/// Squarified treemap (Bruls, Huizing, van Wijk): rectangles (x, y, w, h) for `areas` (largest
/// first) filling a `w` × `h` box.
fn squarify(areas: &[f64], w: f64, h: f64) -> Vec<(f64, f64, f64, f64)> {
    let mut out = Vec::with_capacity(areas.len());
    let (mut x, mut y, mut w, mut h) = (0.0, 0.0, w, h);
    let mut i = 0;
    while i < areas.len() {
        let side = w.min(h);
        let worst = |row: &[f64]| -> f64 {
            let sum: f64 = row.iter().sum();
            let max = row.iter().cloned().fold(f64::MIN, f64::max);
            let min = row.iter().cloned().fold(f64::MAX, f64::min);
            if sum <= 0.0 || min <= 0.0 {
                return f64::MAX;
            }
            (side * side * max / (sum * sum)).max(sum * sum / (side * side * min))
        };
        let mut end = i + 1;
        while end < areas.len() && worst(&areas[i..=end]) <= worst(&areas[i..end]) {
            end += 1;
        }
        let row = &areas[i..end];
        let sum: f64 = row.iter().sum();
        let thickness = if side > 0.0 { sum / side } else { 0.0 };
        let mut offset = 0.0;
        for area in row {
            let length = if thickness > 0.0 { area / thickness } else { 0.0 };
            if w >= h {
                out.push((x, y + offset, thickness, length));
            } else {
                out.push((x + offset, y, length, thickness));
            }
            offset += length;
        }
        if w >= h {
            x += thickness;
            w -= thickness;
        } else {
            y += thickness;
            h -= thickness;
        }
        i = end;
    }
    out
}

impl StoragePage {
    /// Opens child `index` of the open folder (a folder with something inside). Only now is that
    /// subtree copied, once.
    fn open_child(&mut self, index: usize, cx: &mut Context<Self>) {
        let Some(node) = self.path.last() else { return };
        let Some(child) = node.a("children").get(index) else {
            return;
        };
        if child.b("isDir") && !child.a("children").is_empty() {
            let child = Arc::new(child.clone());
            self.path.push(child);
            cx.notify();
        }
    }

    /// The layout of `node`, computed once per opened folder.
    fn layout_of(&mut self, node: &Arc<Value>) -> Arc<Layout> {
        let key = Arc::as_ptr(node) as usize;
        match &self.layout {
            Some((cached, layout)) if *cached == key => Arc::clone(layout),
            _ => {
                let layout = Arc::new(Layout::of(node));
                self.layout = Some((key, Arc::clone(&layout)));
                layout
            }
        }
    }
}

impl Render for StoragePage {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let tk = *tokens(cx);
        let weak = cx.entity().downgrade();
        let weak2 = cx.entity().downgrade();
        let weak3 = cx.entity().downgrade();
        let body = if self.tab_dupes {
            self.dupes_tab(cx, &tk)
        } else if self.tab_space {
            self.space_tab(cx, window, &tk)
        } else {
            self.clean_tab(cx, window, &tk)
        };
        kit::page("storage")
            .child(ui::page_title(t("page.storage")))
            .child(self.drive_cards(cx, &tk))
            .child(
                kit::row()
                    .child(kit::chip(
                        "st-tab-clean",
                        t("storage.tabClean"),
                        None,
                        !self.tab_space && !self.tab_dupes,
                        false,
                        move |_, cx| {
                            let _ = weak.update(cx, |this, cx| {
                                this.tab_space = false;
                                this.tab_dupes = false;
                                cx.notify();
                            });
                        },
                        &tk,
                    ))
                    .child(kit::chip(
                        "st-tab-space",
                        t("storage.tabSpace"),
                        None,
                        self.tab_space && !self.tab_dupes,
                        false,
                        move |_, cx| {
                            let _ = weak2.update(cx, |this, cx| {
                                this.tab_space = true;
                                this.tab_dupes = false;
                                cx.notify();
                            });
                        },
                        &tk,
                    ))
                    .child(kit::chip(
                        "st-tab-dupes",
                        t("dupes.tab"),
                        None,
                        self.tab_dupes,
                        false,
                        move |_, cx| {
                            let _ = weak3.update(cx, |this, cx| {
                                this.tab_dupes = true;
                                cx.notify();
                            });
                        },
                        &tk,
                    )),
            )
            .children(self.acting.bar("st-result", &tk))
            .child(body)
    }
}

#[cfg(test)]
mod tests {
    use super::{Layout, TREEMAP_BOX, squarify};

    #[test]
    fn a_folder_is_laid_out_once_largest_first() {
        let node = serde_json::json!({
            "size": 100.0,
            "other": 5.0,
            "children": [
                {"name": "small", "size": 10.0, "isDir": false},
                {"name": "big", "size": 60.0, "isDir": true, "children": [{"name": "x", "size": 60.0}]},
                {"name": "empty", "size": 0.0, "isDir": true},
                {"name": "mid", "size": 25.0, "isDir": true},
            ]
        });
        let layout = Layout::of(&node);
        assert_eq!(layout.order, vec![1, 3, 0, 2]);
        // Empty entries get no tile; "other" is the last, smallest one.
        let tiles: Vec<Option<usize>> = layout.tiles.iter().map(|t| t.child).collect();
        assert_eq!(tiles, vec![Some(1), Some(3), Some(0), None]);
        let area: f64 = layout.tiles.iter().map(|t| t.rect.2 * t.rect.3).sum();
        assert!((area - TREEMAP_BOX.0 * TREEMAP_BOX.1).abs() < 1e-9);
        assert_eq!(Layout::of(&serde_json::json!({"children": []})), Layout::default());
    }

    #[test]
    fn treemap_fills_the_box() {
        let rects = squarify(&[6.0, 6.0, 4.0, 3.0, 2.0, 2.0, 1.0], 6.0, 4.0);
        let area: f64 = rects.iter().map(|r| r.2 * r.3).sum();
        assert!((area - 24.0).abs() < 1e-9);
        assert!(
            rects
                .iter()
                .all(|r| r.0 >= -1e-9 && r.1 >= -1e-9 && r.0 + r.2 <= 6.0 + 1e-9 && r.1 + r.3 <= 4.0 + 1e-9)
        );
    }
}
