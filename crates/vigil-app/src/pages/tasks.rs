//! Scheduled tasks: every task (Microsoft's hidden by default) with when it runs, its last result
//! and author, risky tasks (run elevated from a folder any user can change) marked, and the
//! selected task's triggers, actions and account. Enable, disable, run and delete go through the
//! action service.

use std::sync::Arc;

use gpui_kit::component::input::InputState;
use gpui_kit::component::table::TableState;
use gpui_kit::prelude::FluentBuilder as _;
use gpui_kit::{
    Context, Div, ElementId, Entity, FocusHandle, Image, InteractiveElement as _, IntoElement, ParentElement, Render,
    StatefulInteractiveElement as _, Styled, Subscription, Window, div, px,
};
use serde_json::{Value, json};
use std::collections::HashMap;
use vigil_core::state::AppState;

use crate::app::Ctx;
use crate::data::{self, Src};
use crate::i18n::{t, tf, tn};
use crate::icons;
use crate::pages::common::{self, Acting, Acts, when};
use crate::pages::dates;
use crate::theme::{Tokens, tokens};
use crate::ui;
use crate::ui::grid::{self, Grid, GridCell, GridCol, GridRow};
use crate::ui::kit::{self, J as _};

fn time_of(start: &str) -> String {
    start.get(11..16).unwrap_or("").to_string()
}

fn date_time_of(start: &str) -> String {
    let core: String = start.chars().take(19).collect();
    if core.len() >= 16 {
        when(&core)
    } else {
        start.to_string()
    }
}

fn units(seconds: i64, keys: [&str; 4]) -> String {
    let (key, n) = if seconds % 86_400 == 0 {
        (keys[0], seconds / 86_400)
    } else if seconds % 3600 == 0 {
        (keys[1], seconds / 3600)
    } else if seconds % 60 == 0 {
        (keys[2], seconds / 60)
    } else {
        (keys[3], seconds)
    };
    tn(key, n.max(0) as u64, &[])
}

fn every(seconds: i64) -> String {
    units(
        seconds,
        [
            "tasks.everyDays",
            "tasks.everyHours",
            "tasks.everyMinutes",
            "tasks.everySeconds",
        ],
    )
}

fn duration(seconds: i64) -> String {
    units(
        seconds,
        ["common.days", "tasks.hours", "tasks.minutes", "tasks.seconds"],
    )
}

fn trigger_text(tr: &Value) -> String {
    let time = time_of(tr.s("start"));
    let days: Vec<String> = tr
        .strs("days")
        .iter()
        .map(|d| dates::weekday(d, tr.a("days").len() > 2))
        .collect();
    let months = if tr.a("months").is_empty() {
        String::new()
    } else {
        let names: Vec<String> = tr.strs("months").iter().map(|m| dates::month(m)).collect();
        format!(" {}", tf("tasks.inMonths", &[("months", &dates::list(&names))]))
    };
    let detail = tr.s("detail");
    let base = match tr.s("kind") {
        "logon" if detail.is_empty() => t("tasks.trigLogon"),
        "logon" => tf("tasks.trigLogonOf", &[("user", detail)]),
        "boot" => t("tasks.trigBoot"),
        "idle" => t("tasks.trigIdle"),
        "registration" => t("tasks.trigRegistration"),
        "event" if detail.is_empty() => t("tasks.trigEvent"),
        "event" => tf("tasks.trigEventIn", &[("log", detail)]),
        "session" => t(match detail {
            "console_connect" => "tasks.trigConsoleConnect",
            "console_disconnect" => "tasks.trigConsoleDisconnect",
            "remote_connect" => "tasks.trigRemoteConnect",
            "remote_disconnect" => "tasks.trigRemoteDisconnect",
            "session_lock" => "tasks.trigLock",
            "session_unlock" => "tasks.trigUnlock",
            _ => "tasks.trigSession",
        }),
        "time" if tr.i("repeatSecs") > 0 && tr.i("repeatForSecs") == 0 => String::new(),
        "time" => tf("tasks.trigTime", &[("time", &date_time_of(tr.s("start")))]),
        "daily" if tr.i("every") > 1 => tn("tasks.trigEveryDays", tr.i("every") as u64, &[("time", &time)]),
        "daily" => tf("tasks.trigDaily", &[("time", &time)]),
        "weekly" if tr.i("every") > 1 => tn(
            "tasks.trigEveryWeeks",
            tr.i("every") as u64,
            &[("days", &dates::list(&days)), ("time", &time)],
        ),
        "weekly" => tf("tasks.trigWeekly", &[("days", &dates::list(&days)), ("time", &time)]),
        "monthly" => {
            let list: Vec<String> = tr
                .strs("days")
                .iter()
                .map(|d| {
                    if *d == "last" {
                        t("tasks.lastDay")
                    } else {
                        d.to_string()
                    }
                })
                .collect();
            tf("tasks.trigMonthly", &[("days", &dates::list(&list)), ("time", &time)]) + &months
        }
        "monthly_dow" => {
            let weeks: Vec<String> = tr
                .strs("weeks")
                .iter()
                .map(|w| match *w {
                    "1" | "2" | "3" | "4" => t(&format!("tasks.week{w}")),
                    _ => t("tasks.weekLast"),
                })
                .collect();
            tf(
                "tasks.trigMonthlyDow",
                &[
                    ("weeks", &dates::list(&weeks)),
                    ("days", &dates::list(&days)),
                    ("time", &time),
                ],
            ) + &months
        }
        _ => t("tasks.trigCustom"),
    };
    let repeat = tr.i("repeatSecs");
    if repeat > 0 {
        let often = every(repeat);
        if base.is_empty() {
            return tf("tasks.trigEvery", &[("every", &often)]);
        }
        if tr.i("repeatForSecs") > 0 {
            return tf(
                "tasks.trigRepeatFor",
                &[
                    ("base", &base),
                    ("every", &often),
                    ("duration", &duration(tr.i("repeatForSecs"))),
                ],
            );
        }
        return tf("tasks.trigRepeat", &[("base", &base), ("every", &often)]);
    }
    base
}

fn trigger_detail(tr: &Value) -> String {
    let mut parts = vec![trigger_text(tr)];
    if tr.i("delaySecs") > 0 {
        parts.push(tf("tasks.delay", &[("duration", &duration(tr.i("delaySecs")))]));
    }
    if tr.i("randomDelaySecs") > 0 {
        parts.push(tf(
            "tasks.randomDelay",
            &[("duration", &duration(tr.i("randomDelaySecs")))],
        ));
    }
    if tr.has("start") && !matches!(tr.s("kind"), "time" | "daily" | "weekly" | "monthly" | "monthly_dow") {
        parts.push(tf("tasks.from", &[("time", &date_time_of(tr.s("start")))]));
    }
    if tr.has("end") {
        parts.push(tf("tasks.until", &[("time", &date_time_of(tr.s("end")))]));
    }
    let text = parts
        .into_iter()
        .filter(|p| !p.is_empty())
        .collect::<Vec<_>>()
        .join(" · ");
    if tr.b("enabled") {
        text
    } else {
        tf("tasks.trigOff", &[("trigger", &text)])
    }
}

fn triggers_of(task: &Value) -> String {
    let triggers = task.a("triggers");
    if triggers.is_empty() {
        return t("tasks.noTrigger");
    }
    let on: Vec<String> = triggers.iter().filter(|tr| tr.b("enabled")).map(trigger_text).collect();
    if on.is_empty() {
        t("tasks.triggersOff")
    } else {
        on.join("; ")
    }
}

/// The last result in words, its code and whether it means success.
fn result_of(task: &Value) -> Option<(String, String, bool)> {
    let raw = task.at("lastResult").as_i64()?;
    let value = raw as u32;
    let code = format!("0x{value:08X}");
    let (key, ok) = match value {
        0x0 => ("tasks.resultOk", true),
        0x41301 => ("tasks.resultRunning", true),
        0x41302 => ("tasks.resultDisabled", true),
        0x41303 => ("tasks.resultNotRun", true),
        0x41306 => ("tasks.resultTerminated", false),
        0x41325 => ("tasks.resultQueued", true),
        0x8004_130F => ("tasks.resultNoAccount", false),
        0x8004_131F => ("tasks.resultAlreadyRunning", false),
        0x8004_1326 => ("tasks.resultDisabled", false),
        0x8007_0002 | 0x8007_0003 => ("tasks.resultNotFound", false),
        0x8007_0005 => ("tasks.resultAccess", false),
        0x8007_010B => ("tasks.resultBadFolder", false),
        0x8007_04DD => ("tasks.resultNotSignedIn", false),
        0x8007_10E0 => ("tasks.resultRefused", false),
        0xC000_013A => ("tasks.resultCtrlC", false),
        v if v < 0x10000 => return Some((tf("tasks.resultExit", &[("code", &v.to_string())]), code, false)),
        _ => return Some((tf("tasks.resultError", &[("code", &code)]), code, false)),
    };
    Some((t(key), code, ok))
}

fn last_run_text(task: &Value) -> String {
    if !task.has("lastRun") {
        return t("tasks.never");
    }
    match result_of(task) {
        Some((text, _, _)) => format!("{} ({text})", when(task.s("lastRun"))),
        None => when(task.s("lastRun")),
    }
}

fn state_rank(state: &str) -> (usize, &'static str) {
    match state {
        "running" => (0, "tasks.stateRunning"),
        "queued" => (1, "tasks.stateQueued"),
        "ready" => (2, "tasks.stateReady"),
        "disabled" => (3, "tasks.stateDisabled"),
        _ => (4, "tasks.stateUnknown"),
    }
}

fn risky(task: &Value) -> bool {
    task.b("elevated") && task.b("userWritable")
}

pub struct TasksPage {
    ctx: Ctx,
    rows: Vec<Value>,
    hide_microsoft: bool,
    icons: HashMap<String, Arc<Image>>,
    loading: bool,
    error: Option<String>,
    table: Entity<TableState<Grid>>,
    search: Entity<InputState>,
    acting: Acting,
    focus: FocusHandle,
    _subscriptions: Vec<Subscription>,
}

impl Acts for TasksPage {
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

impl TasksPage {
    pub fn new(ctx: Ctx, window: &mut Window, cx: &mut Context<Self>) -> Self {
        let cols = vec![
            GridCol::new("name", t("tasks.colName"), 280.),
            GridCol::new("status", t("tasks.colStatus"), 96.),
            GridCol::new("triggers", t("tasks.colTriggers"), 260.),
            GridCol::new("next", t("tasks.colNext"), 150.).date(),
            GridCol::new("last", t("tasks.colLast"), 220.).date(),
            GridCol::new("author", t("tasks.colAuthor"), 150.),
        ];
        let table = grid::new_state(t("tasks.empty"), cols, window, cx);
        let (search, searching) = grid::search(&table, t("tasks.search"), window, cx);
        let subscriptions = vec![searching, cx.observe(&table, |_, _, cx| cx.notify())];
        let mut page = Self {
            ctx,
            rows: Vec::new(),
            hide_microsoft: true,
            icons: HashMap::new(),
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
            move || {
                let rows = data::fetch(core.as_ref(), Src::Tasks);
                let paths: Vec<String> = rows
                    .as_ref()
                    .map(|v| {
                        v.as_array()
                            .map(|a| {
                                a.iter()
                                    .filter(|t| t.b("programExists") && t.s("program").to_lowercase().ends_with(".exe"))
                                    .map(|t| t.s("program").to_string())
                                    .collect()
                            })
                            .unwrap_or_default()
                    })
                    .unwrap_or_default();
                let icons = data::fetch(core.as_ref(), Src::Icons(paths))
                    .ok()
                    .and_then(|v| v.as_object().cloned())
                    .map(|o| {
                        o.iter()
                            .filter_map(|(k, v)| kit::image(v.as_str()?).map(|i| (k.to_lowercase(), i)))
                            .collect()
                    })
                    .unwrap_or_default();
                (rows, icons)
            },
            |this: &mut Self, (result, icons), cx| {
                this.loading = false;
                this.icons = icons;
                match result {
                    Ok(v) => {
                        this.rows = v.as_array().cloned().unwrap_or_default();
                        this.error = None;
                    }
                    Err(e) => this.error = Some(e),
                }
                this.fill(cx);
            },
        );
    }

    fn visible(&self) -> Vec<&Value> {
        self.rows
            .iter()
            .filter(|r| !(self.hide_microsoft && r.b("microsoft")))
            .collect()
    }

    fn fill(&mut self, cx: &mut Context<Self>) {
        let tk = *tokens(cx);
        let mut visible = self.visible();
        visible.sort_by_key(|r| r.s("name").to_lowercase());
        let rows = visible
            .into_iter()
            .map(|task| {
                let (rank, state_key) = state_rank(task.s("state"));
                let mut name =
                    GridCell::text(task.s("name")).image(self.icons.get(&task.s("program").to_lowercase()).cloned());
                if risky(task) {
                    name = name.glyph(icons::WARNING, tk.warn).color(tk.warn);
                } else if !self.icons.contains_key(&task.s("program").to_lowercase()) {
                    name = name.glyph('\u{E737}', tk.ink2);
                }
                let result = result_of(task);
                let mut last = GridCell::text(last_run_text(task));
                last.sort = grid::SortKey::Text(task.s("lastRun").to_string());
                if task.has("lastRun") && result.as_ref().is_some_and(|(_, _, ok)| !ok) {
                    last = last.color(tk.warn);
                }
                let mut next = GridCell::text(if task.has("nextRun") {
                    when(task.s("nextRun"))
                } else {
                    "—".into()
                });
                next.sort = grid::SortKey::Text(task.s("nextRun").to_string());
                let mut args: Vec<&str> = task.a("actions").iter().map(|a| a.s("arguments")).collect();
                args.retain(|a| !a.is_empty());
                let cells = vec![
                    name,
                    GridCell::text(t(state_key)).ranked(rank as f64),
                    GridCell::text(triggers_of(task)),
                    next,
                    last,
                    GridCell::text(task.s("author")),
                ];
                let search = format!(
                    "{} {} {} {} {}",
                    task.s("path"),
                    task.s("author"),
                    task.s("description"),
                    task.s("program"),
                    args.join(" ")
                );
                let mut row = GridRow::new(task.s("path").to_string(), cells, search);
                row.dim = !task.b("enabled");
                row
            })
            .collect();
        grid::fill(&self.table, rows, cx);
    }

    fn current(&self, cx: &gpui_kit::App) -> Option<Value> {
        let key = grid::selected(&self.table, cx)?;
        self.rows.iter().find(|r| r.s("path") == key).cloned()
    }

    fn run(&mut self, op: &str, window: &mut Window, cx: &mut Context<Self>) {
        let Some(task) = self.current(cx) else { return };
        common::send_json(
            self,
            json!({"kind": "task", "op": op, "path": task.s("path")}),
            window,
            cx,
        );
    }

    fn detail(&self, task: &Value, tk: &Tokens) -> Div {
        let (_, state_key) = state_rank(task.s("state"));
        let mut sub = t(state_key);
        if task.b("hidden") {
            sub = format!("{sub} · {}", t("tasks.hidden"));
        }
        let mut pane = kit::panel(tk)
            .child(kit::h3(task.s("name").to_string()))
            .child(kit::faint(sub, tk));
        if risky(task) {
            pane = pane
                .child(
                    kit::row()
                        .child(kit::glyph(icons::WARNING, 14., tk.warn))
                        .child(kit::colored(t("tasks.riskyLabel"), tk.warn)),
                )
                .child(kit::body(t("tasks.riskyTip")));
        }
        let mut n = 0u64;
        let mut fact = |pane: Div, label: String, value: Div| {
            n += 1;
            pane.child(kit::kv(label, value, 130., tk))
        };
        pane = fact(
            pane,
            t("tasks.path"),
            kit::sel(ElementId::Name("tk-path".into()), task.s("path").to_string())
                .font_family(crate::theme::FONT_MONO)
                .text_size(px(12.)),
        );
        if task.has("description") {
            pane = fact(
                pane,
                t("tasks.description"),
                kit::sel("tk-desc", task.s("description").to_string()),
            );
        }
        let triggers = task.a("triggers");
        let trig = if triggers.is_empty() {
            div().child(t("tasks.noTrigger"))
        } else {
            div().flex().flex_col().children(triggers.iter().map(|tr| {
                div()
                    .when(!tr.b("enabled"), |this| this.text_color(tk.ink3))
                    .child(trigger_detail(tr))
            }))
        };
        pane = fact(pane, t("tasks.triggers"), trig);
        let actions = task.a("actions");
        let mut acts = div().flex().flex_col();
        if actions.is_empty() {
            acts = acts.child("—");
        }
        for (i, a) in actions.iter().enumerate() {
            let text = match a.s("kind") {
                "exec" => [a.s("command"), a.s("arguments")]
                    .iter()
                    .filter(|s| !s.is_empty())
                    .copied()
                    .collect::<Vec<_>>()
                    .join(" "),
                "com" => tf("tasks.actionCom", &[("id", a.s("classId"))]),
                "email" => t("tasks.actionEmail"),
                "message" => tf("tasks.actionMessage", &[("title", a.s("data"))]),
                other => other.to_string(),
            };
            acts = acts.child(
                kit::sel(ElementId::NamedInteger("tk-act".into(), i as u64), text)
                    .font_family(crate::theme::FONT_MONO)
                    .text_size(px(12.)),
            );
            if a.s("kind") == "exec" && a.has("program") && a.s("program") != a.s("command") {
                acts = acts.child(kit::faint(tf("tasks.resolved", &[("path", a.s("program"))]), tk));
            }
            if a.s("kind") == "com" && a.has("program") {
                acts = acts.child(kit::faint(tf("tasks.comServer", &[("path", a.s("program"))]), tk));
            }
            if a.has("workingDir") {
                acts = acts.child(kit::faint(tf("tasks.startIn", &[("path", a.s("workingDir"))]), tk));
            }
        }
        pane = fact(pane, t("tasks.actions"), acts);
        let level = t(if task.s("runLevel") == "highest" {
            "tasks.levelHighest"
        } else {
            "tasks.levelLeast"
        });
        let logon = match task.s("logonType") {
            "interactive" => t("tasks.logonInteractive"),
            "password" | "s4u" => t("tasks.logonAlways"),
            _ => String::new(),
        };
        let account = if task.has("account") {
            task.s("account").to_string()
        } else {
            t("tasks.accountUnnamed")
        };
        let runs_as = [account, level, logon]
            .into_iter()
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>()
            .join(" · ");
        pane = fact(pane, t("tasks.runsAs"), div().child(runs_as));
        let mut last = if task.has("lastRun") {
            when(task.s("lastRun"))
        } else {
            t("tasks.never")
        };
        let mut warn = false;
        if let Some((text, code, ok)) = result_of(task) {
            last = format!("{last} · {text} ({code})");
            warn = !ok;
        }
        pane = fact(
            pane,
            t("tasks.lastRunLabel"),
            div().when(warn, |this| this.text_color(tk.warn)).child(last),
        );
        pane = fact(
            pane,
            t("tasks.nextRunLabel"),
            div().child(if task.has("nextRun") {
                when(task.s("nextRun"))
            } else {
                "—".into()
            }),
        );
        if task.has("author") {
            pane = fact(
                pane,
                t("tasks.colAuthor"),
                div().child(kit::plain(task.s("author").to_string())),
            );
        }
        if task.has("created") {
            pane = fact(pane, t("tasks.created"), div().child(date_time_of(task.s("created"))));
        }
        pane = fact(
            pane,
            t("tasks.file"),
            kit::sel("tk-file", task.s("file").to_string())
                .font_family(crate::theme::FONT_MONO)
                .text_size(px(12.)),
        );
        let note = if task.b("microsoft") {
            Some("tasks.microsoftNote")
        } else if !self.ctx.elevated {
            Some("tasks.adminNote")
        } else if task.has("program") && !task.b("programExists") {
            Some("tasks.missingNote")
        } else {
            None
        };
        pane.children(note.map(|k| kit::faint(t(k), tk)))
    }
}

impl Render for TasksPage {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let tk = *tokens(cx);
        let current = self.current(cx);
        let changeable = current.as_ref().is_some_and(|c| !c.b("microsoft")) && self.ctx.elevated && !self.acting.busy;
        let enabled = current.as_ref().is_some_and(|c| c.b("enabled"));
        let target = current
            .as_ref()
            .filter(|c| c.b("programExists"))
            .map(|c| c.s("program").to_string())
            .unwrap_or_default();
        let visible = self.visible();
        let enabled_count = visible.iter().filter(|r| r.b("enabled")).count();
        let hidden = self.rows.len() - visible.len();
        let mut footer = match &self.error {
            Some(e) => e.clone(),
            None => tf(
                "tasks.summary",
                &[
                    ("shown", &self.table.read(cx).delegate().row_count().to_string()),
                    ("total", &visible.len().to_string()),
                    ("enabled", &enabled_count.to_string()),
                ],
            ),
        };
        if self.error.is_none() && hidden > 0 {
            footer = format!("{footer} · {}", tn("tasks.microsoftHidden", hidden as u64, &[]));
        }
        let weak = cx.entity().downgrade();
        let location = target.clone();
        let root = div()
            .track_focus(&self.focus)
            .size_full()
            .flex()
            .flex_col()
            .gap_2()
            .px(px(20.))
            .pt(px(12.))
            .pb(px(12.));
        common::list_keys(root, |p: &TasksPage| p.table.clone(), cx)
            .child(
                div()
                    .flex()
                    .justify_center()
                    .child(div().w_full().max_w(px(640.)).child(ui::search_box(&self.search, &tk))),
            )
            .child(
                kit::row()
                    .child(ui::page_title(t("page.tasks")))
                    .child(
                        div()
                            .id("tk-hide")
                            .tooltip(|window, cx| {
                                gpui_kit::component::tooltip::Tooltip::new(t("tasks.hideMicrosoftTip"))
                                    .build(window, cx)
                            })
                            .child(ui::check_box(
                                "tk-hide-box",
                                self.hide_microsoft,
                                false,
                                t("tasks.hideMicrosoft"),
                                move |on, _, cx| {
                                    let _ = weak.update(cx, |this, cx| {
                                        this.hide_microsoft = on;
                                        this.fill(cx);
                                    });
                                },
                                &tk,
                            )),
                    )
                    .child(
                        ui::CommandBar::new("tk-bar")
                            .cmd(
                                ui::cmd("tk-enable", icons::CHECK, t("tasks.enable"))
                                    .disabled(!(changeable && !enabled))
                                    .on_click(cx.listener(|this, _, window, cx| this.run("enable", window, cx))),
                            )
                            .cmd(
                                ui::cmd("tk-disable", icons::END_TASK, t("tasks.disable"))
                                    .disabled(!(changeable && enabled))
                                    .on_click(cx.listener(|this, _, window, cx| this.run("disable", window, cx))),
                            )
                            .cmd(
                                ui::cmd("tk-run", icons::START, t("tasks.run"))
                                    .disabled(!(changeable && enabled))
                                    .on_click(cx.listener(|this, _, window, cx| this.run("run", window, cx))),
                            )
                            .cmd(
                                ui::cmd("tk-delete", icons::DELETE, t("tasks.delete"))
                                    .disabled(!changeable)
                                    .on_click(cx.listener(|this, _, window, cx| this.run("delete", window, cx))),
                            )
                            .separator()
                            .cmd(
                                ui::cmd("tk-location", icons::FOLDER, t("proc.location"))
                                    .disabled(target.is_empty())
                                    .on_click(cx.listener(move |this, _, window, cx| {
                                        common::send_json(
                                            this,
                                            json!({"kind": "shell", "op": "location", "path": location}),
                                            window,
                                            cx,
                                        )
                                    })),
                            )
                            .cmd(
                                ui::cmd("tk-scheduler", '\u{E787}', t("tasks.openScheduler")).on_click(cx.listener(
                                    |this, _, window, cx| {
                                        common::send_json(
                                            this,
                                            json!({"kind": "shell", "op": "console", "name": "taskschd.msc"}),
                                            window,
                                            cx,
                                        )
                                    },
                                )),
                            )
                            .separator()
                            .cmd(
                                ui::cmd("tk-refresh", icons::REFRESH, t("common.refresh"))
                                    .disabled(self.loading)
                                    .on_click(cx.listener(|this, _, _, cx| this.load(cx))),
                            ),
                    ),
            )
            .child(kit::faint(t("tasks.note"), &tk))
            .children(self.acting.bar("tk-result", &tk))
            .child(
                div()
                    .flex_1()
                    .min_h_0()
                    .flex()
                    .gap_3()
                    .child(grid::sort_row(&self.table, cx))
                    .child(grid::frame(&tk).child(grid::table(&self.table, t("page.tasks"))))
                    .when_some(current, |this, task| {
                        this.child(
                            div()
                                .id("tk-pane")
                                .w(px(400.))
                                .flex_none()
                                .overflow_y_scroll()
                                .child(self.detail(&task, &tk)),
                        )
                    }),
            )
            .child(kit::faint(footer, &tk))
    }
}
