//! The window's content: a Windows 11 NavigationView (hamburger, sections, items with a selection
//! pill, footer) over the Mica base, and the content layer with a rounded top-left corner, as
//! `ui/src/App.svelte` and `Sidebar.svelte` draw it.

use std::sync::Arc;

use gpui_kit::component::WindowExt as _;
use gpui_kit::prelude::FluentBuilder as _;
use gpui_kit::{
    AnyView, AppContext, ClickEvent, Context, Entity, FontWeight, InteractiveElement, IntoElement, ParentElement,
    Render, Role, StatefulInteractiveElement, Styled, Subscription, Window, div, px,
};
use vigil_core::state::AppState;

use crate::i18n::t;
use crate::icons;
use crate::live::Live;
use crate::pages::performance::PerformancePage;
use crate::pages::processes::ProcessesPage;
use crate::theme::{self, Choice, FONT_BODY, FONT_DISPLAY, RADIUS, Tokens, tokens};

/// (key, section) of every page, in the order of the web UI's navigation pane.
pub const PAGES: [(&str, &str); 21] = [
    ("overview", "nav.security"),
    ("findings", "nav.security"),
    ("alerts", "nav.security"),
    ("protection", "nav.security"),
    ("posture", "nav.security"),
    ("firewall", "nav.security"),
    ("accounts", "nav.security"),
    ("extensions", "nav.security"),
    ("quarantine", "nav.security"),
    ("history", "nav.security"),
    ("performance", "nav.live"),
    ("processes", "nav.live"),
    ("network", "nav.live"),
    ("services", "nav.live"),
    ("optimize", "nav.maintenance"),
    ("startup", "nav.maintenance"),
    ("tasks", "nav.maintenance"),
    ("programs", "nav.maintenance"),
    ("storage", "nav.maintenance"),
    ("system", "nav.maintenance"),
    ("reliability", "nav.maintenance"),
];

/// Pages that read live data (the sampler runs only while one is open).
fn is_live(page: &str) -> bool {
    matches!(page, "performance" | "processes")
}

/// How the window starts (from the command line).
pub struct Options {
    pub page: &'static str,
    /// `--pid`: the process the Processes page selects first.
    pub focus_pid: Option<u32>,
    pub demo: bool,
    pub choice: Choice,
    pub mica: bool,
}

pub struct Shell {
    page: &'static str,
    compact: bool,
    live: Entity<Live>,
    core: Option<Arc<AppState>>,
    demo: bool,
    elevated: bool,
    choice: Choice,
    mica: bool,
    content: Option<AnyView>,
    /// `--pid`: the process the Processes page selects first.
    focus_pid: Option<u32>,
    _subscriptions: Vec<Subscription>,
}

impl Shell {
    pub fn new(options: Options, core: Option<Arc<AppState>>, window: &mut Window, cx: &mut Context<Self>) -> Self {
        let Options {
            page,
            focus_pid,
            demo,
            choice,
            mica,
        } = options;
        let live = Live::start(demo, cx);
        // Windows changed its theme: GPUI has just painted the title bar in Windows' theme, so
        // apply Vigil's again (it may be a fixed light or dark).
        let subscriptions = vec![cx.observe_window_appearance(window, |this, window, cx| {
            this.apply_theme(window, cx);
        })];
        let mut shell = Self {
            page,
            compact: false,
            live,
            core,
            demo,
            elevated: vigil_sys::elevation::is_elevated(),
            choice,
            mica,
            content: None,
            focus_pid,
            _subscriptions: subscriptions,
        };
        shell.apply_theme(window, cx);
        shell.open(page, window, cx);
        shell
    }

    fn apply_theme(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let dark = match self.choice {
            Choice::Dark => true,
            Choice::Light => false,
            Choice::System => matches!(
                window.appearance(),
                gpui_kit::WindowAppearance::Dark | gpui_kit::WindowAppearance::VibrantDark
            ),
        };
        let tokens = if dark {
            Tokens::dark(self.mica)
        } else {
            Tokens::light(self.mica)
        };
        theme::apply(tokens, cx);
        crate::win::set_dark_title_bar(window, dark);
        window.refresh();
    }

    fn open(&mut self, page: &'static str, window: &mut Window, cx: &mut Context<Self>) {
        self.page = page;
        let live = self.live.clone();
        let core = self.core.clone();
        self.content = match page {
            "processes" => {
                let pid = self.focus_pid.take();
                Some(cx.new(|cx| ProcessesPage::new(live, core, pid, window, cx)).into())
            }
            "performance" => Some(cx.new(|cx| PerformancePage::new(live, cx)).into()),
            _ => None,
        };
        let active = is_live(page);
        self.live.update(cx, |live, cx| live.set_active(active, cx));
        cx.notify();
    }

    fn open_settings(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let shell = cx.entity().downgrade();
        window.open_dialog(cx, move |dialog, _window, cx| {
            let tk = *tokens(cx);
            let choice_button = |id: &'static str, label: String, choice: Choice| {
                let shell = shell.clone();
                div()
                    .id(id)
                    .px_3()
                    .h(px(32.))
                    .flex()
                    .items_center()
                    .rounded(RADIUS)
                    .border_1()
                    .border_color(tk.control_stroke)
                    .bg(tk.control)
                    .hover(|s| s.bg(tk.control_hover))
                    .child(label)
                    .on_click(move |_: &ClickEvent, window, cx| {
                        let _ = shell.update(cx, |shell, cx| {
                            shell.choice = choice;
                            shell.apply_theme(window, cx);
                        });
                    })
            };
            let language_button = |id: &'static str, label: &'static str, code: &'static str| {
                let shell = shell.clone();
                div()
                    .id(id)
                    .px_3()
                    .h(px(32.))
                    .flex()
                    .items_center()
                    .rounded(RADIUS)
                    .border_1()
                    .border_color(tk.control_stroke)
                    .bg(tk.control)
                    .hover(|s| s.bg(tk.control_hover))
                    .child(label)
                    .on_click(move |_: &ClickEvent, window, cx| {
                        vigil_i18n::set_language(code);
                        let _ = shell.update(cx, |shell, cx| {
                            let page = shell.page;
                            shell.open(page, window, cx);
                        });
                        window.refresh();
                    })
            };
            dialog.title(t("nav.settings")).w(px(520.)).child(
                div()
                    .flex()
                    .flex_col()
                    .gap_3()
                    .child(div().font_weight(FontWeight::SEMIBOLD).child(t("settings.theme")))
                    .child(
                        div()
                            .flex()
                            .gap_2()
                            .child(choice_button("theme-system", t("settings.themeSystem"), Choice::System))
                            .child(choice_button("theme-light", t("settings.themeLight"), Choice::Light))
                            .child(choice_button("theme-dark", t("settings.themeDark"), Choice::Dark)),
                    )
                    .child(div().font_weight(FontWeight::SEMIBOLD).child(t("settings.language")))
                    .child(
                        div()
                            .flex()
                            .flex_wrap()
                            .gap_2()
                            .child(language_button("lang-en", "English", "en"))
                            .child(language_button("lang-es", "Español", "es"))
                            .child(language_button("lang-fr", "Français", "fr"))
                            .child(language_button("lang-pt", "Português (Brasil)", "pt"))
                            .child(language_button("lang-zh", "简体中文", "zh")),
                    )
                    .child(
                        div()
                            .text_size(px(12.))
                            .text_color(tk.ink3)
                            .child(t("gpui.settingsNote")),
                    ),
            )
        });
    }

    fn render_nav(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let tk = *tokens(cx);
        let compact = self.compact;
        let item = |id: &'static str, glyph: char, label: String, active: bool| {
            div()
                .id(id)
                .role(Role::Button)
                .aria_label(label.clone())
                .aria_selected(active)
                .relative()
                .flex()
                .flex_none()
                .items_center()
                .gap(px(14.))
                .h(px(36.))
                .w_full()
                .pl(px(14.))
                .pr(px(12.))
                .rounded(RADIUS)
                .text_color(tk.ink)
                .when(active, |this| this.bg(tk.hover))
                .hover(|s| s.bg(tk.hover))
                .active(|s| s.bg(tk.pressed))
                .when(active, |this| {
                    this.child(
                        div()
                            .absolute()
                            .left(px(0.))
                            .top(px(10.))
                            .w(px(3.))
                            .h(px(16.))
                            .rounded(px(2.))
                            .bg(tk.accent),
                    )
                })
                .child(icons::icon(glyph, 16.0, tk.ink))
                .when(!compact, |this| {
                    this.child(
                        div()
                            .flex_1()
                            .overflow_hidden()
                            .text_ellipsis()
                            .whitespace_nowrap()
                            .child(label),
                    )
                })
        };

        let mut list = div()
            .id("nav-list")
            .flex()
            .flex_col()
            .gap(px(2.))
            .flex_1()
            .min_h_0()
            .overflow_y_scroll();
        let mut previous = "";
        for (index, (key, section)) in PAGES.iter().enumerate() {
            if *section != previous {
                previous = section;
                list = list.child(if compact {
                    div().h(px(1.)).mx(px(10.)).my(px(6.)).bg(tk.rule).flex_none()
                } else {
                    div()
                        .px(px(14.))
                        .pt(px(10.))
                        .pb(px(4.))
                        .text_size(px(12.))
                        .font_weight(FontWeight::SEMIBOLD)
                        .text_color(tk.ink2)
                        .flex_none()
                        .child(t(section))
                });
            }
            let key: &'static str = key;
            list = list.child(
                item(
                    NAV_IDS[index],
                    icons::page(key),
                    t(&format!("page.{key}")),
                    self.page == key,
                )
                .on_click(cx.listener(move |this, _: &ClickEvent, window, cx| this.open(key, window, cx))),
            );
        }

        let status = (!compact).then(|| {
            let (glyph_color, title, note) = if self.elevated {
                (tk.ok, t("nav.administrator"), t("nav.administratorNote"))
            } else {
                (tk.warn, t("nav.readOnly"), t("nav.readOnlyNote"))
            };
            div()
                .flex()
                .flex_col()
                .gap(px(6.))
                .px(px(14.))
                .pt(px(8.))
                .pb(px(10.))
                .mb_1()
                .border_t_1()
                .border_color(tk.rule)
                .child(
                    div()
                        .flex()
                        .items_center()
                        .gap_2()
                        .text_size(px(13.))
                        .font_weight(FontWeight::SEMIBOLD)
                        .text_color(glyph_color)
                        .child(icons::icon(icons::SHIELD, 14.0, glyph_color))
                        .child(title),
                )
                .child(div().text_size(px(12.)).text_color(tk.ink3).child(note))
                .when(self.demo, |this| {
                    this.child(div().text_size(px(12.)).text_color(tk.ink3).child(t("gpui.demo")))
                })
        });

        div()
            .flex()
            .flex_col()
            .flex_none()
            .w(px(if compact { 56. } else { 260. }))
            .h_full()
            .p_1()
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap(px(6.))
                    .h(px(44.))
                    .child(
                        div()
                            .id("hamburger")
                            .role(Role::Button)
                            .aria_label(t(if compact { "nav.expand" } else { "nav.collapse" }))
                            .w(px(40.))
                            .h(px(36.))
                            .flex()
                            .items_center()
                            .justify_center()
                            .rounded(RADIUS)
                            .hover(|s| s.bg(tk.hover))
                            .child(icons::icon(icons::HAMBURGER, 16.0, tk.ink))
                            .on_click(cx.listener(|this, _: &ClickEvent, _, cx| {
                                this.compact = !this.compact;
                                cx.notify();
                            })),
                    )
                    .when(!compact, |this| {
                        this.child(div().text_size(px(12.)).text_color(tk.ink2).child("Vigil"))
                    }),
            )
            .child(
                div().px_1().pb_2().flex().child(
                    div()
                        .id("new-scan")
                        .role(Role::Button)
                        .aria_label(t("nav.newScan"))
                        .flex_1()
                        .flex()
                        .items_center()
                        .justify_center()
                        .gap_2()
                        .h(px(34.))
                        .rounded(RADIUS)
                        .bg(tk.accent)
                        .hover(|s| s.bg(tk.accent_hover))
                        .active(|s| s.bg(tk.accent_pressed))
                        .text_color(tk.on_accent)
                        .font_weight(FontWeight::SEMIBOLD)
                        .child(icons::icon(icons::SCAN, 14.0, tk.on_accent))
                        .when(!compact, |this| this.child(t("nav.newScan"))),
                ),
            )
            .child(list)
            .child(
                div()
                    .flex()
                    .flex_col()
                    .gap(px(2.))
                    .pt(px(6.))
                    .children(status)
                    .child(item("nav-more", icons::MORE, t("nav.more"), false))
                    .child(
                        item("nav-settings", icons::SETTINGS, t("nav.settings"), false)
                            .on_click(cx.listener(|this, _: &ClickEvent, window, cx| this.open_settings(window, cx))),
                    ),
            )
    }
}

/// Element ids of the navigation items (GPUI ids are static strings or numbers).
const NAV_IDS: [&str; 21] = [
    "nav-overview",
    "nav-findings",
    "nav-alerts",
    "nav-protection",
    "nav-posture",
    "nav-firewall",
    "nav-accounts",
    "nav-extensions",
    "nav-quarantine",
    "nav-history",
    "nav-performance",
    "nav-processes",
    "nav-network",
    "nav-services",
    "nav-optimize",
    "nav-startup",
    "nav-tasks",
    "nav-programs",
    "nav-storage",
    "nav-system",
    "nav-reliability",
];

impl Render for Shell {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let tk = *tokens(cx);
        let page = self.page;
        let body = match &self.content {
            Some(view) => view.clone().into_any_element(),
            None => div()
                .size_full()
                .flex()
                .flex_col()
                .gap_3()
                .px(px(28.))
                .py(px(20.))
                .child(
                    div()
                        .font_family(FONT_DISPLAY)
                        .text_size(px(28.))
                        .font_weight(FontWeight::SEMIBOLD)
                        .child(t(&format!("page.{page}"))),
                )
                .child(div().text_color(tk.ink2).child(t("gpui.notPorted")))
                .into_any_element(),
        };
        div()
            .size_full()
            .flex()
            .bg(tk.canvas)
            .text_color(tk.ink)
            .font_family(FONT_BODY)
            .text_size(px(14.))
            .line_height(px(20.))
            .child(self.render_nav(cx))
            .child(
                div()
                    .flex_1()
                    .min_w_0()
                    .h_full()
                    .bg(tk.layer)
                    .border_t_1()
                    .border_l_1()
                    .border_color(tk.layer_stroke)
                    .rounded_tl(px(8.))
                    .overflow_hidden()
                    .child(body),
            )
    }
}
