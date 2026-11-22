//! The Assistant: questions about this computer, answered by the AI agent the person chose with
//! Vigil's read-only tools (`vigil_core::assistant`). It offers a question for each section, shows
//! what the agent read, and links to the pages where the person can see more or act. It never
//! changes anything: a change is made on its page, through the native confirmation.

use futures::StreamExt as _;
use futures::channel::mpsc;
use gpui_kit::component::input::{Input, InputEvent, InputState};
use gpui_kit::prelude::FluentBuilder as _;
use gpui_kit::{
    AppContext as _, Context, Div, Entity, FontWeight, IntoElement, ParentElement, Render, Styled, Subscription,
    Window, div, px,
};
use serde_json::Value;
use vigil_core::assistant::Turn;

use crate::app::Ctx;
use crate::data;
use crate::i18n::{t, tf};
use crate::icons;
use crate::theme::{FONT_MONO, RADIUS_CARD, Tokens, tokens};
use crate::ui;
use crate::ui::kit::{self, J as _};

/// Sections with a suggested question, in the order of the navigation pane.
const STARTERS: [&str; 6] = ["security", "live", "cleanup", "apps", "system", "activity"];

/// Lines of progress kept while the agent works.
const READ_LINES: usize = 8;

/// One turn as the page shows it.
struct Shown {
    user: bool,
    text: String,
    /// (text, page) links of an answer.
    links: Vec<(String, String)>,
    /// The tools the agent called for this answer.
    reads: Vec<String>,
    /// Who answered and where the data went.
    meta: String,
}

pub struct AssistantPage {
    ctx: Ctx,
    input: Entity<InputState>,
    turns: Vec<Shown>,
    running: bool,
    reading: Vec<String>,
    message: Option<String>,
    /// The page the person came from ("" for none).
    from: &'static str,
    _subscriptions: Vec<Subscription>,
}

impl AssistantPage {
    pub fn new(ctx: Ctx, from: &'static str, window: &mut Window, cx: &mut Context<Self>) -> Self {
        let input = cx.new(|cx| InputState::new(window, cx).placeholder(t("assistant.placeholder")));
        if !from.is_empty() {
            let text = about(from);
            input.update(cx, |s, cx| s.set_value(text, window, cx));
        }
        let subscriptions = vec![
            cx.subscribe_in(&input, window, |this, _, event: &InputEvent, window, cx| {
                if let InputEvent::PressEnter { .. } = event {
                    this.send(window, cx);
                }
            }),
        ];
        Self {
            ctx,
            input,
            turns: Vec::new(),
            running: false,
            reading: Vec::new(),
            message: None,
            from,
            _subscriptions: subscriptions,
        }
    }

    /// Opened again from a page (Ask): the question about that page waits in the text box.
    pub fn prefill(&mut self, from: &'static str, window: &mut Window, cx: &mut Context<Self>) {
        self.from = from;
        if !self.running {
            let text = about(from);
            self.input.update(cx, |s, cx| s.set_value(text, window, cx));
        }
        cx.notify();
    }

    /// Asks a suggested question at once.
    fn ask(&mut self, text: String, window: &mut Window, cx: &mut Context<Self>) {
        if self.running {
            return;
        }
        self.input.update(cx, |s, cx| s.set_value(text, window, cx));
        self.send(window, cx);
    }

    /// Sends the question in the text box.
    fn send(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let question = self.input.read(cx).value().trim().to_string();
        if question.is_empty() || self.running {
            return;
        }
        let history: Vec<Turn> = self
            .turns
            .iter()
            .map(|turn| Turn {
                role: if turn.user { "user".into() } else { "assistant".into() },
                text: turn.text.clone(),
            })
            .collect();
        self.turns.push(Shown {
            user: true,
            text: question.clone(),
            links: Vec::new(),
            reads: Vec::new(),
            meta: String::new(),
        });
        self.input.update(cx, |s, cx| s.set_value("", window, cx));
        self.running = true;
        self.reading.clear();
        self.message = None;
        cx.notify();
        let (tx, mut rx) = mpsc::unbounded::<String>();
        let done = match self.ctx.core.clone() {
            Some(core) => crate::actions::ask(
                core,
                question,
                history,
                self.from.to_string(),
                crate::win::hwnd(window),
                tx,
            ),
            None => {
                let (done_tx, done_rx) = futures::channel::oneshot::channel();
                std::thread::spawn(move || {
                    for line in ["get_scan_summary (3.1 KB)", "list_startup (2.4 KB)"] {
                        let _ = tx.unbounded_send(line.to_string());
                        std::thread::sleep(std::time::Duration::from_millis(500));
                    }
                    let _ = done_tx.send(Ok(Some(data::demo("assistantReply"))));
                });
                done_rx
            }
        };
        cx.spawn(async move |this, cx| {
            let follow = this.clone();
            let mut cx2 = cx.clone();
            let progress = async move {
                while let Some(line) = rx.next().await {
                    let _ = follow.update(&mut cx2, |page, cx| {
                        if page.running {
                            if page.reading.len() >= READ_LINES {
                                page.reading.remove(0);
                            }
                            page.reading.push(line);
                            cx.notify();
                        }
                    });
                }
            };
            let (result, ()) = futures::join!(done, progress);
            let _ = this.update(cx, |page, cx| {
                page.running = false;
                match result {
                    Ok(Ok(Some(reply))) => page.turns.push(shown(&reply)),
                    Ok(Ok(None)) | Err(_) => page.message = Some(t("assistant.notStarted")),
                    Ok(Err(error)) => page.message = Some(tf("assistant.error", &[("error", &error)])),
                }
                cx.notify();
            });
        })
        .detach();
    }

    fn clear(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if self.running {
            return;
        }
        self.turns.clear();
        self.message = None;
        self.input.update(cx, |s, cx| s.set_value("", window, cx));
        cx.notify();
    }

    /// The suggested questions and what the assistant can and cannot do.
    fn side(&self, cx: &mut Context<Self>, tk: &Tokens) -> Div {
        let mut list = div().flex().flex_col().gap_2();
        for (index, section) in STARTERS.iter().enumerate() {
            let question = t(&format!("assistant.q.{section}"));
            let label = t(&format!("section.{section}"));
            let ask = question.clone();
            list = list.child(
                ui::FButton::new(("assistant-q", index), ui::Kind::Standard)
                    .accessible_name(question.clone())
                    .disabled(self.running)
                    .w_full()
                    .h_auto()
                    .py(px(10.))
                    .flex_col()
                    .items_start()
                    .gap(px(2.))
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap_2()
                            .text_size(px(12.))
                            .font_weight(FontWeight::SEMIBOLD)
                            .text_color(tk.ink2)
                            .child(icons::icon(icons::section(section), 12.0, tk.ink2))
                            .child(label),
                    )
                    .child(div().text_size(px(13.)).whitespace_normal().child(question))
                    .on_click(cx.listener(move |this, _, window, cx| this.ask(ask.clone(), window, cx))),
            );
        }
        let shell = self.ctx.shell.clone();
        div()
            .w_full()
            .flex()
            .flex_col()
            .gap_3()
            .child(kit::h4(t("assistant.suggested"), tk))
            .child(list)
            .child(kit::faint(t("assistant.privacy"), tk))
            .child(kit::link(
                "assistant-settings",
                t("assistant.configure"),
                move |window, cx| {
                    let _ = shell.update(cx, |shell, cx| shell.open_settings(window, cx));
                },
                tk,
            ))
    }

    /// One turn of the conversation.
    fn turn(&self, index: usize, turn: &Shown, tk: &Tokens) -> Div {
        if turn.user {
            return div().flex().justify_end().child(
                div()
                    .max_w(px(620.))
                    .px(px(14.))
                    .py(px(10.))
                    .rounded(RADIUS_CARD)
                    .bg(tk.brand_soft)
                    .border_1()
                    .border_color(tk.rule)
                    .child(kit::sel(("assistant-you", index), turn.text.clone())),
            );
        }
        let ctx = self.ctx.clone();
        let mut body = div()
            .flex_1()
            .min_w_0()
            .flex()
            .flex_col()
            .gap_2()
            .when(!turn.reads.is_empty(), |this| {
                this.child(
                    div().flex().flex_wrap().gap_2().children(
                        turn.reads
                            .iter()
                            .map(|read| kit::badge(tf("investigate.reading", &[("tool", read)]), None, tk)),
                    ),
                )
            })
            .child(kit::sel(("assistant-answer", index), turn.text.clone()).whitespace_normal());
        if !turn.links.is_empty() {
            let mut links = div().flex().flex_wrap().gap_3();
            for (n, (text, page)) in turn.links.iter().enumerate() {
                let ctx = ctx.clone();
                let page = page.clone();
                links = links.child(kit::link(
                    ("assistant-link", index * 10 + n),
                    text.clone(),
                    move |window, cx| ctx.go(&page, window, cx),
                    tk,
                ));
            }
            body = body.child(links);
        }
        if !turn.meta.is_empty() {
            body = body.child(kit::faint(turn.meta.clone(), tk));
        }
        div()
            .flex()
            .gap_3()
            .child(
                div()
                    .w(px(30.))
                    .h(px(30.))
                    .flex_none()
                    .flex()
                    .items_center()
                    .justify_center()
                    .rounded(px(8.))
                    .bg(tk.brand_soft)
                    .child(icons::icon(icons::section("assistant"), 14.0, tk.brand)),
            )
            .child(body)
    }
}

/// The question about a page that Ask puts in the text box.
fn about(page: &str) -> String {
    tf("assistant.aboutPage", &[("page", &t(&format!("page.{page}")))])
}

/// A reply of the core as the page shows it.
fn shown(reply: &Value) -> Shown {
    let mut meta = tf("investigate.destination", &[("destination", reply.s("destination"))]);
    if reply.b("local") {
        meta = format!("{meta} {}", t("investigate.local"));
    } else if reply.b("anonymized") {
        meta = format!("{meta} {}", t("investigate.anonymized"));
    }
    Shown {
        user: false,
        text: reply.s("answer").to_string(),
        links: reply
            .a("links")
            .iter()
            .map(|l| (l.s("text").to_string(), l.s("page").to_string()))
            .filter(|(text, page)| !text.is_empty() && !page.is_empty())
            .collect(),
        reads: reply.a("calls").iter().map(|c| c.s("name").to_string()).collect(),
        meta,
    }
}

impl Render for AssistantPage {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let tk = *tokens(cx);
        let mut talk = div().flex().flex_col().gap_4();
        if self.turns.is_empty() {
            talk = talk
                .child(kit::h2(t("assistant.introTitle")))
                .child(kit::muted(t("assistant.intro"), &tk));
        }
        for (index, turn) in self.turns.iter().enumerate() {
            talk = talk.child(self.turn(index, turn, &tk));
        }
        if self.running {
            talk = talk.child(
                div()
                    .flex()
                    .flex_col()
                    .gap_2()
                    .child(
                        kit::row()
                            .child(kit::body(t("assistant.thinking")))
                            .child(div().flex_1())
                            .child(
                                ui::button("assistant-stop", t("investigate.stop"))
                                    .glyph(icons::CANCEL)
                                    .on_click(|_, _, _| vigil_core::assistant::cancel()),
                            ),
                    )
                    .child(kit::busy_bar("assistant-busy", &tk))
                    .children(self.reading.iter().map(|line| {
                        kit::faint(tf("investigate.reading", &[("tool", line)]), &tk).font_family(FONT_MONO)
                    })),
            );
        }
        if let Some(message) = &self.message {
            talk = talk.child(kit::colored(message.clone(), tk.warn));
        }
        let composer = div()
            .flex()
            .flex_col()
            .gap_2()
            .pt_3()
            .border_t_1()
            .border_color(tk.rule)
            .child(
                kit::row()
                    .child(
                        div()
                            .flex_1()
                            .min_w_0()
                            .child(Input::new(&self.input).aria_label(t("assistant.placeholder"))),
                    )
                    .child(
                        ui::accent_button("assistant-send", t("assistant.send"))
                            .disabled(self.running)
                            .on_click(cx.listener(|this, _, window, cx| this.send(window, cx))),
                    )
                    .when(!self.turns.is_empty(), |this| {
                        this.child(
                            ui::button("assistant-clear", t("assistant.clear"))
                                .disabled(self.running)
                                .on_click(cx.listener(|this, _, window, cx| this.clear(window, cx))),
                        )
                    }),
            )
            .child(kit::faint(t("assistant.readOnly"), &tk));
        let conversation = kit::panel(&tk)
            .flex_1()
            .min_w_0()
            .flex()
            .flex_col()
            .gap_4()
            .child(talk)
            .child(composer);
        let side = self.side(cx, &tk);
        kit::page("assistant-page").child(kit::columns(0.26, side, conversation, window))
    }
}
