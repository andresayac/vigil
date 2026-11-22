//! The first-run welcome: four short steps (what Vigil does, administrator or read-only, the AI
//! review, the background watch), then "Start a scan" or "Explore". Shown once (the shared watch
//! state remembers it, so the tray copy and an elevated window agree); More > Welcome opens it
//! again. Escape, the close button or Skip end it at any step.

use gpui_kit::component::WindowExt as _;
use gpui_kit::prelude::FluentBuilder as _;
use gpui_kit::{
    AppContext as _, Context, FontWeight, IntoElement, ParentElement, Render, SharedString, Styled, Window, div, px,
};

use crate::app::Ctx;
use crate::i18n::{t, tf};
use crate::icons;
use crate::theme::tokens;
use crate::ui;
use crate::ui::kit;

/// How many steps the welcome has.
pub const STEPS: usize = 4;

/// The step after `step` (the last one stays).
pub fn next(step: usize) -> usize {
    (step + 1).min(STEPS - 1)
}

/// The step before `step` (the first one stays).
pub fn back(step: usize) -> usize {
    step.saturating_sub(1)
}

pub fn is_last(step: usize) -> bool {
    step + 1 >= STEPS
}

/// Whether the welcome opens by itself at start: once, and never in the demo (there only
/// `--dialog welcome` shows it).
pub fn show_at_start(demo: bool, shown: bool) -> bool {
    !demo && !shown
}

/// A step's title and paragraphs (catalog keys). The rights step says which mode this copy runs in.
pub fn step_keys(step: usize, elevated: bool) -> (&'static str, Vec<&'static str>) {
    match step {
        0 => ("welcome.what.title", vec!["welcome.what.body", "welcome.what.confirm"]),
        1 => (
            "welcome.rights.title",
            vec![
                if elevated {
                    "welcome.rights.admin"
                } else {
                    "welcome.rights.readOnly"
                },
                "welcome.rights.body",
            ],
        ),
        2 => (
            "welcome.ai.title",
            vec!["welcome.ai.body", "welcome.ai.local", "welcome.ai.consent"],
        ),
        _ => (
            "welcome.watch.title",
            vec!["welcome.watch.body", "welcome.watch.signIn"],
        ),
    }
}

/// The glyph of each step.
fn step_glyph(step: usize) -> char {
    match step {
        0 => icons::SHIELD,
        1 => icons::LOCK,
        // Globe: where the AI review may send data.
        2 => '\u{E774}',
        // Bell: the background watch's alerts.
        _ => '\u{EA8F}',
    }
}

pub struct Welcome {
    ctx: Ctx,
    step: usize,
}

impl Welcome {
    fn go(&mut self, step: usize, cx: &mut Context<Self>) {
        self.step = step;
        cx.notify();
    }
}

/// Closes the welcome, then runs `then` on the window (a scan, Settings, the restart).
fn close_then(
    ctx: &Ctx,
    then: fn(&mut crate::shell::Shell, &mut Window, &mut gpui_kit::Context<crate::shell::Shell>),
) -> impl Fn(&gpui_kit::ClickEvent, &mut Window, &mut gpui_kit::App) + 'static {
    let shell = ctx.shell.clone();
    move |_, window, cx| {
        window.close_dialog(cx);
        let _ = shell.update(cx, |shell, cx| then(shell, window, cx));
    }
}

impl Render for Welcome {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let tk = *tokens(cx);
        let step = self.step;
        let elevated = self.ctx.elevated;
        let (title, paragraphs) = step_keys(step, elevated);
        let mut text = div()
            .flex()
            .flex_col()
            .gap_2()
            .flex_1()
            .min_w_0()
            .child(kit::h2(t(title)));
        for key in paragraphs {
            text = text.child(kit::body(t(key)));
        }
        // What each step can open directly.
        let extra = match step {
            1 if !elevated => Some(
                ui::button("wl-restart", t("welcome.rights.restart"))
                    .on_click(close_then(&self.ctx, |s, _, cx| s.restart_elevated(cx))),
            ),
            2 => Some(
                ui::button("wl-ai", t("welcome.ai.settings"))
                    .on_click(close_then(&self.ctx, |s, w, cx| s.open_settings(w, cx))),
            ),
            3 => Some(
                ui::button("wl-watch", t("welcome.watch.settings"))
                    .on_click(close_then(&self.ctx, |s, w, cx| s.open_settings(w, cx))),
            ),
            _ => None,
        };
        text = text.when_some(extra, |this, button| this.child(div().flex().pt_1().child(button)));

        let mut dots = div().flex().gap_2().items_center();
        for i in 0..STEPS {
            dots =
                dots.child(
                    div()
                        .size(px(8.))
                        .rounded(px(4.))
                        .bg(if i == step { tk.accent } else { tk.rule_strong }),
                );
        }
        let progress = tf(
            "welcome.step",
            &[("step", &(step + 1).to_string()), ("count", &STEPS.to_string())],
        );

        let weak = cx.entity().downgrade();
        let move_to = move |to: usize| {
            let weak = weak.clone();
            move |_: &gpui_kit::ClickEvent, _: &mut Window, cx: &mut gpui_kit::App| {
                let _ = weak.update(cx, |this, cx| this.go(to, cx));
            }
        };
        let mut buttons = div().flex().gap_2().items_center().child(
            ui::button("wl-skip", t("welcome.skip"))
                .min_w(px(96.))
                .on_click(|_, window, cx| window.close_dialog(cx)),
        );
        buttons = buttons.child(div().flex_1());
        if step > 0 {
            buttons = buttons.child(
                ui::button("wl-back", t("welcome.back"))
                    .min_w(px(96.))
                    .on_click(move_to(back(step))),
            );
        }
        if is_last(step) {
            buttons = buttons
                .child(
                    ui::button("wl-explore", t("welcome.explore"))
                        .min_w(px(120.))
                        .on_click(|_, window, cx| window.close_dialog(cx)),
                )
                .child(
                    ui::accent_button("wl-scan", t("welcome.startScan"))
                        .min_w(px(120.))
                        .on_click(close_then(&self.ctx, |s, w, cx| s.scan_dialog(w, cx))),
                );
        } else {
            buttons = buttons.child(
                ui::accent_button("wl-next", t("welcome.next"))
                    .min_w(px(120.))
                    .on_click(move_to(next(step))),
            );
        }

        div()
            .flex()
            .flex_col()
            .gap_4()
            .child(
                div()
                    .flex()
                    .gap_4()
                    .items_start()
                    .min_h(px(190.))
                    .child(
                        div()
                            .flex_none()
                            .pt_1()
                            .child(kit::glyph(step_glyph(step), 32., tk.accent)),
                    )
                    .child(text),
            )
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_3()
                    .child(dots)
                    .child(kit::faint(SharedString::from(progress), &tk).font_weight(FontWeight::NORMAL)),
            )
            .child(buttons)
    }
}

/// Opens the welcome (and remembers it was shown, in the shared watch state).
pub fn open(ctx: Ctx, window: &mut Window, cx: &mut gpui_kit::App) {
    open_at(ctx, 0, window, cx);
}

/// Opens the welcome at `step` (`--dialog welcome=N` for previews; 1 is the first step).
pub fn open_at(ctx: Ctx, step: usize, window: &mut Window, cx: &mut gpui_kit::App) {
    if let Some(watcher) = &ctx.watcher {
        let _ = watcher.store.update(|file| file.settings.welcome_shown = true);
    }
    let step = step.min(STEPS - 1);
    let view = cx.new(|_| Welcome { ctx, step });
    window.open_dialog(cx, move |dialog, _, cx| {
        dialog
            .bg(tokens(cx).flyout)
            .title(t("welcome.title"))
            .w(px(620.))
            .child(view.clone())
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn steps_move_forward_and_back_within_bounds() {
        assert_eq!(next(0), 1);
        assert_eq!(next(STEPS - 1), STEPS - 1);
        assert_eq!(back(0), 0);
        assert_eq!(back(2), 1);
        assert!(!is_last(0) && is_last(STEPS - 1));
        // Every step has a title and at least one paragraph, in both modes.
        for step in 0..STEPS {
            for elevated in [true, false] {
                let (title, paragraphs) = step_keys(step, elevated);
                assert!(title.starts_with("welcome.") && !paragraphs.is_empty());
            }
        }
    }

    #[test]
    fn the_rights_step_says_which_mode_this_copy_runs_in() {
        assert!(step_keys(1, true).1.contains(&"welcome.rights.admin"));
        assert!(step_keys(1, false).1.contains(&"welcome.rights.readOnly"));
    }

    #[test]
    fn it_opens_by_itself_once_and_never_in_the_demo() {
        assert!(show_at_start(false, false));
        assert!(!show_at_start(false, true));
        assert!(!show_at_start(true, false));
    }
}
