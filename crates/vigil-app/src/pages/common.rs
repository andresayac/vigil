//! What every page shares: sending a request through the action service and showing its result,
//! reading in the background, moving a grid's selection from the keyboard, and dates.

use std::sync::Arc;

use futures::StreamExt as _;
use futures::channel::mpsc;
use gpui_kit::component::table::TableState;
use gpui_kit::{App, AppContext as _, Context, Entity, IntoElement, Window};
use vigil_core::requests::Request;
use vigil_core::state::AppState;

use crate::actions::{self, Outcome};
use crate::i18n::t;
use crate::theme::Tokens;
use crate::ui::grid::{Grid, PAGE};
use crate::ui::{Severity, info_bar};

/// A request in flight and the result of the last one.
#[derive(Default)]
pub struct Acting {
    pub busy: bool,
    pub outcome: Option<Outcome>,
    pub progress: Option<String>,
}

impl Acting {
    /// The InfoBar for the progress or the last result (`None`: nothing to say).
    pub fn bar(&self, id: &'static str, tk: &Tokens) -> Option<gpui_kit::AnyElement> {
        let (severity, text) = match (&self.progress, &self.outcome) {
            (Some(line), _) => (Severity::Info, line.clone()),
            (None, Some(Outcome::Done(lines))) if !lines.is_empty() => (Severity::Success, lines.join("\n")),
            (None, Some(Outcome::Failed(error))) => (Severity::Error, error.clone()),
            _ => return None,
        };
        Some(info_bar(id, severity, text, None, tk).into_any_element())
    }
}

/// A page that can send requests.
pub trait Acts: Sized + 'static {
    fn acting(&mut self) -> &mut Acting;
    fn core(&self) -> Option<Arc<AppState>>;
    /// Called after a request that did something (read the page's data again).
    fn after(&mut self, window: &mut Window, cx: &mut Context<Self>);
}

/// Sends `request` through `vigil_core::service::run_action` (checked, confirmed natively,
/// journaled). In the demo nothing runs: the page says so.
pub fn send<T: Acts>(this: &mut T, request: Request, window: &mut Window, cx: &mut Context<T>) {
    let Some(core) = this.core() else {
        this.acting().outcome = Some(Outcome::Failed(t("app.demoNoActions")));
        cx.notify();
        return;
    };
    if this.acting().busy {
        return;
    }
    let (progress_tx, mut progress_rx) = mpsc::unbounded::<String>();
    let done = actions::run(core, request, crate::win::hwnd(window), progress_tx);
    let acting = this.acting();
    acting.busy = true;
    acting.outcome = None;
    cx.notify();
    cx.spawn_in(window, async move |this, cx| {
        let follow = this.clone();
        let mut cx2 = cx.clone();
        let progress = async move {
            while let Some(line) = progress_rx.next().await {
                let _ = follow.update(&mut cx2, |page, cx| {
                    page.acting().progress = Some(line);
                    cx.notify();
                });
            }
        };
        let (outcome, ()) = futures::join!(done, progress);
        let _ = this.update_in(cx, |page, window, cx| {
            let outcome = outcome.unwrap_or(Outcome::Cancelled);
            let changed = matches!(outcome, Outcome::Done(_));
            let acting = page.acting();
            acting.busy = false;
            acting.progress = None;
            acting.outcome = Some(outcome);
            if changed {
                page.after(window, cx);
            }
            cx.notify();
        });
    })
    .detach();
}

/// Sends a request written as the JSON the pages describe it with (`{"kind": "task", "op":
/// "enable", "path": ...}`); Rust still rebuilds and checks everything from its own state.
pub fn send_json<T: Acts>(this: &mut T, request: serde_json::Value, window: &mut Window, cx: &mut Context<T>) {
    match serde_json::from_value::<Request>(request) {
        Ok(request) => send(this, request, window, cx),
        Err(error) => {
            this.acting().outcome = Some(Outcome::Failed(error.to_string()));
            cx.notify();
        }
    }
}

/// Reads `work` on a background thread and hands the result to `done` on the UI thread.
pub fn read<T: 'static, R: Send + 'static>(
    cx: &mut Context<T>,
    work: impl FnOnce() -> R + Send + 'static,
    done: impl FnOnce(&mut T, R, &mut Context<T>) + 'static,
) {
    let task = cx.background_spawn(async move { work() });
    cx.spawn(async move |this, cx| {
        let result = task.await;
        let _ = this.update(cx, |page, cx| {
            done(page, result, cx);
            cx.notify();
        });
    })
    .detach();
}

/// Moves a grid's selection (`isize::MIN` / `MAX`: first / last) and scrolls it into view.
pub fn step(table: &Entity<TableState<Grid>>, delta: isize, cx: &mut App) {
    table.update(cx, |table, cx| {
        if let Some(ix) = table.delegate_mut().step(delta) {
            table.scroll_to_row(ix, cx);
        }
        cx.notify();
    });
}

/// The six list keys, wired to a grid: put this on the page's root.
pub fn list_keys<T: 'static>(
    root: gpui_kit::Div,
    table: impl Fn(&T) -> Entity<TableState<Grid>> + Clone + 'static,
    cx: &mut Context<T>,
) -> gpui_kit::Div {
    use crate::ui::grid::{PageNext, PagePrevious, SelectFirst, SelectLast, SelectNext, SelectPrevious};
    use gpui_kit::InteractiveElement as _;
    let (a, b, c, d, e, f) = (
        table.clone(),
        table.clone(),
        table.clone(),
        table.clone(),
        table.clone(),
        table,
    );
    root.key_context(crate::ui::grid::KEY_CONTEXT)
        .on_action(cx.listener(move |this, _: &SelectPrevious, _, cx| step(&a(this), -1, cx)))
        .on_action(cx.listener(move |this, _: &SelectNext, _, cx| step(&b(this), 1, cx)))
        .on_action(cx.listener(move |this, _: &SelectFirst, _, cx| step(&c(this), isize::MIN, cx)))
        .on_action(cx.listener(move |this, _: &SelectLast, _, cx| step(&d(this), isize::MAX, cx)))
        .on_action(cx.listener(move |this, _: &PagePrevious, _, cx| step(&e(this), -PAGE, cx)))
        .on_action(cx.listener(move |this, _: &PageNext, _, cx| step(&f(this), PAGE, cx)))
}

/// A local ISO time from the core ("2026-01-01T10:05:00") in the language's date order.
pub fn when(iso: &str) -> String {
    let text = iso.trim();
    if text.len() < 10 {
        return text.to_string();
    }
    let (date, time) = text.split_at(10);
    let mut parts = date.split('-');
    let (Some(y), Some(m), Some(d)) = (parts.next(), parts.next(), parts.next()) else {
        return text.replace('T', " ");
    };
    let time: String = time.trim_start_matches('T').chars().take(5).collect();
    let day = match crate::i18n::language() {
        "en" => format!("{}/{}/{y}", m.trim_start_matches('0'), d.trim_start_matches('0')),
        "es" => format!("{}/{}/{y}", d.trim_start_matches('0'), m.trim_start_matches('0')),
        "zh" => format!("{y}/{}/{}", m.trim_start_matches('0'), d.trim_start_matches('0')),
        _ => format!("{d}/{m}/{y}"),
    };
    if time.is_empty() { day } else { format!("{day} {time}") }
}

/// A day ("2026-03-04") without its year, for chart labels ("3/4", "4/3", "04/03").
pub fn day_short(date: &str) -> String {
    let mut parts = date.get(..10).unwrap_or(date).split('-');
    let (Some(_), Some(m), Some(d)) = (parts.next(), parts.next(), parts.next()) else {
        return date.to_string();
    };
    match crate::i18n::language() {
        "en" | "zh" => format!("{}/{}", m.trim_start_matches('0'), d.trim_start_matches('0')),
        "es" => format!("{}/{}", d.trim_start_matches('0'), m.trim_start_matches('0')),
        _ => format!("{d}/{m}"),
    }
}

/// A moment in milliseconds as a local date and time.
pub fn when_ms(ms: i64) -> String {
    when(&crate::ui::kit::local_iso(ms))
}

#[cfg(test)]
mod tests {
    use super::when;

    #[test]
    fn dates_follow_the_language() {
        assert_eq!(
            vigil_i18n::with_language("en", || when("2026-03-04T10:05:00")),
            "3/4/2026 10:05"
        );
        assert_eq!(
            vigil_i18n::with_language("es", || when("2026-03-04T10:05")),
            "4/3/2026 10:05"
        );
        assert_eq!(vigil_i18n::with_language("fr", || when("2026-03-04")), "04/03/2026");
        assert_eq!(
            vigil_i18n::with_language("zh", || when("2026-03-04T10:05")),
            "2026/3/4 10:05"
        );
    }
}
