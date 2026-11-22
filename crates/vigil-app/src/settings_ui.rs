//! Settings: appearance, the AI agent (provider, endpoint, model with the models an API offers,
//! effort, API key kept in Windows Credential Manager, anonymization), the scan, safety, the
//! background watch and the process list. Keys never come back from the core: the dialog only
//! knows whether one is stored.

use std::collections::HashMap;
use std::sync::Arc;

use gpui_kit::component::WindowExt as _;
use gpui_kit::component::input::{Input, InputState};
use gpui_kit::component::menu::{DropdownMenu as _, PopupMenuItem};
use gpui_kit::prelude::FluentBuilder as _;
use gpui_kit::{
    AnyElement, AppContext as _, Context, Div, ElementId, Entity, FontWeight, InteractiveElement as _, IntoElement,
    ParentElement, Render, StatefulInteractiveElement as _, Styled, Window, div, px,
};
use serde_json::{Value, json};
use vigil_core::settings::View;
use vigil_core::state::AppState;
use vigil_core::watch::WatchSettings;

use crate::app::Ctx;
use crate::data::{self, Src};
use crate::dialogs::provider_name;
use crate::i18n::{t, tf, tn};
use crate::icons;
use crate::pages::common::{self, Acting, Acts};
use crate::theme::{FONT_MONO, Tokens, tokens};
use crate::ui::kit::{self, J as _};
use crate::ui::{self, FButton, Kind};

const LANGUAGES: [(&str, &str); 5] = [
    ("en", "English"),
    ("es", "Español"),
    ("fr", "Français"),
    ("pt", "Português (Brasil)"),
    ("zh", "简体中文"),
];

#[derive(Clone, Copy, PartialEq)]
enum Secret {
    Keep,
    Replace,
    Remove,
}

pub struct SettingsView {
    ctx: Ctx,
    draft: Option<View>,
    watch: Option<WatchSettings>,
    autostart: bool,
    providers: Vec<Value>,
    endpoint: Entity<InputState>,
    model: Entity<InputState>,
    keys: HashMap<String, Entity<InputState>>,
    /// The time of the automatic scan ("HH:MM").
    scan_time: Entity<InputState>,
    modes: HashMap<String, Secret>,
    models: Vec<String>,
    models_note: Option<String>,
    fetching: bool,
    error: Option<String>,
    saving: bool,
    acting: Acting,
}

impl Acts for SettingsView {
    fn acting(&mut self) -> &mut Acting {
        &mut self.acting
    }
    fn core(&self) -> Option<Arc<AppState>> {
        self.ctx.core.clone()
    }
    fn after(&mut self, _: &mut Window, cx: &mut Context<Self>) {
        self.read_watch();
        cx.notify();
    }
}

impl SettingsView {
    fn new(ctx: Ctx, window: &mut Window, cx: &mut Context<Self>) -> Self {
        let endpoint = cx.new(|cx| InputState::new(window, cx));
        let model = cx.new(|cx| InputState::new(window, cx));
        let scan_time = cx.new(|cx| InputState::new(window, cx).placeholder("12:30"));
        let keys = ["openai-compatible", "anthropic-compatible", "virustotal"]
            .iter()
            .map(|id| {
                let input = cx.new(|cx| {
                    InputState::new(window, cx)
                        .masked(true)
                        .placeholder(t("settings.pasteKey"))
                });
                (id.to_string(), input)
            })
            .collect();
        let mut view = Self {
            ctx,
            draft: None,
            watch: None,
            autostart: false,
            providers: Vec::new(),
            endpoint,
            model,
            keys,
            scan_time,
            modes: HashMap::new(),
            models: Vec::new(),
            models_note: None,
            fetching: false,
            error: None,
            saving: false,
            acting: Acting::default(),
        };
        view.read_watch();
        if let Some(time) = view.watch.as_ref().map(|w| w.scan_time.clone()) {
            view.scan_time.update(cx, |s, cx| s.set_value(time, window, cx));
        }
        let core = view.ctx.core.clone();
        let weak = cx.entity().downgrade();
        let task = cx.background_spawn(async move {
            let settings = data::fetch(core.as_ref(), Src::Settings).ok();
            let providers = data::fetch(core.as_ref(), Src::AiProviders).ok();
            (settings, providers)
        });
        window
            .spawn(cx, async move |cx| {
                let (settings, providers) = task.await;
                let _ = cx.update(|window, cx| {
                    let _ = weak.update(cx, |this, cx| {
                        this.providers = providers.and_then(|v| v.as_array().cloned()).unwrap_or_default();
                        this.draft = settings.and_then(|v| serde_json::from_value::<View>(v).ok());
                        if let Some(draft) = &this.draft {
                            let (endpoint, model) = (draft.ai.endpoint.clone(), draft.ai.model.clone());
                            this.endpoint.update(cx, |s, cx| s.set_value(endpoint, window, cx));
                            this.model.update(cx, |s, cx| s.set_value(model, window, cx));
                        }
                        cx.notify();
                    });
                });
            })
            .detach();
        view
    }

    fn read_watch(&mut self) {
        match &self.ctx.watcher {
            Some(w) => {
                let status = w.status();
                self.watch = Some(status.settings.clone());
                self.autostart = status.autostart;
            }
            None if self.ctx.demo() => {
                let status = data::demo("watchStatus");
                self.watch = serde_json::from_value(status.at("settings").clone()).ok();
                self.autostart = status.b("autostart");
            }
            None => self.watch = None,
        }
    }

    fn provider(&self) -> Option<&Value> {
        let id = self.draft.as_ref()?.ai.provider.as_str();
        self.providers.iter().find(|p| p.s("id") == id)
    }

    fn mode(&self, id: &str) -> Secret {
        self.modes.get(id).copied().unwrap_or_else(|| {
            if self
                .draft
                .as_ref()
                .is_some_and(|d| d.secrets.get(id).copied().unwrap_or(false))
            {
                Secret::Keep
            } else {
                Secret::Replace
            }
        })
    }

    fn set_provider(&mut self, id: String, window: &mut Window, cx: &mut Context<Self>) {
        if let Some(draft) = &mut self.draft {
            draft.ai.provider = id;
            draft.ai.model.clear();
            draft.ai.endpoint.clear();
        }
        self.models.clear();
        self.models_note = None;
        self.endpoint.update(cx, |s, cx| s.set_value("", window, cx));
        self.model.update(cx, |s, cx| s.set_value("", window, cx));
        cx.notify();
    }

    fn fetch_models(&mut self, cx: &mut Context<Self>) {
        let Some(provider) = self.provider().map(|p| p.s("id").to_string()) else {
            return;
        };
        let endpoint = self.endpoint.read(cx).value().trim().to_string();
        let endpoint = if endpoint.is_empty() {
            self.provider()
                .map(|p| p.s("defaultEndpoint").to_string())
                .unwrap_or_default()
        } else {
            endpoint
        };
        self.fetching = true;
        let core = self.ctx.core.clone();
        common::read(
            cx,
            move || data::fetch(core.as_ref(), Src::AiModels(provider, endpoint)),
            |this: &mut Self, result, _| {
                this.fetching = false;
                match result {
                    Ok(v) => {
                        this.models = v
                            .as_array()
                            .map(|a| a.iter().filter_map(|m| m.as_str().map(str::to_string)).collect())
                            .unwrap_or_default();
                        this.models_note = Some(if this.models.is_empty() {
                            t("settings.ai.noModels")
                        } else {
                            tn("settings.ai.modelsFound", this.models.len() as u64, &[])
                        });
                    }
                    Err(e) => this.models_note = Some(e),
                }
            },
        );
    }

    fn save(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let Some(mut draft) = self.draft.clone() else { return };
        draft.ai.endpoint = self.endpoint.read(cx).value().trim().to_string();
        draft.ai.model = self.model.read(cx).value().trim().to_string();
        let mut secrets: HashMap<String, Option<String>> = HashMap::new();
        for (id, input) in &self.keys {
            match self.mode(id) {
                Secret::Remove => {
                    secrets.insert(id.clone(), Some(String::new()));
                }
                Secret::Replace => {
                    let value = input.read(cx).value().trim().to_string();
                    if !value.is_empty() {
                        secrets.insert(id.clone(), Some(value));
                    }
                }
                Secret::Keep => {}
            }
        }
        self.saving = true;
        let language = match &self.ctx.core {
            Some(core) => match vigil_core::api::settings_set(core, &draft, &secrets) {
                Ok((_, language)) => language.to_string(),
                Err(e) => {
                    self.saving = false;
                    self.error = Some(e);
                    cx.notify();
                    return;
                }
            },
            None => vigil_i18n::set_language(&draft.language).to_string(),
        };
        if let Some(settings) = &mut self.watch {
            let typed = self.scan_time.read(cx).value().trim().to_string();
            if valid_time(&typed) {
                settings.scan_time = typed;
            }
        }
        if let (Some(watcher), Some(settings)) = (&self.ctx.watcher, self.watch.clone()) {
            watcher.set_language(&language);
            let resumed = watcher.store.update(|file| {
                let resumed = settings.watching && !file.settings.watching;
                file.settings = WatchSettings {
                    tray_notice_shown: file.settings.tray_notice_shown,
                    ..settings
                };
                resumed
            });
            if resumed == Ok(true) {
                watcher.check_soon();
            }
        }
        let theme = crate::theme::Choice::parse(&draft.theme);
        let _ = self
            .ctx
            .shell
            .update(cx, |shell, cx| shell.apply_settings(theme, window, cx));
        crate::platform::Tray::refresh();
        window.close_dialog(cx);
    }

    fn row(&self, label: String, note: Option<String>, control: AnyElement, tk: &Tokens) -> Div {
        div()
            .flex()
            .gap_4()
            .items_center()
            .min_h(px(56.))
            .px_4()
            .py_2()
            .bg(tk.surface)
            .border_1()
            .border_color(tk.rule)
            .rounded(px(6.))
            .child(
                div()
                    .flex_1()
                    .min_w_0()
                    .child(kit::body(label))
                    .children(note.map(|n| kit::faint(n, tk))),
            )
            .child(div().flex_none().max_w(px(380.)).child(control))
    }

    fn secret(
        &self,
        id: &'static str,
        label: String,
        note: Option<String>,
        cx: &mut Context<Self>,
        tk: &Tokens,
    ) -> Div {
        let stored = self
            .draft
            .as_ref()
            .is_some_and(|d| d.secrets.get(id).copied().unwrap_or(false));
        let note = format!("{} {}", note.unwrap_or_default(), t("settings.secretNote"))
            .trim()
            .to_string();
        let set = |mode: Secret| {
            cx.listener(move |this: &mut Self, _, window: &mut Window, cx: &mut Context<Self>| {
                this.modes.insert(id.to_string(), mode);
                if mode != Secret::Replace
                    && let Some(input) = this.keys.get(id)
                {
                    input.update(cx, |s, cx| s.set_value("", window, cx));
                }
                cx.notify();
            })
        };
        let control: AnyElement = match self.mode(id) {
            Secret::Keep => kit::row()
                .child(kit::glyph(icons::CHECK, 14., tk.ok))
                .child(kit::colored(t("settings.saved"), tk.ok))
                .child(
                    ui::button(
                        ElementId::Name(format!("se-replace-{id}").into()),
                        t("settings.replace"),
                    )
                    .on_click(set(Secret::Replace)),
                )
                .child(
                    ui::button(ElementId::Name(format!("se-remove-{id}").into()), t("settings.remove"))
                        .on_click(set(Secret::Remove)),
                )
                .into_any_element(),
            Secret::Remove => kit::row()
                .child(kit::faint(t("settings.willRemove"), tk))
                .child(
                    ui::button(ElementId::Name(format!("se-undo-{id}").into()), t("settings.undo"))
                        .on_click(set(Secret::Keep)),
                )
                .into_any_element(),
            Secret::Replace => {
                let input = self.keys.get(id).cloned();
                kit::row()
                    .children(input.map(|i| div().w(px(240.)).child(Input::new(&i))))
                    .when(stored, |this| {
                        this.child(
                            ui::button(ElementId::Name(format!("se-cancel-{id}").into()), t("common.cancel"))
                                .on_click(set(Secret::Keep)),
                        )
                    })
                    .into_any_element()
            }
        };
        self.row(label, Some(note), control, tk)
    }
}

fn is_local(endpoint: &str) -> bool {
    let Some(rest) = endpoint
        .strip_prefix("http://")
        .or_else(|| endpoint.strip_prefix("https://"))
    else {
        return false;
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let host = match authority.strip_prefix('[') {
        Some(v6) => v6.split(']').next().unwrap_or(""),
        None => authority.split(':').next().unwrap_or(""),
    };
    host.eq_ignore_ascii_case("localhost") || host.starts_with("127.") || host == "::1"
}

impl Render for SettingsView {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let tk = *tokens(cx);
        let Some(draft) = self.draft.clone() else {
            return div().p_4().child(kit::faint(t("common.reading"), &tk));
        };
        let mut body = div().flex().flex_col().gap_2();
        // Appearance.
        body = body.child(kit::h3(t("settings.appearance")));
        let weak = cx.entity().downgrade();
        body = body.child(
            self.row(
                t("settings.theme"),
                None,
                ui::segmented(
                    "se-theme",
                    t("settings.theme"),
                    vec![
                        ("system", t("settings.themeSystem")),
                        ("light", t("settings.themeLight")),
                        ("dark", t("settings.themeDark")),
                    ],
                    match draft.theme.as_str() {
                        "light" => "light",
                        "dark" => "dark",
                        _ => "system",
                    },
                    move |v: &'static str, _, cx| {
                        let _ = weak.update(cx, |this, cx| {
                            if let Some(d) = &mut this.draft {
                                d.theme = v.to_string();
                            }
                            cx.notify();
                        });
                    },
                    &tk,
                )
                .into_any_element(),
                &tk,
            ),
        );
        let weak = cx.entity().downgrade();
        let current = draft.language.clone();
        let label = if current == "auto" {
            t("settings.languageAuto")
        } else {
            LANGUAGES
                .iter()
                .find(|(c, _)| *c == current)
                .map(|(_, n)| n.to_string())
                .unwrap_or(current.clone())
        };
        body = body.child(
            self.row(
                t("settings.language"),
                Some(t("settings.languageNote")),
                FButton::new("se-language", Kind::Standard)
                    .label(label)
                    .accessible_name(t("settings.language"))
                    .chevron()
                    .dropdown_menu(move |menu, _, _| {
                        let mut menu = menu;
                        for (code, name) in std::iter::once(("auto", t("settings.languageAuto")))
                            .chain(LANGUAGES.iter().map(|(c, n)| (*c, n.to_string())))
                        {
                            let weak = weak.clone();
                            menu = menu.item(PopupMenuItem::new(name).checked(current == code).on_click(
                                move |_, _, cx| {
                                    let _ = weak.update(cx, |this, cx| {
                                        if let Some(d) = &mut this.draft {
                                            d.language = code.to_string();
                                        }
                                        cx.notify();
                                    });
                                },
                            ));
                        }
                        menu
                    })
                    .into_any_element(),
                &tk,
            ),
        );

        // The AI agent.
        body = body.child(kit::h3(t("settings.ai.title")));
        let provider = self.provider().cloned();
        let provider_id = draft.ai.provider.clone();
        let name = provider_name(provider.as_ref(), &provider_id);
        let weak = cx.entity().downgrade();
        let providers = self.providers.clone();
        let menu_current = provider_id.clone();
        body = body.child(
            self.row(
                t("settings.ai.provider"),
                Some(t("settings.ai.providerNote")),
                FButton::new("se-provider", Kind::Standard)
                    .label(name.clone())
                    .accessible_name(t("settings.ai.provider"))
                    .chevron()
                    .dropdown_menu(move |menu, _, _| {
                        let mut menu = menu;
                        let pick = |id: String, label: String, menu: gpui_kit::component::menu::PopupMenu| {
                            let weak = weak.clone();
                            let on = menu_current == id;
                            menu.item(PopupMenuItem::new(label).checked(on).on_click(move |_, window, cx| {
                                let id = id.clone();
                                let _ = weak.update(cx, |this, cx| this.set_provider(id, window, cx));
                            }))
                        };
                        menu = pick("auto".into(), t("ai.automatic"), menu);
                        for (kind, title) in [("api", "settings.ai.apis"), ("local-agent", "settings.ai.localAgents")] {
                            let group: Vec<&Value> = providers.iter().filter(|p| p.s("kind") == kind).collect();
                            if group.is_empty() {
                                continue;
                            }
                            menu = menu.separator().label(t(title));
                            for p in group {
                                let mut label = p.s("name").to_string();
                                if !p.b("available") {
                                    label = format!("{label} — {}", t("settings.ai.notAvailableShort"));
                                }
                                menu = pick(p.s("id").to_string(), label, menu);
                            }
                        }
                        menu.separator().pipe(|m| pick("off".into(), t("ai.off"), m))
                    })
                    .into_any_element(),
                &tk,
            ),
        );
        if provider_id != "off" {
            let status = match &provider {
                None if self.providers.is_empty() => (tk.ink3, t("settings.ai.checking"), String::new()),
                Some(p) if p.b("available") => (tk.ok, t("settings.ai.available"), p.s("note").to_string()),
                Some(p) => (tk.warn, t("settings.ai.notAvailable"), p.s("note").to_string()),
                None => (tk.ink3, String::new(), String::new()),
            };
            let endpoint_text = {
                let typed = self.endpoint.read(cx).value().trim().to_string();
                if typed.is_empty() {
                    provider
                        .as_ref()
                        .map(|p| p.s("defaultEndpoint").to_string())
                        .unwrap_or_default()
                } else {
                    typed
                }
            };
            let local = provider.as_ref().is_some_and(|p| p.s("kind") == "api") && is_local(&endpoint_text);
            let privacy = if local {
                kit::row()
                    .child(kit::glyph(icons::SHIELD, 14., tk.ok))
                    .child(kit::colored(t("settings.ai.staysLocal"), tk.ok).font_weight(FontWeight::SEMIBOLD))
            } else if provider_id == "auto" {
                kit::row()
                    .child(kit::glyph('\u{E774}', 14., tk.ink2))
                    .child(kit::body(t("settings.ai.sentAuto")))
            } else {
                kit::row()
                    .child(kit::glyph('\u{E774}', 14., tk.ink2))
                    .child(kit::body(tf("settings.ai.sentTo", &[("destination", &name)])))
            };
            let mut line = kit::row().child(kit::dot(Some(status.0))).child(kit::body(status.1));
            if !status.2.is_empty() {
                line = line.child(kit::faint(format!("· {}", status.2), &tk));
            }
            body = body.child(div().px_4().flex().flex_col().gap_1().child(line).child(privacy));
        }
        if let Some(p) = provider.clone() {
            if p.b("needsEndpoint") {
                let example = match p.s("id") {
                    "openai-compatible" => "https://api.openai.com/v1 · http://localhost:11434/v1 (Ollama) · http://localhost:1234/v1 (LM Studio)".to_string(),
                    "anthropic-compatible" => "https://api.anthropic.com · http://localhost:11434 (Ollama)".to_string(),
                    _ => p.s("defaultEndpoint").to_string(),
                };
                let typed = self.endpoint.read(cx).value().trim().to_string();
                let insecure = typed.starts_with("http://") && !is_local(&typed);
                body = body.child(
                    self.row(
                        t("settings.ai.endpoint"),
                        Some(example),
                        div()
                            .w(px(300.))
                            .font_family(FONT_MONO)
                            .child(Input::new(&self.endpoint))
                            .into_any_element(),
                        &tk,
                    ),
                );
                if insecure {
                    body = body.child(kit::colored(t("settings.ai.insecure"), tk.warn).px_4());
                }
            }
            if !matches!(p.s("kind"), "auto" | "off") {
                let typed = self.endpoint.read(cx).value().trim().to_string();
                let default_applies = p.has("defaultModel") && (typed.is_empty() || typed == p.s("defaultEndpoint"));
                let note = if default_applies {
                    tf("settings.ai.modelDefault", &[("model", p.s("defaultModel"))])
                } else if p.s("kind") == "api" {
                    t("settings.ai.modelRequired")
                } else {
                    t("settings.ai.modelNote")
                };
                let mut suggestions: Vec<String> = p.strs("suggestedModels").into_iter().map(str::to_string).collect();
                for m in &self.models {
                    if !suggestions.contains(m) {
                        suggestions.push(m.clone());
                    }
                }
                let model_input = self.model.clone();
                let mut control =
                    kit::row().child(div().w(px(220.)).font_family(FONT_MONO).child(Input::new(&self.model)));
                if !suggestions.is_empty() {
                    control = control.child(
                        FButton::new("se-models", Kind::Standard)
                            .glyph(icons::CHEVRON_DOWN)
                            .accessible_name(t("settings.ai.model"))
                            .dropdown_menu(move |menu, _, _| {
                                let mut menu = menu;
                                for m in suggestions.clone() {
                                    let input = model_input.clone();
                                    menu = menu.item(PopupMenuItem::new(m.clone()).on_click(move |_, window, cx| {
                                        input.update(cx, |s, cx| s.set_value(m.clone(), window, cx));
                                    }));
                                }
                                menu
                            }),
                    );
                }
                if p.b("needsEndpoint") {
                    control = control.child(
                        ui::button(
                            "se-refresh-models",
                            t(if self.fetching {
                                "settings.ai.refreshing"
                            } else {
                                "settings.ai.refreshModels"
                            }),
                        )
                        .tip(t("settings.ai.refreshModelsTip"))
                        .disabled(self.fetching)
                        .on_click(cx.listener(|this, _, _, cx| this.fetch_models(cx))),
                    );
                }
                let note = match &self.models_note {
                    Some(n) => format!("{note} {n}"),
                    None => note,
                };
                body = body.child(self.row(t("settings.ai.model"), Some(note), control.into_any_element(), &tk));
            }
            if p.has("secret") {
                let id: &'static str = match p.s("secret") {
                    "anthropic-compatible" => "anthropic-compatible",
                    _ => "openai-compatible",
                };
                body = body.child(self.secret(id, t("settings.ai.apiKey"), Some(t("settings.ai.apiKeyNote")), cx, &tk));
            }
            if p.b("supportsEffort") {
                let weak = cx.entity().downgrade();
                let current: &'static str = match draft.ai.effort.as_str() {
                    "low" => "low",
                    "high" => "high",
                    "xhigh" => "xhigh",
                    "max" => "max",
                    _ => "medium",
                };
                body = body.child(
                    self.row(
                        t("settings.ai.effort"),
                        Some(t("settings.ai.effortNote")),
                        ui::segmented(
                            "se-effort",
                            t("settings.ai.effort"),
                            ["low", "medium", "high", "xhigh", "max"]
                                .iter()
                                .map(|e| (*e, t(&format!("effort.{e}"))))
                                .collect(),
                            current,
                            move |v: &'static str, _, cx| {
                                let _ = weak.update(cx, |this, cx| {
                                    if let Some(d) = &mut this.draft {
                                        d.ai.effort = v.to_string();
                                    }
                                    cx.notify();
                                });
                            },
                            &tk,
                        )
                        .into_any_element(),
                        &tk,
                    ),
                );
            }
        }
        if provider_id != "off" {
            let weak = cx.entity().downgrade();
            body = body.child(
                self.row(
                    t("settings.ai.anonymize"),
                    Some(t("settings.ai.anonymizeNote")),
                    ui::toggle_switch(
                        "se-redact",
                        draft.ai.redact,
                        false,
                        t(if draft.ai.redact { "common.on" } else { "common.off" }),
                        move |on, _, cx| {
                            let _ = weak.update(cx, |this, cx| {
                                if let Some(d) = &mut this.draft {
                                    d.ai.redact = on;
                                }
                                cx.notify();
                            });
                        },
                        &tk,
                    )
                    .into_any_element(),
                    &tk,
                ),
            );
        }

        // Scan.
        body = body.child(kit::h3(t("settings.scan")));
        let weak = cx.entity().downgrade();
        body = body.child(
            self.row(
                t("settings.eventLogs"),
                Some(t("settings.eventLogsNote")),
                ui::segmented(
                    "se-days",
                    t("settings.eventLogs"),
                    [7u32, 14, 30, 60, 90]
                        .iter()
                        .map(|d| (*d, tn("common.days", u64::from(*d), &[])))
                        .collect(),
                    draft.days,
                    move |v, _, cx| {
                        let _ = weak.update(cx, |this, cx| {
                            if let Some(d) = &mut this.draft {
                                d.days = v;
                            }
                            cx.notify();
                        });
                    },
                    &tk,
                )
                .into_any_element(),
                &tk,
            ),
        );
        body = body.child(self.toggle(
            "se-vt",
            t("settings.virustotal"),
            Some(t("settings.virustotalNote")),
            draft.virustotal,
            |d, on| d.virustotal = on,
            cx,
            &tk,
        ));
        body = body.child(self.secret("virustotal", t("settings.virustotalKey"), None, cx, &tk));

        // Safety.
        body = body.child(kit::h3(t("settings.safety")));
        body = body.child(self.toggle(
            "se-restore",
            t("settings.restorePoint"),
            Some(t("settings.restorePointNote")),
            draft.restore_point,
            |d, on| d.restore_point = on,
            cx,
            &tk,
        ));

        // Background watch.
        if let Some(w) = self.watch.clone() {
            body = body.child(kit::h3(t("settings.watch.title")));
            body = body.child(self.watch_toggle(
                "se-w-watching",
                t("settings.watch.watching"),
                Some(t("settings.watch.watchingNote")),
                w.watching,
                |s, on| s.watching = on,
                cx,
                &tk,
            ));
            let weak = cx.entity().downgrade();
            body = body.child(
                self.row(
                    t("settings.watch.close"),
                    Some(t("settings.watch.closeNote")),
                    ui::segmented(
                        "se-w-close",
                        t("settings.watch.close"),
                        vec![
                            (true, t("settings.watch.closeTray")),
                            (false, t("settings.watch.closeQuit")),
                        ],
                        w.close_to_tray,
                        move |v, _, cx| {
                            let _ = weak.update(cx, |this, cx| {
                                if let Some(s) = &mut this.watch {
                                    s.close_to_tray = v;
                                }
                                cx.notify();
                            });
                        },
                        &tk,
                    )
                    .into_any_element(),
                    &tk,
                ),
            );
            body = body.child(self.schedule_row(&w, cx, &tk));
            let on = self.autostart;
            let busy = self.acting.busy;
            let auto = ui::toggle_switch(
                "se-w-autostart",
                on,
                busy,
                t(if on { "common.on" } else { "common.off" }),
                {
                    let weak = cx.entity().downgrade();
                    move |value, window, cx| {
                        let _ = weak.update(cx, |this, cx| {
                            common::send_json(
                                this,
                                json!({"kind": "tuning", "op": "vigil.autostart", "params": {"on": value}}),
                                window,
                                cx,
                            );
                        });
                    }
                },
                &tk,
            );
            body = body.child(self.row(
                t("settings.watch.autostart"),
                Some(t("settings.watch.autostartNote")),
                auto.into_any_element(),
                &tk,
            ));
            if let Some(bar) = self.acting.bar("se-autostart-result", &tk) {
                body = body.child(bar);
            }
            let mut checks = div().flex().flex_col().gap_1();
            for (key, label) in [
                ("startup", "settings.watch.notifyStartup"),
                ("services", "settings.watch.notifyServices"),
                ("tasks", "settings.watch.notifyTasks"),
                ("security", "settings.watch.notifySecurity"),
                ("ports", "settings.watch.notifyPorts"),
                ("hooks", "settings.watch.notifyHooks"),
                ("events", "settings.watch.notifyEvents"),
            ] {
                let value = match key {
                    "startup" => w.notify_startup,
                    "services" => w.notify_services,
                    "tasks" => w.notify_tasks,
                    "security" => w.notify_security,
                    "ports" => w.notify_ports,
                    "hooks" => w.notify_hooks,
                    _ => w.notify_events,
                };
                let weak = cx.entity().downgrade();
                checks = checks.child(ui::check_box(
                    ElementId::Name(format!("se-n-{key}").into()),
                    value,
                    false,
                    t(label),
                    move |on, _, cx| {
                        let _ = weak.update(cx, |this, cx| {
                            if let Some(s) = &mut this.watch {
                                match key {
                                    "startup" => s.notify_startup = on,
                                    "services" => s.notify_services = on,
                                    "tasks" => s.notify_tasks = on,
                                    "security" => s.notify_security = on,
                                    "ports" => s.notify_ports = on,
                                    "hooks" => s.notify_hooks = on,
                                    _ => s.notify_events = on,
                                }
                            }
                            cx.notify();
                        });
                    },
                    &tk,
                ));
            }
            body = body.child(self.row(
                t("settings.watch.notify"),
                Some(t("settings.watch.notifyNote")),
                checks.into_any_element(),
                &tk,
            ));
        }

        // Processes.
        body = body.child(kit::h3(t("settings.processes")));
        body = body.child(self.toggle(
            "se-auto",
            t("settings.autoRefresh"),
            Some(t("settings.autoRefreshNote")),
            draft.auto_refresh,
            |d, on| d.auto_refresh = on,
            cx,
            &tk,
        ));
        let data_dir = self
            .ctx
            .core
            .as_ref()
            .map(|c| c.root.display().to_string())
            .unwrap_or_else(|| data::demo("appInfo").s("dataDir").to_string());
        body = body.child(kit::faint(tf("settings.dataDir", &[("path", &data_dir)]), &tk));
        if let Some(e) = &self.error {
            body = body.child(kit::colored(e.clone(), tk.bad));
        }
        div()
            .flex()
            .flex_col()
            .gap_3()
            .child(
                div()
                    .id("se-body")
                    .max_h(px(560.))
                    .overflow_y_scroll()
                    .pr_2()
                    .child(body),
            )
            .child(
                div()
                    .flex()
                    .justify_end()
                    .gap_2()
                    .child(
                        ui::button("se-cancel", t("common.cancel"))
                            .min_w(px(120.))
                            .on_click(|_, window, cx| window.close_dialog(cx)),
                    )
                    .child(
                        ui::accent_button("se-save", t("common.save"))
                            .min_w(px(120.))
                            .disabled(self.saving)
                            .on_click(cx.listener(|this, _, window, cx| this.save(window, cx))),
                    ),
            )
    }
}

impl SettingsView {
    #[allow(clippy::too_many_arguments)]
    fn toggle(
        &self,
        id: &'static str,
        label: String,
        note: Option<String>,
        value: bool,
        set: fn(&mut View, bool),
        cx: &mut Context<Self>,
        tk: &Tokens,
    ) -> Div {
        let weak = cx.entity().downgrade();
        let control = ui::toggle_switch(
            id,
            value,
            false,
            t(if value { "common.on" } else { "common.off" }),
            move |on, _, cx| {
                let _ = weak.update(cx, |this, cx| {
                    if let Some(d) = &mut this.draft {
                        set(d, on);
                    }
                    cx.notify();
                });
            },
            tk,
        );
        self.row(label, note, control.into_any_element(), tk)
    }

    #[allow(clippy::too_many_arguments)]
    fn watch_toggle(
        &self,
        id: &'static str,
        label: String,
        note: Option<String>,
        value: bool,
        set: fn(&mut WatchSettings, bool),
        cx: &mut Context<Self>,
        tk: &Tokens,
    ) -> Div {
        let weak = cx.entity().downgrade();
        let control = ui::toggle_switch(
            id,
            value,
            false,
            t(if value { "common.on" } else { "common.off" }),
            move |on, _, cx| {
                let _ = weak.update(cx, |this, cx| {
                    if let Some(s) = &mut this.watch {
                        set(s, on);
                    }
                    cx.notify();
                });
            },
            tk,
        );
        self.row(label, note, control.into_any_element(), tk)
    }
}

/// `menu.pipe(f)`: applies `f` (keeps a builder chain readable).
trait Pipe: Sized {
    fn pipe<R>(self, f: impl FnOnce(Self) -> R) -> R {
        f(self)
    }
}
impl<T> Pipe for T {}

/// Opens Settings.
pub fn open(ctx: Ctx, window: &mut Window, cx: &mut gpui_kit::App) {
    let view = cx.new(|cx| SettingsView::new(ctx, window, cx));
    window.open_dialog(cx, move |dialog, _, cx| {
        dialog
            .bg(crate::theme::tokens(cx).flyout)
            .title(t("settings.title"))
            .w(px(720.))
            .child(view.clone())
    });
}

/// "HH:MM" with a real hour and minute.
fn valid_time(text: &str) -> bool {
    let Some((h, m)) = text.split_once(':') else {
        return false;
    };
    h.len() <= 2 && m.len() == 2 && h.parse::<u8>().is_ok_and(|h| h < 24) && m.parse::<u8>().is_ok_and(|m| m < 60)
}

impl SettingsView {
    /// Automatic scans: off, every day or every week, the day and the time.
    fn schedule_row(&self, w: &WatchSettings, cx: &mut Context<Self>, tk: &Tokens) -> Div {
        let weak = cx.entity().downgrade();
        let schedule: &'static str = match w.scan_schedule.as_str() {
            "daily" => "daily",
            "weekly" => "weekly",
            _ => "off",
        };
        let mut control = div().flex().flex_col().gap_2().child(ui::segmented(
            "se-w-scan",
            t("settings.watch.scan"),
            vec![
                ("off", t("settings.watch.scanOff")),
                ("daily", t("settings.watch.scanDaily")),
                ("weekly", t("settings.watch.scanWeekly")),
            ],
            schedule,
            move |v: &'static str, _, cx| {
                let _ = weak.update(cx, |this, cx| {
                    if let Some(s) = &mut this.watch {
                        s.scan_schedule = v.to_string();
                    }
                    cx.notify();
                });
            },
            tk,
        ));
        if schedule == "weekly" {
            const DAYS: [&str; 7] = [
                "monday",
                "tuesday",
                "wednesday",
                "thursday",
                "friday",
                "saturday",
                "sunday",
            ];
            let day = w.scan_day.clamp(1, 7);
            let weak = cx.entity().downgrade();
            control = control.child(
                FButton::new("se-w-day", Kind::Standard)
                    .label(crate::pages::dates::weekday(DAYS[usize::from(day) - 1], false))
                    .accessible_name(t("settings.watch.scanDay"))
                    .chevron()
                    .dropdown_menu(move |menu, _, _| {
                        let mut menu = menu;
                        for (i, key) in DAYS.iter().enumerate() {
                            let weak = weak.clone();
                            let value = i as u8 + 1;
                            menu = menu.item(
                                PopupMenuItem::new(crate::pages::dates::weekday(key, false))
                                    .checked(value == day)
                                    .on_click(move |_, _, cx| {
                                        let _ = weak.update(cx, |this, cx| {
                                            if let Some(s) = &mut this.watch {
                                                s.scan_day = value;
                                            }
                                            cx.notify();
                                        });
                                    }),
                            );
                        }
                        menu
                    }),
            );
        }
        if schedule != "off" {
            control = control.child(
                kit::row()
                    .child(kit::faint(t("settings.watch.scanTime"), tk))
                    .child(div().w(px(90.)).child(Input::new(&self.scan_time))),
            );
        }
        self.row(
            t("settings.watch.scan"),
            Some(t("settings.watch.scanNote")),
            control.into_any_element(),
            tk,
        )
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn times() {
        assert!(super::valid_time("07:05"));
        assert!(super::valid_time("23:59"));
        assert!(!super::valid_time("24:00"));
        assert!(!super::valid_time("7:5"));
        assert!(!super::valid_time("noon"));
    }
}
