//! Network: the computer's connections and listening ports with the process behind each, which
//! service a port is for, and remote-access ports open to the network. End task, block in the
//! firewall and open the location go through the action service.

use std::sync::Arc;

use gpui_kit::component::input::InputState;
use gpui_kit::component::table::TableState;
use gpui_kit::prelude::FluentBuilder as _;
use gpui_kit::{
    ClipboardItem, Context, Entity, FocusHandle, InteractiveElement as _, IntoElement, ParentElement, Render,
    StatefulInteractiveElement as _, Styled, Subscription, Window, div, px,
};
use serde_json::{Value, json};
use vigil_core::state::AppState;

use crate::app::Ctx;
use crate::data::{self, Src};
use crate::i18n::{t, tf};
use crate::pages::common::{self, Acting, Acts};
use crate::theme::tokens;
use crate::ui;
use crate::ui::grid::{self, Grid, GridCell, GridCol, GridRow};
use crate::ui::kit::{self, J as _};

/// Well-known ports; names starting with "@" are translated.
const PORTS: &[(u16, &str)] = &[
    (20, "FTP data"),
    (21, "FTP"),
    (22, "SSH"),
    (23, "Telnet"),
    (25, "SMTP"),
    (53, "DNS"),
    (67, "DHCP"),
    (68, "DHCP"),
    (69, "TFTP"),
    (80, "HTTP"),
    (88, "Kerberos"),
    (110, "POP3"),
    (123, "NTP"),
    (135, "RPC endpoint mapper"),
    (137, "NetBIOS name"),
    (138, "NetBIOS datagram"),
    (139, "NetBIOS session"),
    (143, "IMAP"),
    (161, "SNMP"),
    (389, "LDAP"),
    (443, "HTTPS"),
    (445, "SMB"),
    (465, "SMTP (TLS)"),
    (500, "IPsec IKE"),
    (514, "Syslog"),
    (587, "SMTP submission"),
    (636, "LDAP (TLS)"),
    (853, "DNS over TLS"),
    (993, "IMAP (TLS)"),
    (995, "POP3 (TLS)"),
    (1080, "SOCKS proxy"),
    (1194, "OpenVPN"),
    (1433, "SQL Server"),
    (1434, "SQL Server browser"),
    (1701, "L2TP"),
    (1723, "PPTP"),
    (1900, "SSDP (UPnP)"),
    (2179, "Hyper-V console"),
    (3306, "MySQL"),
    (3389, "@port.rdp"),
    (3478, "STUN"),
    (3702, "WS-Discovery"),
    (4500, "IPsec NAT-T"),
    (5040, "@port.cdp"),
    (5353, "mDNS"),
    (5355, "LLMNR"),
    (5357, "WSD"),
    (5432, "PostgreSQL"),
    (5900, "VNC"),
    (5938, "TeamViewer"),
    (5985, "WinRM"),
    (5986, "WinRM (TLS)"),
    (6379, "Redis"),
    (6881, "BitTorrent"),
    (7680, "@port.do"),
    (8080, "@port.httpAlt"),
    (8443, "@port.httpsAlt"),
    (9000, "@port.httpAlt"),
    (9050, "Tor"),
    (9150, "Tor Browser"),
    (11211, "Memcached"),
    (27017, "MongoDB"),
    (51820, "WireGuard"),
];

const REMOTE_ACCESS: [u16; 7] = [22, 23, 3389, 5900, 5938, 5985, 5986];

fn port_of(address: &str) -> Option<u16> {
    let (_, port) = address.rsplit_once(':')?;
    port.parse::<u16>().ok().filter(|p| *p > 0)
}

/// The service a connection talks to (outgoing) or offers (listening).
pub fn service_of(c: &Value) -> String {
    let address = if c.has("remote") { c.s("remote") } else { c.s("local") };
    let Some(port) = port_of(address) else {
        return String::new();
    };
    let name = PORTS.iter().find(|(p, _)| *p == port).map(|(_, n)| *n).unwrap_or("");
    match name.strip_prefix('@') {
        Some(key) => t(key),
        None => name.to_string(),
    }
}

/// A remote-access port listening on every network interface.
pub fn exposed(c: &Value) -> bool {
    let local = c.s("local");
    !c.has("remote")
        && port_of(local).is_some_and(|p| REMOTE_ACCESS.contains(&p))
        && (local.starts_with("0.0.0.0:") || local.starts_with("[::]:"))
}

fn key_of(c: &Value) -> String {
    format!("{}|{}|{}|{}", c.s("protocol"), c.s("local"), c.s("remote"), c.i("pid"))
}

pub struct NetworkPage {
    ctx: Ctx,
    rows: Vec<Value>,
    internet_only: bool,
    listening: bool,
    loading: bool,
    error: Option<String>,
    table: Entity<TableState<Grid>>,
    search: Entity<InputState>,
    acting: Acting,
    focus: FocusHandle,
    _subscriptions: Vec<Subscription>,
}

impl Acts for NetworkPage {
    fn acting(&mut self) -> &mut Acting {
        &mut self.acting
    }
    fn core(&self) -> Option<Arc<AppState>> {
        self.ctx.core.clone()
    }
    fn after(&mut self, _: &mut Window, _: &mut Context<Self>) {}
}

impl NetworkPage {
    pub fn new(ctx: Ctx, window: &mut Window, cx: &mut Context<Self>) -> Self {
        let cols = vec![
            GridCol::new("process", t("network.process"), 170.),
            GridCol::new("pid", "PID".into(), 70.).numeric(),
            GridCol::new("protocol", t("network.protocol"), 80.),
            GridCol::new("local", t("network.local"), 190.),
            GridCol::new("remote", t("network.remote"), 210.),
            GridCol::new("state", t("network.state"), 110.),
            GridCol::new("service", t("network.service"), 150.),
            GridCol::new("path", t("network.path"), 300.),
        ];
        let table = grid::new_state(String::new(), cols, window, cx);
        let (search, searching) = grid::search(&table, t("network.filter"), window, cx);
        let subscriptions = vec![searching, cx.observe(&table, |_, _, cx| cx.notify())];
        let mut page = Self {
            ctx,
            rows: Vec::new(),
            internet_only: false,
            listening: true,
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
            move || data::fetch(core.as_ref(), Src::Connections),
            |this: &mut Self, result, cx| {
                this.loading = false;
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

    fn shown(&self) -> Vec<&Value> {
        self.rows
            .iter()
            .filter(|c| (!self.internet_only || c.b("public")) && (self.listening || c.has("remote")))
            .collect()
    }

    fn fill(&mut self, cx: &mut Context<Self>) {
        let tk = *tokens(cx);
        let rows = self
            .shown()
            .into_iter()
            .map(|c| {
                let service = service_of(c);
                let mut remote = GridCell::text(c.s("remote")).mono();
                if c.b("public") {
                    remote.strong = true;
                }
                let mut service_cell = GridCell::text(service.clone());
                if exposed(c) {
                    service_cell = service_cell.color(tk.warn);
                    service_cell.strong = true;
                }
                let cells = vec![
                    GridCell::text(c.s("process")),
                    GridCell::num(c.i("pid").to_string(), c.n("pid")),
                    GridCell::text(c.s("protocol")),
                    GridCell::text(c.s("local")).mono(),
                    remote,
                    GridCell::text(c.s("state")),
                    service_cell,
                    GridCell::text(c.s("exe")),
                ];
                let search = format!(
                    "{} {} {} {} {} {service} {}",
                    c.s("process"),
                    c.i("pid"),
                    c.s("local"),
                    c.s("remote"),
                    c.s("state"),
                    c.s("exe")
                );
                GridRow::new(key_of(c), cells, search)
            })
            .collect();
        grid::fill(&self.table, rows, cx);
    }

    fn current(&self, cx: &gpui_kit::App) -> Option<Value> {
        let key = grid::selected(&self.table, cx)?;
        self.rows.iter().find(|c| key_of(c) == key).cloned()
    }
}

impl Render for NetworkPage {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let tk = *tokens(cx);
        let current = self.current(cx);
        let busy = self.acting.busy;
        let pid = current.as_ref().map(|c| c.i("pid")).unwrap_or(0);
        // With the PID, the start time names exactly the process the list showed: if it ended and
        // another took its PID, the core refuses the request.
        let created = current.as_ref().map(|c| c.i("createdMs")).unwrap_or(0);
        let exe = current.as_ref().map(|c| c.s("exe").to_string()).unwrap_or_default();
        let remote = current.as_ref().map(|c| c.s("remote").to_string()).unwrap_or_default();
        let weak = cx.entity().downgrade();
        let weak2 = cx.entity().downgrade();
        let shown = self.shown();
        let public = shown.iter().filter(|c| c.b("public")).count();
        let listen = shown.iter().filter(|c| !c.has("remote")).count();
        let mut services: Vec<String> = shown.iter().filter(|c| exposed(c)).map(|c| service_of(c)).collect();
        services.dedup();
        let footer = match &self.error {
            Some(e) => kit::faint(e.clone(), &tk),
            None => kit::row()
                .gap_1()
                .child(kit::faint(
                    tf(
                        "network.summary",
                        &[
                            ("shown", &self.table.read(cx).delegate().row_count().to_string()),
                            ("total", &self.rows.len().to_string()),
                            ("publicCount", &public.to_string()),
                            ("listenCount", &listen.to_string()),
                        ],
                    ),
                    &tk,
                ))
                .when_some((!services.is_empty()).then_some(services), |this, s| {
                    this.child(
                        kit::colored(
                            format!("· {}", tf("network.exposed", &[("services", &s.join(", "))])),
                            tk.warn,
                        )
                        .text_size(px(12.)),
                    )
                }),
        };
        let (exe_block, exe_location) = (exe.clone(), exe.clone());
        let root = div()
            .track_focus(&self.focus)
            .size_full()
            .flex()
            .flex_col()
            .gap_2()
            .px(px(20.))
            .pt(px(12.))
            .pb(px(12.));
        common::list_keys(root, |p: &NetworkPage| p.table.clone(), cx)
            .child(
                kit::row()
                    .child(ui::page_title(t("page.network")))
                    .child(div().flex_1())
                    .child(div().w(px(280.)).child(ui::search_box(&self.search, &tk)))
                    .child(
                        div()
                            .id("net-internet")
                            .tooltip(|window, cx| {
                                gpui_kit::component::tooltip::Tooltip::new(t("network.internetOnlyTip"))
                                    .build(window, cx)
                            })
                            .child(ui::check_box(
                                "net-internet-box",
                                self.internet_only,
                                false,
                                t("network.internetOnly"),
                                move |on, _, cx| {
                                    let _ = weak.update(cx, |this, cx| {
                                        this.internet_only = on;
                                        this.fill(cx);
                                    });
                                },
                                &tk,
                            )),
                    )
                    .child(ui::check_box(
                        "net-listening",
                        self.listening,
                        false,
                        t("network.listening"),
                        move |on, _, cx| {
                            let _ = weak2.update(cx, |this, cx| {
                                this.listening = on;
                                this.fill(cx);
                            });
                        },
                        &tk,
                    ))
                    .child(
                        ui::button(
                            "net-refresh",
                            t(if self.loading {
                                "common.reading"
                            } else {
                                "common.refresh"
                            }),
                        )
                        .disabled(self.loading)
                        .on_click(cx.listener(|this, _, _, cx| this.load(cx))),
                    ),
            )
            .child(
                kit::row()
                    .child(
                        ui::button("net-end", t("proc.end"))
                            .danger(true)
                            .disabled(current.is_none() || pid <= 4 || created == 0 || busy)
                            .on_click(cx.listener(move |this, _, window, cx| {
                                common::send_json(
                                    this,
                                    json!({"kind": "process", "op": "terminate", "pid": pid, "createdMs": created}),
                                    window,
                                    cx,
                                )
                            })),
                    )
                    .child(
                        ui::button("net-block", t("proc.block"))
                            .disabled(exe_block.is_empty() || !self.ctx.elevated || created == 0 || busy)
                            .on_click(cx.listener(move |this, _, window, cx| {
                                common::send_json(
                                    this,
                                    json!({"kind": "process", "op": "block", "pid": pid, "createdMs": created}),
                                    window,
                                    cx,
                                )
                            })),
                    )
                    .child(
                        ui::button("net-location", t("proc.location"))
                            .disabled(exe_location.is_empty())
                            .on_click(cx.listener(move |this, _, window, cx| {
                                common::send_json(
                                    this,
                                    json!({"kind": "shell", "op": "location", "path": exe}),
                                    window,
                                    cx,
                                )
                            })),
                    )
                    .child(
                        ui::button("net-copy", t("network.copyRemote"))
                            .disabled(remote.is_empty())
                            .on_click(move |_, _, cx| cx.write_to_clipboard(ClipboardItem::new_string(remote.clone()))),
                    ),
            )
            .children(self.acting.bar("net-result", &tk))
            .child(grid::frame(&tk).child(grid::table(&self.table, t("page.network"))))
            .child(footer)
    }
}
