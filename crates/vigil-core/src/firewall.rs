//! The Firewall rules page: the live profiles and rules (read-only), and the requests that turn a
//! rule on or off or delete it. Requests name a rule by its key; the rule, its identifying fields
//! and every text of the confirmation come from Rust's own fresh read, never from the page.

use std::time::Duration;

use serde::Serialize;
use serde_json::json;
use vigil_i18n::tr;
use vigil_sys::firewall::{Firewall, FirewallProfile, FirewallRule, Folders, REMOTE_ACCESS_PORTS, Summary};

use crate::planner::{SpecExt, spec};
use crate::requests::{Context, Plan};

/// A few thousand rules read in well under a second; this only bounds a stuck firewall service.
const READ_TIMEOUT: Duration = Duration::from_secs(20);

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FirewallView {
    pub profiles: Vec<FirewallProfile>,
    pub rules: Vec<FirewallRule>,
    pub summary: Summary,
}

fn read() -> Result<Firewall, String> {
    vigil_sys::firewall::read(READ_TIMEOUT).map_err(|e| tr!("Could not read the firewall rules: {0}", e))
}

/// The firewall profiles and every rule with its flags (read-only; slow, call it off the UI thread).
pub fn view() -> Result<FirewallView, String> {
    let firewall = read()?;
    Ok(FirewallView {
        summary: vigil_sys::firewall::summarize(&firewall.rules),
        profiles: firewall.profiles,
        rules: firewall.rules,
    })
}

/// The live rules a firewall request is checked against.
pub fn live_rules() -> Result<Vec<FirewallRule>, String> {
    Ok(read()?.rules)
}

/// "Inbound · Allow · TCP 8080 · C:\...\app.exe", for the confirmation.
fn target_text(rule: &FirewallRule) -> String {
    let mut parts = vec![
        if rule.direction == "out" {
            tr!("Outbound")
        } else {
            tr!("Inbound")
        },
        if rule.action == "allow" {
            tr!("Allow")
        } else {
            tr!("Block")
        },
    ];
    let ports = rule.local_ports.trim();
    if ports.is_empty() || ports == "*" {
        parts.push(rule.protocol_name.clone());
    } else {
        parts.push(format!("{} {ports}", rule.protocol_name));
    }
    if !rule.program.is_empty() {
        parts.push(rule.program.clone());
    } else if !rule.service.is_empty() {
        parts.push(tr!("service {0}", rule.service));
    }
    parts.join(" · ")
}

/// What the rule would allow once it is on, as warnings for the confirmation.
fn enable_warnings(rule: &FirewallRule) -> Vec<String> {
    let mut on = rule.clone();
    on.enabled = true;
    vigil_sys::firewall::flags_for(&on, &Folders::from_env())
        .iter()
        .filter_map(|flag| match flag.code {
            "open_public" => Some(tr!(
                "Once on, this rule accepts connections from any address on public networks, for every program."
            )),
            "remote_access" => {
                // Product names stay as they are; Remote Desktop has a name in every language.
                let service = if flag.port == 3389 {
                    tr!("Remote Desktop")
                } else {
                    REMOTE_ACCESS_PORTS
                        .iter()
                        .find(|(port, _)| *port == flag.port)
                        .map_or(String::new(), |(_, name)| (*name).to_string())
                };
                Some(tr!(
                    "Once on, this rule lets other computers connect to port {0} ({1}), which is used to control a computer remotely.",
                    flag.port,
                    service
                ))
            }
            "writable_program" => Some(tr!(
                "The program is in a folder any program can write to, so another program could take its place and inherit this rule."
            )),
            "missing_program" => Some(tr!("The program this rule is for no longer exists.")),
            _ => None,
        })
        .collect()
}

/// Turning a firewall rule on or off, or deleting it. The rule must be in the live list and be
/// the only one with its key.
pub fn plan(op: &str, key: &str, ctx: &Context<'_>) -> Result<Plan, String> {
    let rule = ctx
        .firewall
        .iter()
        .find(|r| r.key == key)
        .ok_or(tr!("The firewall rule is no longer there. Refresh the list."))?;
    if rule.duplicate {
        return Err(tr!(
            "Another firewall rule has the same name, direction, program and ports, so Vigil cannot tell them apart. Use Windows Defender Firewall to change it."
        ));
    }
    let quoted = format!("\"{}\"", rule.name);
    let allow = rule.action == "allow";
    let built = match op {
        "disable" => {
            let explain = if allow {
                tr!(
                    "Windows Defender Firewall stops applying this rule. The traffic it allowed is then handled by the other rules and the profile's default, which for incoming connections is usually to block them. Nothing is deleted, and you can turn it back on here or undo it from History."
                )
            } else {
                tr!(
                    "Windows Defender Firewall stops applying this rule, so the traffic it blocked may be allowed again by other rules or the profile's default. Nothing is deleted, and you can turn it back on here or undo it from History."
                )
            };
            let built = spec(
                "firewall.rule_disable",
                tr!("Turn off firewall rule {0}", quoted),
                target_text(rule),
                explain,
            )
            .group("disable");
            if rule.builtin {
                built.warning(&tr!(
                    "This rule belongs to \"{0}\", a rule group Windows defines. Features that rely on it may stop working until you turn it back on.",
                    rule.group
                ))
            } else {
                built
            }
        }
        "enable" => {
            let explain = if allow {
                tr!("Windows Defender Firewall applies this rule again and allows the traffic it describes.")
            } else {
                tr!("Windows Defender Firewall applies this rule again and blocks the traffic it describes.")
            };
            let built = spec(
                "firewall.rule_enable",
                tr!("Turn on firewall rule {0}", quoted),
                target_text(rule),
                explain,
            )
            .group("fix");
            let warnings = enable_warnings(rule);
            if warnings.is_empty() {
                built
            } else {
                built.warning(&warnings.join("\n"))
            }
        }
        "delete" => {
            if rule.builtin {
                return Err(tr!(
                    "{0} belongs to a rule group Windows defines. It can be turned off, but not deleted.",
                    quoted
                ));
            }
            let explain = if allow {
                tr!(
                    "Removes the rule from Windows Defender Firewall. Vigil keeps its full definition, so you can recreate it from History. If a program still needs it, Windows may ask again whether to allow that program."
                )
            } else {
                tr!(
                    "Removes the rule from Windows Defender Firewall, so the traffic it blocked is no longer blocked by it. Vigil keeps its full definition, so you can recreate it from History."
                )
            };
            let built = spec(
                "firewall.rule_delete",
                tr!("Delete firewall rule {0}", quoted),
                target_text(rule),
                explain,
            )
            .group("remove")
            .destructive();
            if rule.app_package {
                built.warning(&tr!(
                    "A Microsoft Store app declared this rule; reinstalling or updating the app may add it again."
                ))
            } else {
                built
            }
        }
        _ => return Err(tr!("Unknown request: {0}", op)),
    };
    let ident = &rule.ident;
    Ok(Plan::Run {
        spec: built.params(json!({
            "name": ident.name,
            "direction": ident.direction,
            "program": ident.program,
            "service": ident.service,
            "protocol": ident.protocol,
            "localPorts": ident.local_ports,
            "remotePorts": ident.remote_ports,
            "label": rule.name,
        })),
        item: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::requests::{Request, build};
    use vigil_sys::firewall::{RuleIdent, assign_keys};

    fn rule(name: &str, ports: &str) -> FirewallRule {
        FirewallRule {
            name: name.into(),
            direction: "in".into(),
            action: "allow".into(),
            enabled: false,
            profiles: vec!["private".into(), "public".into()],
            program_exists: true,
            protocol: 6,
            protocol_name: "TCP".into(),
            local_ports: ports.into(),
            remote_addresses: "*".into(),
            ident: RuleIdent {
                name: name.into(),
                direction: "in".into(),
                protocol: "6".into(),
                local_ports: ports.into(),
                ..RuleIdent::default()
            },
            ..FirewallRule::default()
        }
    }

    fn ctx(rules: &[FirewallRule]) -> Context<'_> {
        Context {
            analysis: None,
            processes: &[],
            cleanup: &[],
            space_files: &[],
            power_plans: &[],
            drive_media: &[],
            services: &[],
            startup: &[],
            tasks: &[],
            firewall: rules,
        }
    }

    fn ask(op: &str, key: &str, rules: &[FirewallRule]) -> Result<vigil_actions::ActionSpec, String> {
        match build(
            &Request::FirewallRule {
                op: op.into(),
                key: key.into(),
            },
            &ctx(rules),
        )? {
            Plan::Run { spec, .. } => Ok(spec),
            _ => Err("not a run plan".into()),
        }
    }

    #[test]
    fn rules_are_checked_against_the_live_list() {
        let mut builtin = rule("Remote Desktop - User Mode (TCP-In)", "3389");
        builtin.builtin = true;
        builtin.group = "Remote Desktop".into();
        let mut rules = vec![
            rule("Contoso Sync", "8080"),
            builtin,
            rule("Twin", "1"),
            rule("Twin", "1"),
        ];
        assign_keys(&mut rules);

        let spec = ask("delete", &rules[0].key, &rules).expect("delete");
        assert_eq!(spec.op, "firewall.rule_delete");
        assert!(spec.destructive && spec.reversible && spec.admin);
        assert_eq!(spec.params["name"], "Contoso Sync");
        assert_eq!(spec.params["localPorts"], "8080");
        assert_eq!(spec.params["protocol"], "6");
        assert!(spec.target.contains("TCP 8080"), "{}", spec.target);

        assert!(ask("delete", "no|such|rule", &rules).is_err());
        assert!(
            ask("delete", &rules[2].key, &rules).is_err(),
            "rules that share a key are refused"
        );
        assert!(ask("format", &rules[0].key, &rules).is_err());

        // Windows' own rules: never deleted, turned off only with a warning.
        assert!(ask("delete", &rules[1].key, &rules).is_err());
        let off = ask("disable", &rules[1].key, &rules).expect("disable");
        assert_eq!(off.op, "firewall.rule_disable");
        assert!(off.warning.contains("Remote Desktop"), "{}", off.warning);

        // Turning on a rule that opens a remote-access port says so.
        let on = ask("enable", &rules[1].key, &rules).expect("enable");
        assert_eq!(on.op, "firewall.rule_enable");
        assert!(on.warning.contains("3389"), "{}", on.warning);
        let quiet = ask("disable", &rules[0].key, &rules).expect("disable");
        assert!(quiet.warning.is_empty());
    }

    #[test]
    fn the_request_kind_is_firewall_rule() {
        let parsed: Request =
            serde_json::from_value(json!({"kind": "firewall-rule", "op": "disable", "key": "a|in|||6|80|"}))
                .expect("request");
        assert!(matches!(parsed, Request::FirewallRule { ref op, .. } if op == "disable"));
    }
}
