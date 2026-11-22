//! Concrete manual remediation steps for each finding.
//!
//! These are manual steps shown in the report: the scan itself NEVER runs them, the user
//! decides. The names come from a system that may be compromised, so they are quoted in a
//! way that copying and pasting a command cannot run anything else.

use std::collections::HashSet;

use serde_json::{Map, Value, json};

use crate::lenient::{Get, as_int, list, opt_str, quote_literal, str_of, text, truthy};
use crate::model::{Item, Role};
use crate::rules::file_exists;
use vigil_i18n::{tl, tr};

fn browser_page(browser: &str) -> &'static str {
    match browser {
        "Chrome" | "Chromium" => "chrome://extensions",
        "Edge" => "edge://extensions",
        "Brave" => "brave://extensions",
        "Vivaldi" => "vivaldi://extensions",
        "Opera" | "Opera GX" => "opera://extensions",
        "Firefox" => "about:addons",
        _ => tl!("the extensions page"),
    }
}

/// PowerShell single-quoted literal; `None` when the text is not safe to quote.
pub fn ps_quote(text: Option<&str>) -> Option<String> {
    let text = text?;
    if text.is_empty()
        || text
            .chars()
            .any(|ch| (ch as u32) < 32 || ch == '\u{2028}' || ch == '\u{2029}')
    {
        return None;
    }
    // PowerShell also accepts typographic quotes as string delimiters.
    let text: String = text
        .chars()
        .map(|c| {
            if matches!(c, '\u{2018}' | '\u{2019}' | '\u{201a}' | '\u{201b}') {
                '\''
            } else {
                c
            }
        })
        .collect();
    Some(format!("'{}'", text.replace('\'', "''")))
}

/// `ps_quote` of a value (`None` stays `None`; other values are quoted as text).
fn quote_value(value: &Value) -> Option<String> {
    ps_quote(opt_str(value).as_deref())
}

/// An optional quoted text for a remediation step ("None" when it could not be quoted).
fn shown(quoted: &Option<String>) -> String {
    quoted.clone().unwrap_or_else(|| "None".into())
}

fn registry_path(location: &str) -> Option<String> {
    for (short, full) in [("HKLM\\", "HKEY_LOCAL_MACHINE\\"), ("HKCU\\", "HKEY_CURRENT_USER\\")] {
        if let Some(rest) = location.strip_prefix(short) {
            return Some(format!("Registry::{full}{rest}"));
        }
    }
    None
}

#[derive(Default)]
struct Step {
    title: String,
    command: Option<String>,
    note: Option<String>,
    admin: bool,
    url: Option<String>,
    danger: bool,
}

impl Step {
    fn new(title: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            ..Self::default()
        }
    }
    fn command(mut self, command: impl Into<String>) -> Self {
        self.command = Some(command.into());
        self
    }
    fn note(mut self, note: impl Into<String>) -> Self {
        self.note = Some(note.into());
        self
    }
    fn admin(mut self, admin: bool) -> Self {
        self.admin = admin;
        self
    }
    fn danger(mut self) -> Self {
        self.danger = true;
        self
    }
    fn url(mut self, url: impl Into<String>) -> Self {
        self.url = Some(url.into());
        self
    }
    fn to_value(&self) -> Value {
        json!({
            "title": self.title, "command": self.command, "note": self.note,
            "admin": self.admin, "url": self.url, "danger": self.danger,
        })
    }
}

fn role_steps(role: &Role) -> Vec<Step> {
    let detail: &Map<String, Value> = &role.detail;
    match role.kind.as_str() {
        "service" => {
            let name = text(detail.at("name"));
            let Some(quoted) = ps_quote(Some(&name)) else {
                return vec![Step::new(tr!(
                    "Service {0}: its name contains unusual characters; manage it from services.msc",
                    quote_literal(&name)
                ))];
            };
            vec![
                Step::new(tr!("Stop and disable the service \"{0}\"", name))
                    .command(format!(
                        "Stop-Service -Name {quoted} -Force; Set-Service -Name {quoted} -StartupType Disabled"
                    ))
                    .admin(true),
                Step::new(tr!(
                    "Delete the service completely (only if it is malicious or a leftover)"
                ))
                .command(format!("sc.exe delete {quoted}"))
                .admin(true)
                .danger(),
            ]
        }
        "task" => {
            let task_path = if truthy(detail.at("task_path")) {
                str_of(detail.at("task_path"))
            } else {
                "\\".into()
            };
            let (Some(path), Some(name)) = (ps_quote(Some(&task_path)), quote_value(detail.at("task_name"))) else {
                return vec![Step::new(tr!(
                    "Task with a non-standard name: manage it from Task Scheduler (taskschd.msc)"
                ))];
            };
            let target = format!("-TaskPath {path} -TaskName {name}");
            vec![
                Step::new(tr!("Disable the task \"{0}\"", str_of(detail.at("task_name"))))
                    .command(format!("Disable-ScheduledTask {target}"))
                    .admin(true),
                Step::new(tr!("Delete the task (only if it is malicious or a leftover)"))
                    .command(format!("Unregister-ScheduledTask {target} -Confirm:$false"))
                    .admin(true)
                    .danger(),
            ]
        }
        "driver" => {
            let Some(quoted) = quote_value(detail.at("name")) else {
                return vec![];
            };
            vec![Step::new(tr!("Disable the driver \"{0}\"", str_of(detail.at("name"))))
                .command(format!("sc.exe config {quoted} start= disabled"))
                .note(tr!("Careful: disabling a required driver can prevent Windows from starting. Create a restore point first."))
                .admin(true)
                .danger()]
        }
        "startup" => {
            let source = detail.at("source").as_str().unwrap_or("");
            if source == "startup_folder" {
                return match quote_value(detail.at("file")) {
                    Some(quoted) => vec![
                        Step::new(tr!("Remove the file from the Startup folder"))
                            .command(format!("Remove-Item -LiteralPath {quoted}")),
                    ],
                    None => vec![],
                };
            }
            let reg_key = text(detail.at("reg_key"));
            let key = registry_path(&reg_key);
            let value = quote_value(detail.at("value"));
            let admin = reg_key.starts_with("HKLM");
            if source == "run"
                && let (Some(key), Some(value)) = (&key, &value)
            {
                return vec![
                    Step::new(tr!("Disable the startup entry \"{0}\"", str_of(detail.at("value"))))
                        .note(tr!("Task Manager (Ctrl+Shift+Esc) → Startup apps → Disable.")),
                    Step::new(tr!("Delete the registry entry"))
                        .command(format!(
                            "Remove-ItemProperty -Path {} -Name {value}",
                            shown(&ps_quote(Some(key)))
                        ))
                        .admin(admin)
                        .danger(),
                ];
            }
            if source == "com_hijack"
                && let Some(key) = &key
            {
                return vec![
                    Step::new(tr!("Remove the per-user registration"))
                        .command(format!("Remove-Item -LiteralPath {} -Recurse", shown(&ps_quote(Some(key)))))
                        .note(tr!(
                            "Windows then uses the class it registers for the whole computer again. Export the key with regedit first if you are not sure."
                        ))
                        .danger(),
                ];
            }
            if source == "ifeo_debugger"
                && let Some(key) = &key
            {
                return vec![
                    Step::new(tr!("Remove the attached debugger"))
                        .command(format!(
                            "Remove-ItemProperty -Path {} -Name 'Debugger'",
                            shown(&ps_quote(Some(key)))
                        ))
                        .admin(true)
                        .danger(),
                ];
            }
            if key.is_some() {
                return vec![Step::new(tr!("Review the key {0} by hand (value \"{1}\")", str_of(detail.at("reg_key")), str_of(detail.at("value"))))
                .note(tr!("This is a sensitive startup point: edit it with regedit only if you know what the value should be."))
                .admin(admin)
                .danger()];
            }
            vec![]
        }
        "wmi" => {
            let Some(quoted) = quote_value(detail.at("name")) else {
                return vec![];
            };
            vec![Step::new(tr!("Delete the WMI subscription \"{0}\"", str_of(detail.at("name"))))
                .command(format!(
                    "Get-CimInstance -Namespace root/subscription -ClassName CommandLineEventConsumer | Where-Object Name -eq {quoted} | Remove-CimInstance"
                ))
                .admin(true)
                .danger()
                .note(tr!("Also delete its associated __EventFilter and __FilterToConsumerBinding."))]
        }
        "process" => {
            let pids: Vec<String> = list(detail.at("pids"))
                .iter()
                .filter_map(as_int)
                .map(|p| p.to_string())
                .collect();
            if pids.is_empty() {
                return vec![];
            }
            vec![
                Step::new(tr!("End the running processes"))
                    .command(format!("Stop-Process -Id {} -Force", pids.join(",")))
                    .note(tr!(
                        "Process IDs change on every boot; you can also end them from Task Manager."
                    )),
            ]
        }
        _ => vec![],
    }
}

fn config_steps(topic: &str) -> Vec<Step> {
    match topic {
        "defender_off" => vec![Step::new(tr!("Turn real-time protection back on"))
            .command("Set-MpPreference -DisableRealtimeMonitoring $false")
            .admin(true)
            .note(tr!("Or from Windows Security → Virus & threat protection."))],
        "outdated_signatures" => vec![Step::new(tr!("Update the antivirus definitions")).command("Update-MpSignature")],
        "firewall_disabled" => vec![Step::new(tr!("Turn the firewall back on for all profiles"))
            .command("Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True")
            .admin(true)],
        "uac_disabled" => vec![Step::new(tr!("Turn UAC back on")).note(
            tr!("Control Panel → User Accounts → Change User Account Control settings → default level. Requires a restart."),
        )],
        "uac_silent" => vec![Step::new(tr!("Show the UAC prompt again"))
            .note(tr!("Control Panel → User Accounts → Change User Account Control settings."))],
        "rdp_enabled" => vec![Step::new(tr!("Turn off Remote Desktop if you do not use it")).note(tr!("Settings → System → Remote Desktop → Off."))],
        "proxy_enabled" => {
            vec![Step::new(tr!("Remove the proxy")).note(tr!("Settings → Network & internet → Proxy → turn off \"Use a proxy server\"."))]
        }
        "proxy_auto_config" => {
            vec![Step::new(tr!("Remove the proxy script")).note(tr!("Settings → Network & internet → Proxy → turn off \"Use setup script\"."))]
        }
        "dns_set_by_hand" => vec![Step::new(tr!("Let the network choose the DNS servers")).note(tr!(
            "Settings → Network & internet → your connection → DNS server assignment → Edit → Automatic (DHCP). Keep the servers if you chose them yourself."
        ))],
        "dns_policy_rule" => vec![Step::new(tr!("Review the name resolution rules"))
            .command("Get-DnsClientNrptRule")
            .note(tr!(
                "Remove a rule you do not recognize with Remove-DnsClientNrptRule; a company computer gets its rules from its IT department."
            ))],
        "doh_unknown" => vec![Step::new(tr!("Review the encrypted DNS settings")).note(tr!(
            "Settings → Network & internet → your connection → DNS server assignment, and in the browser Settings → Privacy → Use secure DNS. A setting made by a policy shows as managed."
        ))],
        "winhttp_proxy" | "proxy_outside" | "proxy_local_program" => vec![
            Step::new(tr!("Remove the proxy")).note(tr!("Settings → Network & internet → Proxy → turn off \"Use a proxy server\" and \"Use setup script\".")),
            Step::new(tr!("Remove the proxy for Windows services"))
                .command("netsh winhttp reset proxy")
                .admin(true),
        ],
        "wpad_hosts" => vec![Step::new(tr!("Remove the wpad lines from the hosts file")).note(tr!(
            "Open Notepad as administrator, edit C:\\Windows\\System32\\drivers\\etc\\hosts and delete the lines with wpad; turn off \"Automatically detect settings\" in Settings → Network & internet → Proxy if you do not need it."
        ))],
        "persistent_routes" => vec![Step::new(tr!("Review the permanent routes"))
            .command("route print -4")
            .note(tr!("Remove a route you do not recognize with route delete followed by its destination, as administrator."))],
        "virtual_adapter_unknown" | "network_filter_unknown" => vec![Step::new(tr!("Find the program that installed it")).note(
            tr!("Settings → Apps → Installed apps: uninstall it if you do not use it. Device Manager → Network adapters lists the adapter."),
        )],
        "name_broadcasts" => vec![Step::new(tr!("Turn off LLMNR and NetBIOS")).note(tr!(
            "Group policy: Computer Configuration → Administrative Templates → Network → DNS Client → Turn off multicast name resolution; and in the adapter's IPv4 settings → Advanced → WINS → Disable NetBIOS over TCP/IP."
        ))],
        "hosts" => vec![Step::new(tr!("Review the hosts file")).note(
            tr!("Open Notepad as administrator and edit C:\\Windows\\System32\\drivers\\etc\\hosts; delete the lines you do not recognize."),
        )],
        "smartscreen_disabled" => vec![Step::new(tr!("Turn SmartScreen back on"))
            .note(tr!("Windows Security → App & browser control → Reputation-based protection."))],
        "updates_overdue" => vec![Step::new(tr!("Check for updates")).note(tr!("Settings → Windows Update → Check for updates."))],
        "guest_enabled" => vec![Step::new(tr!("Disable the guest account"))
            .command("Disable-LocalUser -SID (Get-LocalUser | Where-Object { $_.SID -like '*-501' }).SID")
            .admin(true)],
        "browser_policies" => vec![Step::new(tr!("View the active policies"))
            .note(tr!("Open chrome://policy or edge://policy in the browser to see what is being enforced."))],
        "shared_folders" => vec![Step::new(tr!("Review what you share"))
            .command("Get-SmbShare")
            .admin(true)
            .note(tr!("Stop sharing a folder with: Remove-SmbShare -Name 'name'"))],
        "firewall_open_public" | "firewall_remote_access" | "firewall_writable_program" | "firewall_missing_programs" => {
            vec![Step::new(tr!("Review the rule on the Firewall rules page")).note(tr!(
                "Turn it off or delete it there (History can undo it), or in Windows Defender Firewall (wf.msc) → Inbound Rules."
            ))]
        }
        "ps_profile" => vec![Step::new(tr!("Review the PowerShell profile")).note(tr!(
            "Open the file in Notepad and remove the lines you do not recognize: PowerShell runs it every time it starts."
        ))],
        "office_vsto_addin" | "office_startup_macros" | "outlook_vba" => vec![
            Step::new(tr!("Review the Office add-ins and startup files")).note(tr!(
                "In the Office program: File → Options → Add-ins (and Trust Center for macros). Move a file you do not use out of the startup folder."
            )),
        ],
        "outlook_home_page" => vec![Step::new(tr!("Remove the Outlook home page")).note(tr!(
            "Delete the URL value under the key shown here with regedit, or clear the folder's home page in its Properties."
        ))],
        "service_weak_permissions" => vec![Step::new(tr!("Update the program, or ask its maker for a fix")).note(tr!(
            "Until then, remove write access for Users, Authenticated Users and Everyone on what is listed here (Properties → Security), or put the service's path in quotes in its ImagePath value."
        ))],
        "rmm_agent" => vec![
            Step::new(tr!("If you did not install it, uninstall it")).note(tr!(
                "Use Installed programs (or Settings → Apps), then change the passwords of the accounts used on this computer. If your IT provider installed it, ask them before removing it."
            )),
            Step::new(tr!("If you use it, keep unattended access off when you do not need it"))
                .note(tr!("Or protect it with a long password and two-factor sign-in in the agent's own settings.")),
        ],
        "com_scriptlet" => vec![Step::new(tr!("Remove the per-user registration")).note(tr!(
            "Delete the key shown here with regedit (export it first): Windows then uses the class it registers for the whole computer again."
        ))],
        "secret_shared" | "secret_registry" => vec![
            Step::new(tr!("Change the password it holds")).note(tr!(
                "Assume it is known: change that password (or the account's) first, then remove it from where it is kept."
            )),
            Step::new(tr!("Remove the stored password")).admin(true).note(tr!(
                "Delete the setup or Group Policy file shown here, or clear the registry value; turn off automatic sign-in in Windows if it is on."
            )),
        ],
        "secret_history" => vec![
            Step::new(tr!("Change the passwords and keys that were typed")).note(tr!(
                "Replace each password or key found at the lines shown here, since programs you run can read this file."
            )),
            Step::new(tr!("Delete those lines from the history")).note(tr!(
                "Open the file shown here in Notepad and delete the lines, or delete the whole file; PowerShell starts a new one."
            )),
        ],
        "secret_file" | "secret_private_key" | "secret_password_list" => vec![
            Step::new(tr!("Move the secret to a safe place")).note(tr!(
                "Keep passwords in a password manager or Windows Credential Manager, protect private keys with a passphrase, and replace any key or token that may have been copied."
            )),
        ],
        "cert_root_known_bad" | "cert_root_imitation" | "cert_root_user" | "cert_root_unknown" | "cert_root_expired"
        | "cert_interception" | "cert_development" => vec![Step::new(tr!("Remove the root certificate you do not need"))
            .note(tr!(
                "Open certmgr.msc (your account) or certlm.msc (the computer, as an administrator) → Trusted Root Certification Authorities → Certificates, compare the thumbprint shown here and delete it. A tool you still use may add it again."
            ))],
        "cert_publisher_self_signed" | "cert_publishers" => vec![Step::new(tr!("Remove publishers you do not recognize"))
            .note(tr!(
                "Open certlm.msc as an administrator (or certmgr.msc) → Trusted Publishers → Certificates and delete the ones you do not need; their programs then show the usual prompt again."
            ))],
        "amsi_disabled" => vec![Step::new(tr!("Turn script scanning back on"))
            .note(tr!(
                "Delete the AmsiEnable value shown here with regedit (or set it to 1), then run a full Microsoft Defender scan."
            ))],
        "powershell_policy_bypass" => vec![Step::new(tr!("Ask who set the policy, or remove it"))
            .admin(true)
            .note(tr!(
                "It comes from Group Policy or a program that wrote the policy key shown here; without it, PowerShell's default execution policy applies again."
            ))],
        "task_hidden_from_scheduler" => vec![Step::new(tr!("Delete the hidden task with administrator rights"))
            .admin(true)
            .note(tr!(
                "Task Scheduler cannot show it: delete its key under HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tree and its file in C:\\Windows\\System32\\Tasks, or ask a security professional."
            ))],
        _ => vec![],
    }
}

/// Manual steps for an item (shown in the report; never run by the scan).
pub fn build_remediation(item: &Item) -> Vec<Value> {
    let mut steps: Vec<Step> = Vec::new();
    match item.kind.as_str() {
        "executable" | "command" | "group" => {
            let mut seen: HashSet<String> = HashSet::new();
            let mut roles: Vec<&Role> = item.roles.iter().collect();
            roles.sort_by_key(|r| r.kind == "process");
            for role in roles {
                for step in role_steps(role) {
                    let signature = format!("{}{}", step.title, step.command.as_deref().unwrap_or(""));
                    if seen.insert(signature) {
                        steps.push(step);
                    }
                }
            }
            steps.truncate(16);
            if item.kind == "executable"
                && let Some(path) = item.path.as_deref().filter(|p| !p.is_empty())
                && file_exists(item.file.as_ref())
            {
                if let Some(quoted) = ps_quote(Some(path)) {
                    steps.push(
                        Step::new(tr!("Scan the file with Microsoft Defender"))
                            .command(format!("Start-MpScan -ScanType CustomScan -ScanPath {quoted}")),
                    );
                }
                if let Some(sha) = item.sha256.as_deref().filter(|s| !s.is_empty()) {
                    steps.push(
                        Step::new(tr!(
                            "Check the reputation of the file on VirusTotal (only its hash is sent)"
                        ))
                        .url(format!("https://www.virustotal.com/gui/file/{sha}")),
                    );
                }
            }
        }
        "program" => steps.push(
            Step::new(tr!("Uninstall \"{0}\"", item.title))
                .note(tr!("Settings → Apps → Installed apps → find the name → Uninstall.")),
        ),
        "extension" => {
            let browser = text(item.facts.at("browser"));
            let page = tr!(browser_page(&browser));
            steps.push(Step::new(tr!("Remove the extension from {0}", browser)).note(tr!(
                "Open {0} in the browser, find \"{1}\" and select Remove.",
                page,
                item.title
            )));
        }
        "config" => {
            let topic = item.facts.at("topic").as_str().unwrap_or("");
            steps.extend(config_steps(topic));
            if topic == "defender_exclusions" {
                for path in list(item.facts.at("paths")).iter().take(8) {
                    let path = str_of(path);
                    if let Some(quoted) = ps_quote(Some(&path)) {
                        steps.push(
                            Step::new(tr!("Remove the exclusion {0}", path))
                                .command(format!("Remove-MpPreference -ExclusionPath {quoted}"))
                                .admin(true),
                        );
                    }
                }
            }
            if topic == "additional_accounts" {
                for account in list(item.facts.at("accounts")).iter().take(6) {
                    let name = str_of(account.at("name"));
                    if let Some(quoted) = ps_quote(Some(&name)) {
                        steps.push(
                            Step::new(tr!("Disable the account \"{0}\" if you do not recognize it", name))
                                .command(format!("Disable-LocalUser -Name {quoted}"))
                                .admin(true)
                                .danger(),
                        );
                    }
                }
            }
        }
        "event" => match item.facts.at("category").as_str().unwrap_or("") {
            "antivirus_detection" => {
                steps.push(Step::new(tr!("View the protection history")).note(tr!(
                    "Windows Security → Virus & threat protection → Protection history."
                )));
                steps.push(Step::new(tr!("Run a full scan")).command("Start-MpScan -ScanType FullScan"));
            }
            "remote_desktop" | "remote_logon" | "failed_logons" => steps.push(
                Step::new(tr!("If you do not use Remote Desktop, turn it off")).note(tr!(
                    "Settings → System → Remote Desktop. Change your password if you do not recognize the sign-ins."
                )),
            ),
            _ => {}
        },
        _ => {}
    }
    steps.iter().map(Step::to_value).collect()
}
