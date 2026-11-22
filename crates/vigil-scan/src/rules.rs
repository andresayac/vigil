//! Local heuristic rules: command, path and file-name patterns.
//!
//! They are deterministic and work offline. They do not replace an antivirus: they produce a
//! risk score and the reasons behind it, which the AI then uses as hints.

use std::sync::LazyLock;

use serde_json::{Map, Value};

use crate::lenient::{Get, Rx, char_len, is_true, lower, rx, text, truthy};
use crate::model::Flag;
use crate::ntpath::{WINDIR, basename, splitext};
use vigil_i18n::{tl, tr};

/// Patterns compiled case-insensitive with `.` matching newlines (case-insensitive, dot-all).
fn is_rx(pattern: &str) -> Rx {
    Rx::new(&format!("(?is){pattern}"))
}

// --------------------------------------------------------------------------- commands

struct Pattern {
    code: &'static str,
    weight: i64,
    text: &'static str,
    rx: Rx,
}

fn pattern(code: &'static str, weight: i64, text: &'static str, source: &str) -> Pattern {
    Pattern {
        code,
        weight,
        text,
        rx: is_rx(source),
    }
}

/// Applied to the command line, to inline code and to the decoded content of an -EncodedCommand.
static COMMAND_PATTERNS: LazyLock<Vec<Pattern>> = LazyLock::new(|| {
    vec![
        pattern(
            "miner",
            80,
            tl!("typical cryptocurrency miner parameters"),
            r"stratum\+(tcp|ssl|tls)://|\bxmrig\b|--donate-level|--cpu-max-threads-hint|\bcryptonight\b|\brandomx\b|nicehash|minexmr|nanopool|supportxmr|2miners\.com|ethermine|f2pool|-o\s+\S*pool\S*:\d{2,5}",
        ),
        pattern(
            "anti_recovery",
            70,
            tl!("deletes backups or logs (typical of ransomware or of someone covering their tracks)"),
            r"vssadmin(\.exe)?\s+.*delete\s+shadows|shadowcopy\s+.*delete|wbadmin\s+delete\s+catalog|bcdedit(\.exe)?\s+.*(recoveryenabled\s+no|bootstatuspolicy\s+ignoreallfailures)|wevtutil(\.exe)?\s+(cl|clear-log)\b|clear-eventlog|fsutil\s+usn\s+deletejournal",
        ),
        pattern(
            "offensive_tool",
            70,
            tl!("mentions well-known attack tools"),
            r"mimikatz|sekurlsa|lsadump|powersploit|invoke-empire|powershell[- ]empire|cobalt\s*strike|meterpreter|invoke-obfuscation|sharphound|bloodhound|\brubeus\b|lazagne|nishang|powercat|invoke-powershelltcp|invoke-shellcode|invoke-reflectivepeinjection|procdump(64)?(\.exe)?\s+.*lsass|comsvcs(\.dll)?\s*,?\s*(#24|minidump)",
        ),
        pattern(
            "disables_defenses",
            60,
            tl!("tries to disable the antivirus or the firewall, or to add exclusions"),
            r"add-mppreference\s+.*-exclusion|set-mppreference\s+.*-disable\w+\s+(\$?true|1)\b|disableantispyware|netsh(\.exe)?\s+advfirewall\s+set\s+\w+\s+state\s+off|netsh(\.exe)?\s+firewall\s+set\s+opmode\s+disable|sc(\.exe)?\s+(stop|delete|config)\s+(windefend|wscsvc|sense|mpssvc|wuauserv)\b|taskkill.*\b(msmpeng|mbam|avp|avastsvc|avgsvc)\b",
        ),
        pattern(
            "amsi_bypass",
            60,
            tl!("tries to bypass antimalware script scanning (AMSI)"),
            r"amsiinitfailed|amsiutils|amsiscanbuffer|amsi\.dll",
        ),
        pattern(
            "regsvr32_scriptlet",
            60,
            tl!("regsvr32 loading a scriptlet (covert execution technique)"),
            r"\bregsvr32(\.exe)?\b.*(/i:\s*(https?|ftp):|scrobj\.dll)",
        ),
        pattern(
            "reverse_shell",
            55,
            tl!("opens a remotely controllable network connection (reverse shell)"),
            r"net\.sockets\.tcpclient|system\.net\.sockets\.tcpclient|/dev/tcp/|\bnc(at)?(\.exe)?\s+.*-e\s+(cmd|powershell)",
        ),
        // "administra\w+" also matches localized group names (Administradores, Administrateurs...).
        pattern(
            "creates_account",
            50,
            tl!("creates users or adds them to the administrators group"),
            r"\bnet1?(\.exe)?\s+user\s+\S+\s+\S+\s+/add|\bnet1?(\.exe)?\s+localgroup\s+administra\w+\s+\S+\s+/add|new-localuser|add-localgroupmember",
        ),
        pattern(
            "remote_mshta",
            50,
            tl!("mshta running remote or inline code"),
            r"\bmshta(\.exe)?\b.*((https?|ftp):|javascript:|vbscript:)",
        ),
        pattern(
            "rundll32_proxy",
            45,
            tl!("rundll32 used to launch something else (indirect execution)"),
            r"\brundll32(\.exe)?\b.*(javascript:|vbscript:|mshtml\s*,\s*runhtmlapplication|shell32(\.dll)?\s*,\s*shellexec_rundll|url(\.dll)?\s*,\s*(fileprotocolhandler|openurl)|advpack(\.dll)?\s*,\s*(launchinfsection|registerocx)|pcwutl(\.dll)?\s*,\s*launchapplication|zipfldr(\.dll)?\s*,\s*routethecall|ieadvpack)",
        ),
        pattern(
            "memory_injection",
            45,
            tl!("loads or injects code directly into memory"),
            r"virtualalloc|virtualprotect|writeprocessmemory|createremotethread|getdelegateforfunctionpointer|reflection\.assembly\]::load\(",
        ),
        pattern(
            "keylogger",
            45,
            tl!("uses functions typical of keystroke capture"),
            r"getasynckeystate|setwindowshookex",
        ),
        pattern(
            "certutil_download",
            40,
            tl!("certutil used to download or decode files"),
            r"\bcertutil(\.exe)?\b.*[-/](urlcache|decode|decodehex)\b",
        ),
        pattern(
            "remote_scriptlet",
            40,
            tl!("loads a remote COM scriptlet"),
            r"script:(https?|ftp)://|\.sct\b",
        ),
        pattern(
            "bitsadmin_download",
            35,
            tl!("bitsadmin used to download or to persist"),
            r"\bbitsadmin(\.exe)?\b.*/(transfer|addfile|setnotifycmdline)",
        ),
        pattern(
            "obfuscation",
            30,
            tl!("obfuscated command (escape characters or dynamic construction)"),
            r"(\[char\]\s*\(?\s*\d+.{0,40}){4,}|-bxor\b|(\^[a-z]){5,}|(`[a-z]){5,}|('\s*\+\s*'[^']{1,4}){5,}",
        ),
        pattern(
            "network_download",
            25,
            tl!("downloads content from the Internet"),
            r"downloadstring|downloadfile|downloaddata|invoke-webrequest|\biwr\b|\birm\b|invoke-restmethod|start-bitstransfer|net\.webclient|\bcurl(\.exe)?\s+[^|&]*https?://|\bwget\s+[^|&]*https?://",
        ),
        // The original also excludes private ranges with a lookahead; see `ip_url_match`.
        pattern(
            "ip_url",
            25,
            tl!("URL that points to an IP address instead of a domain"),
            r"(https?|ftp)://",
        ),
        pattern(
            "abused_site",
            25,
            tl!("uses a hosting or tunnelling service widely abused by malware"),
            r"pastebin\.com|paste\.ee|hastebin|ghostbin|rentry\.(co|org)|transfer\.sh|anonfiles|file\.io/|cdn\.discordapp\.com/attachments|discord(app)?\.com/api/webhooks|api\.telegram\.org/bot|bit\.ly/|tinyurl\.com/|is\.gd/|ngrok(-free)?\.(io|app|dev)|trycloudflare\.com|duckdns\.org|\.no-ip\.|ddns\.net|serveo\.net|portmap\.io",
        ),
        pattern(
            "executes_text",
            20,
            tl!("runs text built at run time as code"),
            r"\biex\b|invoke-expression",
        ),
        pattern(
            "base64_execution",
            15,
            tl!("decodes Base64 content when it runs"),
            r"frombase64string",
        ),
        pattern(
            "command_persistence",
            15,
            tl!("creates tasks, services or startup entries"),
            r"schtasks(\.exe)?\s+.*/create|register-scheduledtask|new-service\b|\bsc(\.exe)?\s+create\b|reg(\.exe)?\s+add\s+.*\\(run|runonce)\b|set-itemproperty\s+.*\\currentversion\\run",
        ),
    ]
});

rx!(IP_URL_HOST, r"\A\d{1,3}(\.\d{1,3}){3}");
rx!(IP_URL_PRIVATE, r"\A(127\.|0\.0\.0\.0|10\.|192\.168\.|169\.254\.)");

/// `(https?|ftp)://(?!127\.|0\.0\.0\.0|10\.|192\.168\.|169\.254\.)\d{1,3}(\.\d{1,3}){3}`
/// (the `regex` crate has no lookahead, so the exclusion is checked by hand).
fn ip_url_match(scheme: &Rx, text: &str) -> bool {
    let mut start = 0;
    while let Some(found) = scheme.find_at(text, start) {
        let rest = &text[found.end()..];
        if !IP_URL_PRIVATE.is_match(rest) && IP_URL_HOST.is_match(rest) {
            return true;
        }
        start = found.start() + text[found.start()..].chars().next().map_or(1, char::len_utf8);
    }
    false
}

/// Signals in one or more views of the same command (each pattern counts only once).
pub fn scan_command(texts: &[Option<&str>]) -> Vec<Flag> {
    let joined = texts
        .iter()
        .flatten()
        .filter(|t| !t.is_empty())
        .copied()
        .collect::<Vec<_>>()
        .join("\n");
    if joined.is_empty() {
        return Vec::new();
    }
    COMMAND_PATTERNS
        .iter()
        .filter(|p| {
            if p.code == "ip_url" {
                ip_url_match(&p.rx, &joined)
            } else {
                p.rx.is_match(&joined)
            }
        })
        .map(|p| Flag::new(p.code, p.weight, tr!(p.text)))
        .collect()
}

/// [`scan_command`] for a single text.
pub fn scan_text(text: &str) -> Vec<Flag> {
    scan_command(&[Some(text)])
}

// --------------------------------------------------------------------------- known names

static REMOTE_TOOLS: LazyLock<Rx> = LazyLock::new(|| {
    is_rx(
        r"anydesk|teamviewer|rustdesk|screenconnect|connectwise|splashtop|logmein|gotoassist|ammyy|supremo|netsupport|client32\.exe|remote utilities|rutserv|rfusclient|dwagent|dwservice|meshagent|meshcentral|\batera|syncro|ninjarmm|tightvnc|ultravnc|realvnc|tigervnc|winvnc|vncserver|\bradmin\b|aeroadmin|zoho assist|getscreen|hoptodesk|remotepc|\bparsec|chrome remote desktop|chromoting|remoting_host|tailscale|zerotier|\bngrok|cloudflared|\bfrpc?\b|\bchisel\b|\bplink\b|\\openssh\\sshd|\bsshd\.exe",
    )
});
static PIRACY_TOOLS: LazyLock<Rx> = LazyLock::new(|| {
    is_rx(
        r"kmspico|kmsauto|kms[-_ ]?activator|autokms|kmseldi|kms_vl_all|kmsemulator|sppextcomobjhook|vlmcsd|microsoft[ _]toolkit|re-?loader activator|\baact\b|w10 ?digital ?activation|hwidgen|ratiborus|massgrave|\bohook\b|\bkeygen\b|\bcrack(ed)?\b|\bpatch(er)?\.exe",
    )
});
static PUP_NAMES: LazyLock<Rx> = LazyLock::new(|| {
    is_rx(
        r"toolbar|driver ?booster|driver ?updater|driver ?easy|driverpack ?solution|drivermax|pc ?optimizer|pc ?cleaner|registry ?cleaner|speedup|mypcbackup|web ?companion|bytefence|segurazo|\bwajam|conduit|babylon|mindspark|opencandy|installcore|softonic|reimage|restoro|advanced systemcare|slimcleaner|onesafe|pc ?accelerate|iobit|wise care|system mechanic|mcafee webadvisor|mcafee security scan|avast secure browser|browser assistant|search protect|yontoo|crossrider|superfish|coupon|shopping assistant|pc ?app ?store|utorrent|bittorrent web|hola vpn|winzip driver|total av|\bmackeeper",
    )
});
pub(crate) static OBSOLETE_SOFTWARE: LazyLock<Rx> = LazyLock::new(|| {
    is_rx(
        r"adobe flash player|shockwave player|silverlight|quicktime|java\(tm\) (6|7)\b|java (6|7|8) update|python 2\.\d|internet explorer|adobe reader (9|x|xi)\b|winrar [1-5]\.|real ?player|toolbar",
    )
});

/// A remote access, remote control or tunnelling tool named in the text (a program's name,
/// publisher or paths), from the same lists the scan uses: the broad name pattern above and the
/// table of remote management agents (`crate::rmm::AGENTS`), which also gives each agent's
/// expected signer.
pub fn is_remote_access_tool(text: &str) -> bool {
    REMOTE_TOOLS.is_match(text) || crate::rmm::agent_for(text).is_some()
}

/// Signals based on names (program, service, task, path).
pub fn label_flags(names: &[&str]) -> Vec<Flag> {
    let text = names
        .iter()
        .filter(|n| !n.is_empty())
        .copied()
        .collect::<Vec<_>>()
        .join(" | ");
    if text.is_empty() {
        return Vec::new();
    }
    let mut flags = Vec::new();
    if PIRACY_TOOLS.is_match(&text) {
        flags.push(Flag::new(
            "piracy_activator",
            50,
            tr!("name associated with activators or cracks (a very common infection route)"),
        ));
    }
    if is_remote_access_tool(&text) {
        flags.push(Flag::new(
            "remote_access",
            15,
            tr!("remote access, VPN or tunnelling tool: confirm that you installed it"),
        ));
    }
    if PUP_NAMES.is_match(&text) {
        flags.push(Flag::new(
            "pup",
            25,
            tr!("name associated with potentially unwanted software or bloatware"),
        ));
    }
    flags
}

// --------------------------------------------------------------------------- paths

const EXT: &str = r"(exe|dll|scr|com|bat|cmd|vbs|vbe|js|jse|ps1|hta|pif|sys)";

static LOCATION_RULES: LazyLock<Vec<Pattern>> = LazyLock::new(|| {
    vec![
        pattern(
            "path_recycle_bin",
            50,
            tl!("runs from the Recycle Bin"),
            r"\\\$recycle\.bin\\",
        ),
        pattern(
            "alternate_data_stream",
            60,
            tl!("runs from an alternate data stream (a file hidden inside another file)"),
            r"^[a-z]:\\.*\.[a-z0-9]{1,5}:[^\\]+$",
        ),
        pattern(
            "path_system_volume",
            50,
            tl!("runs from System Volume Information"),
            r"\\system volume information\\",
        ),
        pattern(
            "path_unusual_windows",
            45,
            tl!("runs from a Windows folder that should not contain programs"),
            r"\\windows\\(fonts|tasks|debug|help|media|cursors|web|tracing|addins|pla|ime|security\\logs)\\",
        ),
        pattern(
            "path_temp",
            30,
            tl!("runs from a temporary folder"),
            r"\\appdata\\local\\temp\\|\\windows\\temp\\|^[a-z]:\\te?mp\\",
        ),
        pattern(
            "path_public",
            30,
            tl!("runs from the public folder (C:\\Users\\Public)"),
            r"\\users\\public\\",
        ),
        pattern(
            "path_appdata_root",
            30,
            tl!("loose executable in the root of AppData (a typical malware location)"),
            &format!(r"\\appdata\\(roaming|local|locallow)\\[^\\]+\.{EXT}$"),
        ),
        pattern(
            "path_programdata_root",
            30,
            tl!("loose executable in the root of ProgramData"),
            &format!(r"^[a-z]:\\programdata\\[^\\]+\.{EXT}$"),
        ),
        pattern(
            "path_hidden_root",
            30,
            tl!("runs from an unusual system folder"),
            r"^[a-z]:\\(perflogs|msocache|recovery|intel|\$[^\\]+)\\",
        ),
        pattern(
            "path_downloads",
            15,
            tl!("runs from the Downloads folder"),
            r"\\downloads\\",
        ),
        pattern(
            "path_drive_root",
            15,
            tl!("loose executable in the root of the drive"),
            &format!(r"^[a-z]:\\[^\\]+\.{EXT}$"),
        ),
        // "escritorio" is the on-disk name of the Desktop folder on some Spanish-language installations.
        pattern(
            "path_desktop",
            10,
            tl!("runs from the Desktop"),
            r"\\(desktop|escritorio)\\",
        ),
    ]
});

// Folders only an administrator can write to: an unprivileged program cannot place or replace files there.
static PROTECTED: LazyLock<Rx> =
    LazyLock::new(|| is_rx(r"^[a-z]:\\(program files( \(x86\))?|windows|programdata\\microsoft)\\"));
static WRITABLE_INSIDE_WINDOWS: LazyLock<Rx> =
    LazyLock::new(|| is_rx(r"\\windows\\(temp|tasks|tracing|system32\\tasks|system32\\spool\\drivers\\color)\\"));
// Normal locations for Microsoft-signed binaries.
static MS_HOMES: LazyLock<Rx> = LazyLock::new(|| {
    is_rx(
        r"^[a-z]:\\windows\\|^[a-z]:\\program files( \(x86\))?\\|^[a-z]:\\programdata\\microsoft\\|\\appdata\\local\\microsoft\\|\\appdata\\local\\programs\\microsoft vs code( insiders)?\\|\\appdata\\local\\programs\\(common\\)?microsoft\\|\\appdata\\local\\packages\\microsoft|\\\.vscode(-insiders)?\\|\\\.dotnet\\",
    )
});

pub fn location_flags(path: &str) -> Vec<Flag> {
    LOCATION_RULES
        .iter()
        .filter(|p| p.rx.is_match(path))
        .map(|p| Flag::new(p.code, p.weight, tr!(p.text)))
        .collect()
}

/// An unprivileged user can modify the folder (everything except the protected folders).
pub fn is_user_writable(path: &str) -> bool {
    !PROTECTED.is_match(path) || WRITABLE_INSIDE_WINDOWS.is_match(path)
}

pub fn in_microsoft_home(path: &str) -> bool {
    MS_HOMES.is_match(path)
}

pub fn in_windows_dir(path: &str) -> bool {
    lower(path).starts_with(&format!("{}\\", lower(&WINDIR)))
}

// --------------------------------------------------------------------------- file names

/// System processes that must only run from the Windows folder.
const SYSTEM_NAMES: &[&str] = &[
    "svchost.exe",
    "lsass.exe",
    "csrss.exe",
    "smss.exe",
    "services.exe",
    "winlogon.exe",
    "wininit.exe",
    "spoolsv.exe",
    "taskhostw.exe",
    "dllhost.exe",
    "conhost.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "runtimebroker.exe",
    "sihost.exe",
    "ctfmon.exe",
    "dwm.exe",
    "fontdrvhost.exe",
    "searchindexer.exe",
    "audiodg.exe",
    "userinit.exe",
    "taskmgr.exe",
    "cmd.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "wmiprvse.exe",
    "msiexec.exe",
    "backgroundtaskhost.exe",
    "securityhealthservice.exe",
    "sppsvc.exe",
    "werfault.exe",
    "dashost.exe",
    "smartscreen.exe",
    "lsaiso.exe",
    "explorer.exe",
    "powershell.exe",
    "wuauclt.exe",
    "taskeng.exe",
    "lsm.exe",
    "logonui.exe",
    "consent.exe",
];

/// Usual targets of look-alike names (svch0st, scvhost, lsasss...).
const TYPOSQUAT_TARGETS: &[&str] = &[
    "svchost",
    "lsass",
    "csrss",
    "smss",
    "winlogon",
    "wininit",
    "spoolsv",
    "taskhostw",
    "dllhost",
    "conhost",
    "rundll32",
    "explorer",
    "runtimebroker",
    "sihost",
    "ctfmon",
    "fontdrvhost",
    "searchindexer",
    "audiodg",
    "chrome",
    "firefox",
    "msedge",
];

static DOUBLE_EXT: LazyLock<Rx> = LazyLock::new(|| {
    is_rx(
        r"\.(pdf|docx?|xlsx?|pptx?|txt|rtf|jpe?g|png|gif|bmp|mp[34]|avi|mkv|zip|rar|7z|html?)\s*\.(exe|scr|com|bat|cmd|pif|vbs|js|lnk|hta)$",
    )
});
rx!(ALNUM_LOWER, r"^[a-z0-9]+$");
rx!(HEX_LONG, r"^[0-9a-f]{8,}$");
rx!(FOUR_LETTERS, r"[a-z]{4,}");

/// Edit distance with transpositions (optimal string alignment).
fn osa_distance(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let mut prev2: Vec<usize> = Vec::new();
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    for i in 1..=a.len() {
        let ca = a[i - 1];
        let mut cur = vec![0; b.len() + 1];
        cur[0] = i;
        for j in 1..=b.len() {
            let cb = b[j - 1];
            let cost = usize::from(ca != cb);
            cur[j] = (prev[j] + 1).min(cur[j - 1] + 1).min(prev[j - 1] + cost);
            if i > 1 && j > 1 && ca == b[j - 2] && a[i - 2] == cb {
                cur[j] = cur[j].min(prev2[j - 2] + 1);
            }
        }
        prev2 = std::mem::replace(&mut prev, cur);
    }
    prev[b.len()]
}

fn leet(stem: &str) -> String {
    stem.chars()
        .map(|c| match c {
            '0' => 'o',
            '1' => 'l',
            '3' => 'e',
            '5' | '$' => 's',
            '@' => 'a',
            other => other,
        })
        .collect::<String>()
        .replace("rn", "m")
        .replace("vv", "w")
}

/// Signals from the file name: impersonation of system processes, double extension.
///
/// `signed`: it has a valid signature from any publisher (an odd name is then no longer a signal).
pub fn name_flags(path: &str, ms_signed: bool, signed: bool) -> Vec<Flag> {
    let mut flags = Vec::new();
    let base = lower(basename(path));
    let stem = splitext(&base).0.to_string();

    if base.contains('\u{202e}') {
        flags.push(Flag::new(
            "reversed_name",
            60,
            tr!("the name uses a character that reverses the text to hide the real extension"),
        ));
    }
    if DOUBLE_EXT.is_match(&base) {
        flags.push(Flag::new(
            "double_extension",
            50,
            tr!("double extension: it looks like a document but is an executable"),
        ));
    }

    let in_windows = in_windows_dir(path) || lower(path).contains("\\program files\\windowsapps\\microsoft");
    if SYSTEM_NAMES.contains(&base.as_str()) && !in_windows {
        if ms_signed {
            flags.push(Flag::new(
                "misplaced_windows_binary",
                35,
                tr!("copy of a Windows program outside its folder (possible DLL side-loading)"),
            ));
        } else {
            flags.push(Flag::new(
                "system_impersonation",
                70,
                tr!("uses the name of a Windows process but is not in the Windows folder"),
            ));
        }
    } else if !ms_signed && [".exe", ".scr", ".com"].iter().any(|e| base.ends_with(e)) {
        let normalized = leet(&stem);
        for target in TYPOSQUAT_TARGETS {
            if stem == *target {
                continue;
            }
            if normalized == *target || (target.len() >= 5 && osa_distance(&stem, target) == 1) {
                flags.push(Flag::new(
                    "system_lookalike_name",
                    45,
                    tr!("name almost identical to \"{0}\" (camouflage technique)", target),
                ));
                break;
            }
        }
    }

    if !signed && looks_random(&stem) {
        flags.push(Flag::new("random_name", 10, tr!("random-looking name")));
    }
    flags
}

/// Names such as "a3f9c2e17b" or "x7k2m9q4": long hexadecimal strings or dense mixes of letters and digits.
fn looks_random(stem: &str) -> bool {
    if char_len(stem) < 8 || !ALNUM_LOWER.is_match(stem) {
        return false;
    }
    let letters = stem.chars().filter(char::is_ascii_alphabetic).count();
    let digits = stem.len() - letters;
    if HEX_LONG.is_match(stem) && digits >= 3 {
        return true;
    }
    digits >= 4 && letters >= 4 && !FOUR_LETTERS.is_match(stem)
}

// --------------------------------------------------------------------------- signatures

/// Microsoft signers that identify its own software (not certified third-party drivers).
const MICROSOFT_SIGNERS: &[&str] = &[
    "microsoft windows",
    "microsoft corporation",
    "microsoft windows publisher",
    "microsoft windows kits publisher",
    ".net",
    "microsoft windows early launch anti-malware publisher",
    "microsoft windows tcb publisher",
    "microsoft windows software compatibility publisher",
    "microsoft azure code sign",
    "microsoft dynamic code publisher",
];
/// Microsoft signature on THIRD-PARTY code: it does not mean Microsoft is the author.
const THIRD_PARTY_ATTESTATION: &[&str] = &[
    "microsoft windows hardware compatibility publisher",
    "microsoft windows third party component",
    "microsoft 3rd party application component",
];

/// Valid Microsoft signature on its own software.
pub fn is_microsoft_signed(info: Option<&Map<String, Value>>) -> bool {
    let Some(info) = info.filter(|i| !i.is_empty()) else {
        return false;
    };
    if info.at("sig_status").as_str() != Some("Valid") {
        return false;
    }
    if truthy(info.at("os_binary")) {
        return true;
    }
    let signer = lower(&text(info.at("signer")));
    let issuer = lower(&text(info.at("issuer")));
    if THIRD_PARTY_ATTESTATION.contains(&signer.as_str()) {
        return false;
    }
    MICROSOFT_SIGNERS.contains(&signer.as_str()) && issuer.starts_with("microsoft")
}

/// `info.get("exists") is True`.
pub(crate) fn file_exists(info: Option<&Map<String, Value>>) -> bool {
    info.is_some_and(|i| is_true(i.at("exists")))
}

#[cfg(test)]
pub(crate) fn all_patterns_compile() -> bool {
    COMMAND_PATTERNS
        .iter()
        .chain(LOCATION_RULES.iter())
        .all(|p| p.rx.is_valid())
        && [
            &*REMOTE_TOOLS,
            &*PIRACY_TOOLS,
            &*PUP_NAMES,
            &*OBSOLETE_SOFTWARE,
            &*PROTECTED,
            &*WRITABLE_INSIDE_WINDOWS,
            &*MS_HOMES,
            &*DOUBLE_EXT,
        ]
        .iter()
        .all(|r| r.is_valid())
        && [
            &*IP_URL_HOST,
            &*IP_URL_PRIVATE,
            &*ALNUM_LOWER,
            &*HEX_LONG,
            &*FOUR_LETTERS,
        ]
        .iter()
        .all(|r| r.is_valid())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn patterns_compile() {
        assert!(all_patterns_compile());
    }

    #[test]
    fn ip_urls() {
        let codes = |t: &str| scan_text(t).into_iter().map(|f| f.code).collect::<Vec<_>>();
        assert!(codes("iwr http://203.0.113.7/a").contains(&"ip_url".to_string()));
        assert!(!codes("iwr http://192.168.1.4/a").contains(&"ip_url".to_string()));
        assert!(!codes("http://10.0.0.1/ and http://example.org").contains(&"ip_url".to_string()));
        assert!(codes("http://10.0.0.1/ then https://198.51.100.2/").contains(&"ip_url".to_string()));
    }

    #[test]
    fn flag_texts_follow_the_language() {
        let lookalike = |lang: &str| {
            vigil_i18n::with_language(lang, || {
                name_flags(r"C:\Users\jdoe\AppData\Local\scvhost.exe", false, false)
            })
        };
        let (english, spanish, chinese) = (lookalike("en"), lookalike("es"), lookalike("zh"));
        let code = "system_lookalike_name";
        let text = |flags: &[Flag]| flags.iter().find(|f| f.code == code).map(|f| f.text.clone());
        assert_eq!(
            text(&english).as_deref(),
            Some("name almost identical to \"svchost\" (camouflage technique)")
        );
        assert_eq!(
            text(&spanish).as_deref(),
            Some("nombre casi idéntico a \"svchost\" (técnica de camuflaje)")
        );
        assert_eq!(text(&chinese).as_deref(), Some("名称与“svchost”几乎相同（伪装技术）"));
        let ip = vigil_i18n::with_language("fr", || scan_text("iwr http://203.0.113.7/a"));
        let ip = ip.iter().find(|f| f.code == "ip_url").expect("ip_url flag");
        assert_eq!(ip.text, "URL qui pointe vers une adresse IP au lieu d'un domaine");
    }

    #[test]
    fn distance() {
        assert_eq!(osa_distance("scvhost", "svchost"), 1);
        assert_eq!(osa_distance("lsasss", "lsass"), 1);
        assert_eq!(osa_distance("service", "svchost"), 6);
    }
}
