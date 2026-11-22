//! Certificates Windows trusts, in the scan. READ-ONLY: the stores are read with
//! `vigil_sys::certs` (opened read-only, nothing added or removed).
//!
//! A root certificate lets whoever holds its private key make any website, or any signed program,
//! look genuine on this computer. Roots in Microsoft's Trusted Root Program are normal; so are the
//! few old roots Windows itself ships. Everything else is kept in `sysconfig.certificates` and
//! judged here:
//!
//! - a root added to your account's store (programs need no administrator rights for that, which
//!   is why adware and banking malware use it), more so when it was added in the last week;
//! - a root on the computer that is in no program and belongs to nothing Vigil recognizes;
//! - a root whose name imitates a well-known authority, or one of the few known-bad roots
//!   (Superfish, eDellRoot, PrivDog);
//! - programs that inspect encrypted connections (debugging proxies, antivirus HTTPS scanning,
//!   company web filters): information, since they are fine when you installed them yourself;
//! - local development authorities and certificates for this computer's own web server:
//!   information;
//! - self-made code-signing certificates trusted as a publisher.

use chrono::{Local, NaiveDateTime, TimeZone};
use serde_json::{Map, Value, json};
use vigil_i18n::tr;

use crate::lenient::{Get, list, lower, take, text};
use crate::model::{Flag, Item};

/// Where collection stores its results in the inventory.
pub(crate) const SECTION: &str = "certificates";

/// A root added this many days before the scan counts as recent.
const RECENT_DAYS: i64 = 7;

/// The old roots Windows itself ships, outside the root program (SHA-1 thumbprints, checked on a
/// Windows 11 computer). A root with one of these names and another thumbprint imitates them.
const WINDOWS_ROOTS: &[(&str, &str)] = &[
    (
        "7F88CD7223F3C813818C994614A89C99FA3B5247",
        "microsoft authenticode(tm) root authority",
    ),
    (
        "245C97DF7514E7CF2DF8BE72AE957B9E04741E85",
        "copyright (c) 1997 microsoft corp.",
    ),
    ("A43489159A520F0D93D032CCAF37E7FE20A8B419", "microsoft root authority"),
    (
        "CDD4EEAE6000AC7F40C3802C171E30148030C072",
        "microsoft root certificate authority",
    ),
    (
        "3B1EFD3A66EA28B16697394703A72CA340A05BD5",
        "microsoft root certificate authority 2010",
    ),
    (
        "8F43288AD272F3103B6FB1428485EA3014C0BCFE",
        "microsoft root certificate authority 2011",
    ),
    (
        "92B46C76E13054E104F230517E6E504D43AB10B5",
        "symantec enterprise mobile root for microsoft",
    ),
    ("BE36A4562FB2EE05DBB3D32323ADF445084ED656", "thawte timestamping ca"),
    (
        "18F7C1FCC3090203FD5BAA2F861A754976C8DD25",
        "no liability accepted, (c)97 verisign, inc.",
    ),
];

/// Roots installed by adware or by software that shipped a root with its private key: whoever has
/// the key can impersonate any website on this computer.
const KNOWN_BAD: &[&str] = &["superfish", "edellroot", "privdog", "dsdtestprovider"];

/// Programs that install a root so they can read encrypted connections (lower case, matched as
/// words against the subject, issuer and friendly name).
const INTERCEPTION: &[(&str, &str)] = &[
    ("mitmproxy", "mitmproxy"),
    ("http toolkit", "HTTP Toolkit"),
    ("fiddler", "Fiddler"),
    ("do_not_trust_fiddlerroot", "Fiddler"),
    ("charles proxy", "Charles Proxy"),
    ("portswigger", "Burp Suite"),
    ("burp", "Burp Suite"),
    ("proxyman", "Proxyman"),
    ("owasp zap", "OWASP ZAP"),
    ("zscaler", "Zscaler"),
    ("netskope", "Netskope"),
    ("fortigate", "Fortinet"),
    ("fortinet", "Fortinet"),
    ("palo alto", "Palo Alto Networks"),
    ("cisco umbrella", "Cisco Umbrella"),
    ("sophos", "Sophos"),
    ("blue coat", "Blue Coat"),
    ("forcepoint", "Forcepoint"),
    ("websense", "Forcepoint"),
    ("check point", "Check Point"),
    ("avast", "Avast"),
    ("avg", "AVG"),
    ("kaspersky", "Kaspersky"),
    ("eset ssl filter", "ESET"),
    ("bitdefender", "Bitdefender"),
    ("norton", "Norton"),
    ("mcafee", "McAfee"),
    ("adguard", "AdGuard"),
    ("netfree", "NetFree"),
];

/// Local development authorities and tools that make HTTPS work for local sites (matched as
/// words, lower case).
const DEVELOPMENT: &[&str] = &[
    "mkcert",
    "caddy local authority",
    "local development",
    "development ca",
    "development certificate",
    "asp.net core https development",
    "iis express",
    "laragon",
    "laravel valet",
    "herd",
    "xampp",
    "wampserver",
    "minikube",
    "docker",
    "localhost",
];

/// Well-known authorities whose names a fake root borrows to look genuine.
const BRANDS: &[&str] = &[
    "digicert",
    "globalsign",
    "sectigo",
    "comodo",
    "verisign",
    "thawte",
    "geotrust",
    "entrust",
    "godaddy",
    "go daddy",
    "let's encrypt",
    "isrg",
    "baltimore",
    "usertrust",
    "identrust",
    "quovadis",
    "certum",
    "amazon",
    "google trust",
    "microsoft",
    "apple",
];

/// Subjects that say nothing about who made the root.
const GENERIC: &[&str] = &[
    "root ca",
    "root",
    "ca",
    "certificate authority",
    "root certificate authority",
    "test",
    "test ca",
    "default",
    "my ca",
    "localhost ca",
];

const CODE_SIGNING: &str = "1.3.6.1.5.5.7.3.3";
const SERVER_AUTH: &str = "1.3.6.1.5.5.7.3.1";

// ------------------------------------------------------------------------------- collection

#[cfg(windows)]
pub(crate) fn collect() -> Value {
    let stores = vigil_sys::certs::read();
    let program = vigil_sys::certs::root_program();
    let computer = lower(&std::env::var("COMPUTERNAME").unwrap_or_default());
    let mut roots = Vec::new();
    let mut publishers = Vec::new();
    let mut in_program = 0usize;
    let mut intermediates = Map::new();
    for cert in &stores.certificates {
        match cert.store.as_str() {
            "Root" => {
                if cert.program_property || program.as_ref().is_some_and(|p| p.contains(&cert.sha1)) {
                    in_program += 1;
                } else {
                    roots.push(cert_json(cert, &computer));
                }
            }
            "TrustedPublisher" => publishers.push(cert_json(cert, &computer)),
            _ => {
                let count = intermediates.get(&cert.scope).and_then(Value::as_u64).unwrap_or(0);
                intermediates.insert(cert.scope.clone(), json!(count + 1));
            }
        }
    }
    let mut notes = Vec::new();
    if program.is_none() {
        notes.push(json!({
            "area": tr!("Root certificates"),
            "message": tr!("Windows' list of trusted root authorities could not be read; roots were judged by name only"),
        }));
    }
    if !stores.unreadable.is_empty() {
        notes.push(json!({
            "area": tr!("Root certificates"),
            "message": tr!("some certificate stores could not be read: {0}", stores.unreadable.join(", ")),
        }));
    }
    json!({
        "program_known": program.is_some(),
        "program_size": program.as_ref().map_or(0, |p| p.len()),
        "roots_in_program": in_program,
        "roots": roots,
        "publishers": publishers,
        "intermediates": intermediates,
        "notes": notes,
    })
}

#[cfg(not(windows))]
pub(crate) fn collect() -> Value {
    json!({})
}

#[cfg(windows)]
fn cert_json(cert: &vigil_sys::certs::Certificate, computer: &str) -> Value {
    let subject = lower(&cert.subject);
    let own_name = !subject.is_empty()
        && (subject == "localhost" || subject == "127.0.0.1" || (!computer.is_empty() && subject == computer));
    json!({
        "scope": cert.scope,
        "store": cert.store,
        "subject": cert.subject,
        "issuer": cert.issuer,
        "friendly_name": cert.friendly_name,
        "sha1": cert.sha1,
        "not_before": local_iso(cert.not_before_ms),
        "not_after": local_iso(cert.not_after_ms),
        "self_signed": cert.self_signed,
        "ca": cert.ca,
        "usages": cert.usages,
        "added": cert.added_ms.map(local_iso).unwrap_or_default(),
        "own_name": own_name,
    })
}

/// Unix ms as local `YYYY-MM-DDTHH:MM:SS` ("" for 0 or out of range).
fn local_iso(ms: i64) -> String {
    if ms <= 0 {
        return String::new();
    }
    Local
        .timestamp_millis_opt(ms)
        .single()
        .map(|t| t.format("%Y-%m-%dT%H:%M:%S").to_string())
        .unwrap_or_default()
}

// ------------------------------------------------------------------------------- judging

fn reference_time(raw: &Value) -> Option<NaiveDateTime> {
    let started = text(raw.at("meta").at("started"));
    NaiveDateTime::parse_from_str(take(&started, 19), "%Y-%m-%dT%H:%M:%S").ok()
}

fn days_before(iso: &str, reference: Option<NaiveDateTime>) -> Option<i64> {
    let when = NaiveDateTime::parse_from_str(take(iso, 19), "%Y-%m-%dT%H:%M:%S").ok()?;
    let now = reference.unwrap_or_else(|| Local::now().naive_local());
    Some((now - when).num_seconds().div_euclid(86_400))
}

/// Whether `needle` appears in `hay` as whole words (both lower case).
fn has_words(hay: &str, needle: &str) -> bool {
    let bytes = hay.as_bytes();
    let mut start = 0;
    while let Some(found) = hay[start..].find(needle) {
        let at = start + found;
        let end = at + needle.len();
        let before = at == 0 || !bytes[at - 1].is_ascii_alphanumeric();
        let after = end == bytes.len() || !bytes[end].is_ascii_alphanumeric();
        if before && after {
            return true;
        }
        start = at + 1;
    }
    false
}

/// What a root outside the program is, as far as its names tell.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Kind {
    /// One of the old roots Windows ships.
    Windows,
    KnownBad(String),
    /// A program that reads encrypted connections (its product name).
    Interception(String),
    Development,
    /// Uses the name of a well-known authority (the brand) without being its root.
    Imitation(String),
    Unknown,
}

pub(crate) fn kind_of(cert: &Value) -> Kind {
    let subject = lower(&text(cert.at("subject")));
    let names = format!(
        "{} | {} | {}",
        subject,
        lower(&text(cert.at("issuer"))),
        lower(&text(cert.at("friendly_name")))
    );
    let sha1 = text(cert.at("sha1")).to_uppercase();
    if let Some((thumb, _)) = WINDOWS_ROOTS.iter().find(|(_, name)| subject == *name) {
        return if *thumb == sha1 {
            Kind::Windows
        } else {
            Kind::Imitation("Microsoft".to_string())
        };
    }
    if let Some(bad) = KNOWN_BAD.iter().find(|b| names.contains(*b)) {
        return Kind::KnownBad((*bad).to_string());
    }
    if let Some((_, product)) = INTERCEPTION.iter().find(|(word, _)| has_words(&names, word)) {
        return Kind::Interception((*product).to_string());
    }
    let only_itself = cert.at("ca").as_bool() == Some(false);
    let own_server = cert.at("own_name").as_bool() == Some(true) && {
        let usages = list(cert.at("usages"));
        usages.len() == 1 && text(&usages[0]) == SERVER_AUTH
    };
    if only_itself || own_server || DEVELOPMENT.iter().any(|d| has_words(&names, d)) {
        return Kind::Development;
    }
    if let Some(brand) = BRANDS.iter().find(|b| has_words(&subject, b)) {
        return Kind::Imitation((*brand).to_string());
    }
    Kind::Unknown
}

fn config(
    topic: &str,
    title: String,
    score: i64,
    summary: String,
    facts: Map<String, Value>,
    extra: Vec<Flag>,
) -> Item {
    let mut item = Item::new("config", title, summary.clone());
    let mut all = Map::new();
    all.insert("topic".into(), json!(topic));
    all.extend(facts);
    item.facts = all;
    item.add_flag(Flag::new(topic, score, summary));
    for flag in extra {
        item.add_flag(flag);
    }
    item.rescore();
    item
}

fn cert_facts(cert: &Value) -> Map<String, Value> {
    [
        "scope",
        "store",
        "subject",
        "issuer",
        "friendly_name",
        "sha1",
        "not_before",
        "not_after",
        "added",
        "usages",
    ]
    .iter()
    .map(|k| ((*k).to_string(), cert.at(k).clone()))
    .collect()
}

fn store_name(cert: &Value) -> String {
    match text(cert.at("scope")).as_str() {
        "user" => tr!("your account's trusted root store"),
        "policy" => tr!("the trusted root store set by Group Policy"),
        "enterprise" => tr!("the enterprise trusted root store"),
        _ => tr!("the computer's trusted root store"),
    }
}

fn shown_name(cert: &Value) -> String {
    let subject = text(cert.at("subject"));
    if subject.is_empty() {
        text(cert.at("sha1"))
    } else {
        subject
    }
}

fn expired(cert: &Value, reference: Option<NaiveDateTime>) -> bool {
    days_before(&text(cert.at("not_after")), reference).is_some_and(|d| d > 0)
}

/// The findings for `sysconfig.certificates`.
pub(crate) fn items(raw: &Value) -> Vec<Item> {
    let section = raw.at("sysconfig").at(SECTION);
    let reference = reference_time(raw);
    let mut out = Vec::new();
    let mut interception: Vec<(String, String)> = Vec::new();
    let mut development: Vec<String> = Vec::new();

    for cert in list(section.at("roots")) {
        let name = shown_name(cert);
        let user = text(cert.at("scope")) == "user";
        let corporate = matches!(text(cert.at("scope")).as_str(), "policy" | "enterprise");
        let recent = days_before(&text(cert.at("added")), reference).is_some_and(|d| (0..=RECENT_DAYS).contains(&d));
        match kind_of(cert) {
            Kind::Windows => {}
            Kind::KnownBad(which) => out.push(config(
                "cert_root_known_bad",
                tr!("Known unsafe root certificate: {0}", name),
                80,
                tr!(
                    "\"{0}\" ({1}) is a root certificate whose private key was published or that adware installs; anyone can use it to impersonate any website on this computer. Remove it.",
                    name,
                    which
                ),
                cert_facts(cert),
                vec![],
            )),
            Kind::Interception(product) => interception.push((name, product)),
            Kind::Development => development.push(name),
            Kind::Imitation(brand) => out.push(config(
                "cert_root_imitation",
                tr!("Root certificate that imitates a known authority: {0}", name),
                70,
                tr!(
                    "\"{0}\" uses the name of {1} but is not in Microsoft's list of trusted root authorities; it is in {2}. Fake roots borrow known names to look genuine.",
                    name,
                    brand,
                    store_name(cert)
                ),
                cert_facts(cert),
                vec![],
            )),
            Kind::Unknown => {
                if expired(cert, reference) {
                    out.push(config(
                        "cert_root_expired",
                        tr!("Expired root certificate: {0}", name),
                        5,
                        tr!(
                            "\"{0}\" is not in Microsoft's list of trusted root authorities and has expired, so it no longer works; you can remove it.",
                            name
                        ),
                        cert_facts(cert),
                        vec![],
                    ));
                    continue;
                }
                let mut extra = Vec::new();
                if recent {
                    extra.push(Flag::new(
                        "cert_root_recent",
                        20,
                        tr!("added in the last {0} days", RECENT_DAYS),
                    ));
                }
                if GENERIC.contains(&lower(&text(cert.at("subject"))).as_str()) || text(cert.at("subject")).is_empty() {
                    extra.push(Flag::new(
                        "cert_root_generic",
                        10,
                        tr!("its name says nothing about who made it"),
                    ));
                }
                let (topic, score, summary) = if user {
                    (
                        "cert_root_user",
                        50,
                        tr!(
                            "\"{0}\" was added to your account's trusted root store and is not in Microsoft's list of trusted root authorities. Any program can add one there without administrator rights; with its key, websites and programs can be made to look genuine to you.",
                            name
                        ),
                    )
                } else if corporate {
                    (
                        "cert_root_corporate",
                        10,
                        tr!(
                            "\"{0}\" is trusted on this computer through {1}. Companies and schools add their own roots this way; on a personal computer, ask who set it.",
                            name,
                            store_name(cert)
                        ),
                    )
                } else {
                    (
                        "cert_root_unknown",
                        35,
                        tr!(
                            "\"{0}\" is in the computer's trusted root store, is not in Microsoft's list of trusted root authorities, and is not from a tool Vigil recognizes. If you do not know what installed it, remove it.",
                            name
                        ),
                    )
                };
                out.push(config(
                    topic,
                    tr!("Root certificate outside Microsoft's list: {0}", name),
                    score,
                    summary,
                    cert_facts(cert),
                    extra,
                ));
            }
        }
    }

    if !interception.is_empty() {
        let shown: Vec<String> = interception.iter().map(|(n, p)| format!("{n} ({p})")).collect();
        out.push(config(
            "cert_interception",
            tr!("Programs that can read your encrypted connections: {0}", interception.len()),
            15,
            tr!(
                "These roots let a program decrypt HTTPS traffic to inspect it: {0}. That is expected for a debugging proxy, an antivirus web shield or a company filter you installed or accepted; if you did not, remove them.",
                shown.join(", ")
            ),
            [("certificates", json!(shown))]
                .into_iter()
                .map(|(k, v)| (k.to_string(), v))
                .collect(),
            vec![],
        ));
    }
    if !development.is_empty() {
        out.push(config(
            "cert_development",
            tr!("Local development certificates: {0}", development.len()),
            5,
            tr!(
                "Tools for local websites added these trusted certificates: {0}. They are normal on a developer's computer; their keys are on this computer, so remove the ones you no longer use.",
                development.join(", ")
            ),
            [("certificates", json!(development))]
                .into_iter()
                .map(|(k, v)| (k.to_string(), v))
                .collect(),
            vec![],
        ));
    }

    // Trusted publishers: programs and drivers signed by these install without the usual prompt.
    let mut vendors = Vec::new();
    for cert in list(section.at("publishers")) {
        let name = shown_name(cert);
        let usages = list(cert.at("usages"));
        let signs_code = usages.is_empty() || usages.iter().any(|u| text(u) == CODE_SIGNING);
        if cert.at("self_signed").as_bool() == Some(true) && signs_code {
            out.push(config(
                "cert_publisher_self_signed",
                tr!("Self-made code signing certificate trusted as a publisher: {0}", name),
                30,
                tr!(
                    "\"{0}\" signed itself and is in the Trusted Publishers store: programs and drivers signed with its key install without the usual warning. Driver packages add these; if you no longer need it, remove it.",
                    name
                ),
                cert_facts(cert),
                vec![],
            ));
        } else {
            vendors.push(name);
        }
    }
    if !vendors.is_empty() {
        out.push(config(
            "cert_publishers",
            tr!("Trusted publishers: {0}", vendors.len()),
            0,
            tr!(
                "Programs and drivers signed by these publishers install without the usual prompt: {0}. Installers add them; remove the ones you do not recognize.",
                vendors.join(", ")
            ),
            [("publishers", json!(vendors))]
                .into_iter()
                .map(|(k, v)| (k.to_string(), v))
                .collect(),
            vec![],
        ));
    }
    out.sort_by_key(|i| std::cmp::Reverse(i.score));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root(subject: &str, scope: &str, extra: Value) -> Value {
        let mut base = json!({
            "scope": scope,
            "store": "Root",
            "subject": subject,
            "issuer": subject,
            "friendly_name": "",
            "sha1": "00112233445566778899AABBCCDDEEFF00112233",
            "not_before": "2025-01-01T00:00:00",
            "not_after": "2035-01-01T00:00:00",
            "self_signed": true,
            "ca": true,
            "usages": [],
            "added": "2026-01-10T12:00:00",
            "own_name": false,
        });
        if let (Some(target), Value::Object(more)) = (base.as_object_mut(), extra) {
            target.extend(more);
        }
        base
    }

    fn scan(roots: Vec<Value>, publishers: Vec<Value>) -> Value {
        json!({
            "meta": {"started": "2026-01-12T09:00:00"},
            "sysconfig": {"certificates": {"roots": roots, "publishers": publishers}},
        })
    }

    fn topics(items: &[Item]) -> Vec<String> {
        items.iter().map(|i| text(i.facts.at("topic"))).collect()
    }

    #[test]
    fn windows_roots_are_known_by_thumbprint() {
        let genuine = root(
            "Microsoft Authenticode(tm) Root Authority",
            "machine",
            json!({"sha1": "7F88CD7223F3C813818C994614A89C99FA3B5247"}),
        );
        assert_eq!(kind_of(&genuine), Kind::Windows);
        let fake = root("Microsoft Authenticode(tm) Root Authority", "machine", json!({}));
        assert_eq!(kind_of(&fake), Kind::Imitation("Microsoft".into()));
    }

    #[test]
    fn names_decide_the_kind() {
        assert_eq!(
            kind_of(&root("mitmproxy", "machine", json!({}))),
            Kind::Interception("mitmproxy".into())
        );
        assert_eq!(
            kind_of(&root(
                "Contoso",
                "machine",
                json!({"friendly_name": "DO_NOT_TRUST_FiddlerRoot"})
            )),
            Kind::Interception("Fiddler".into())
        );
        assert_eq!(
            kind_of(&root("Caddy Local Authority - 2026 ECC Root", "user", json!({}))),
            Kind::Development
        );
        assert_eq!(
            kind_of(&root("Superfish, Inc.", "machine", json!({}))),
            Kind::KnownBad("superfish".into())
        );
        assert_eq!(
            kind_of(&root("DigiCert Global Root G9", "user", json!({}))),
            Kind::Imitation("digicert".into())
        );
        assert_eq!(kind_of(&root("Fabrikam Root", "machine", json!({}))), Kind::Unknown);
        // "avg" is a word, not part of "javgen".
        assert_eq!(kind_of(&root("Javgen Root", "machine", json!({}))), Kind::Unknown);
    }

    #[test]
    fn a_certificate_that_is_not_a_ca_only_vouches_for_itself() {
        assert_eq!(
            kind_of(&root("PC-VICTIM", "machine", json!({"ca": false}))),
            Kind::Development
        );
        // The computer's own web server certificate: its name, server use only.
        assert_eq!(
            kind_of(&root(
                "PC-VICTIM",
                "machine",
                json!({"ca": null, "own_name": true, "usages": [SERVER_AUTH]})
            )),
            Kind::Development
        );
        // The same name trusted for everything is not just a web server certificate.
        assert_eq!(
            kind_of(&root("PC-VICTIM", "machine", json!({"ca": null, "own_name": true}))),
            Kind::Unknown
        );
    }

    #[test]
    fn a_recent_root_in_the_users_store_is_high() {
        let items = items(&scan(
            vec![root(
                "Fabrikam Secure Root",
                "user",
                json!({"added": "2026-01-10T12:00:00"}),
            )],
            vec![],
        ));
        assert_eq!(topics(&items), ["cert_root_user"]);
        assert_eq!(items[0].score, 70);
        let older = items_for(root(
            "Fabrikam Secure Root",
            "user",
            json!({"added": "2025-06-01T12:00:00"}),
        ));
        assert_eq!(older[0].score, 50);
    }

    fn items_for(cert: Value) -> Vec<Item> {
        items(&scan(vec![cert], vec![]))
    }

    #[test]
    fn machine_corporate_and_expired_roots() {
        let machine = items_for(root(
            "Fabrikam Root",
            "machine",
            json!({"added": "2024-01-01T00:00:00"}),
        ));
        assert_eq!(
            (topics(&machine)[0].as_str(), machine[0].score),
            ("cert_root_unknown", 35)
        );
        let policy = items_for(root(
            "Contoso Corp Root",
            "policy",
            json!({"added": "2024-01-01T00:00:00"}),
        ));
        assert_eq!(
            (topics(&policy)[0].as_str(), policy[0].score),
            ("cert_root_corporate", 10)
        );
        let old = items_for(root(
            "Fabrikam Root",
            "machine",
            json!({"not_after": "2020-01-01T00:00:00"}),
        ));
        assert_eq!((topics(&old)[0].as_str(), old[0].score), ("cert_root_expired", 5));
        let generic = items_for(root("Root CA", "machine", json!({"added": "2024-01-01T00:00:00"})));
        assert_eq!(generic[0].score, 45);
    }

    #[test]
    fn tools_are_grouped_and_windows_roots_are_quiet() {
        let items = items(&scan(
            vec![
                root("mitmproxy", "machine", json!({})),
                root("HTTP Toolkit CA", "user", json!({})),
                root("mkcert development CA", "user", json!({})),
                root(
                    "Copyright (c) 1997 Microsoft Corp.",
                    "machine",
                    json!({"sha1": "245C97DF7514E7CF2DF8BE72AE957B9E04741E85"}),
                ),
            ],
            vec![],
        ));
        assert_eq!(topics(&items), ["cert_interception", "cert_development"]);
        assert_eq!(items[0].score, 15);
        assert_eq!(list(items[0].facts.at("certificates")).len(), 2);
    }

    #[test]
    fn publishers() {
        let own = json!({"scope": "machine", "store": "TrustedPublisher", "subject": "Contoso Driver", "issuer": "Contoso Driver", "self_signed": true, "usages": []});
        let vendor = json!({"scope": "machine", "store": "TrustedPublisher", "subject": "Fabrikam Software", "issuer": "Fabrikam CA", "self_signed": false, "usages": [CODE_SIGNING]});
        let items = items(&scan(vec![], vec![own, vendor]));
        assert_eq!(topics(&items), ["cert_publisher_self_signed", "cert_publishers"]);
        assert_eq!(items[0].score, 30);
    }

    #[test]
    fn words_are_matched_whole() {
        assert!(has_words("charles proxy ca", "charles proxy"));
        assert!(!has_words("avgen", "avg"));
        assert!(has_words("avg web shield | x", "avg"));
    }

    /// Run by hand: counts by kind on this computer (no names).
    #[cfg(windows)]
    #[test]
    #[ignore = "reads this computer's certificate stores"]
    fn live_counts() {
        let started = std::time::Instant::now();
        let section = collect();
        let mut kinds = std::collections::BTreeMap::new();
        for cert in list(section.at("roots")) {
            let kind = match kind_of(cert) {
                Kind::Windows => "windows",
                Kind::KnownBad(_) => "known_bad",
                Kind::Interception(_) => "interception",
                Kind::Development => "development",
                Kind::Imitation(_) => "imitation",
                Kind::Unknown => "unknown",
            };
            *kinds.entry(format!("{}:{kind}", text(cert.at("scope")))).or_insert(0) += 1;
        }
        let raw = json!({"sysconfig": {"certificates": section.clone()}});
        let found = items(&raw);
        println!(
            "in program {} (list of {}), outside {kinds:?}, publishers {}, findings {:?} in {:?}",
            section.at("roots_in_program"),
            section.at("program_size"),
            list(section.at("publishers")).len(),
            found
                .iter()
                .map(|i| (text(i.facts.at("topic")), i.score))
                .collect::<Vec<_>>(),
            started.elapsed()
        );
    }
}
