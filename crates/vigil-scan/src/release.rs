//! The opt-in check for a newer Vigil: one GET to GitHub's "latest release" endpoint of Vigil's own
//! repository, through the same HTTP agent the AI providers use (TLS, proxy, no redirects).
//!
//! Nothing about the computer is sent: the request carries a fixed User-Agent with Vigil's version,
//! no identifiers and no cookies. The answer is untrusted: it is read with a size cap, and only a
//! plain version tag and a release page on `github.com/andresayac/vigil` are kept. Nothing is
//! downloaded or installed.

use std::time::Duration;

use serde_json::Value;
use vigil_i18n::tr;

use crate::ai::net::{agent, check_endpoint};
use crate::lenient::Get;

/// GitHub's "latest release" endpoint of Vigil's repository (pre-releases and drafts never appear
/// there).
pub const LATEST_URL: &str = "https://api.github.com/repos/andresayac/vigil/releases/latest";

/// Every release page of Vigil starts with this.
pub const RELEASES_PREFIX: &str = "https://github.com/andresayac/vigil/releases/";

/// The answer is small (a release's metadata); anything bigger is refused.
const MAX_ANSWER: u64 = 256 * 1024;
const TIMEOUT: Duration = Duration::from_secs(15);

/// A newer release, as validated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Release {
    /// "2.4.0" (without the leading "v").
    pub version: String,
    /// The release page (always under [`RELEASES_PREFIX`]).
    pub url: String,
    /// The names of its downloads that look like Vigil's own (setup, portable, checksums).
    pub assets: Vec<String>,
}

/// `major.minor.patch` of a plain version ("v2.4.0" or "2.4.0"). Pre-releases ("2.4.0-beta.1")
/// and build metadata are not offered, so they give `None`.
pub fn parse_version(text: &str) -> Option<(u64, u64, u64)> {
    let text = text.trim();
    let text = text
        .strip_prefix('v')
        .or_else(|| text.strip_prefix('V'))
        .unwrap_or(text);
    if text.is_empty() || text.len() > 30 {
        return None;
    }
    let mut parts = text.split('.');
    let mut next = || -> Option<u64> {
        let part = parts.next()?;
        if part.is_empty() || part.len() > 9 || !part.chars().all(|c| c.is_ascii_digit()) {
            return None;
        }
        // No leading zeros ("01"), as semantic versioning says.
        if part.len() > 1 && part.starts_with('0') {
            return None;
        }
        part.parse().ok()
    };
    let version = (next()?, next()?, next()?);
    if parts.next().is_some() {
        return None;
    }
    Some(version)
}

/// True when `latest` is a plain version greater than `current`.
pub fn is_newer(latest: &str, current: &str) -> bool {
    match (parse_version(latest), parse_version(current)) {
        (Some(latest), Some(current)) => latest > current,
        _ => false,
    }
}

/// A release page of Vigil's repository: `https://github.com/andresayac/vigil/releases/...` with
/// only plain characters after it (no query, fragment, credentials or spaces).
pub fn valid_release_url(url: &str) -> bool {
    let Some(rest) = url.strip_prefix(RELEASES_PREFIX) else {
        return false;
    };
    !rest.is_empty()
        && rest.len() <= 80
        && rest.chars().all(|c| c.is_ascii_alphanumeric() || "-_./".contains(c))
        && !rest.contains("..")
}

/// An asset name Vigil publishes: `Vigil_x.y.z_x64-setup.exe`, `Vigil-x.y.z-portable.exe` or
/// `SHA256SUMS.txt`. Anything else in the answer is ignored.
fn own_asset(name: &str) -> bool {
    if name == "SHA256SUMS.txt" {
        return true;
    }
    let plain = |s: &str| !s.is_empty() && s.chars().all(|c| c.is_ascii_digit() || c == '.');
    if let Some(version) = name
        .strip_prefix("Vigil_")
        .and_then(|r| r.strip_suffix("_x64-setup.exe"))
    {
        return plain(version);
    }
    if let Some(version) = name
        .strip_prefix("Vigil-")
        .and_then(|r| r.strip_suffix("-portable.exe"))
    {
        return plain(version);
    }
    false
}

/// Checks GitHub's answer and keeps what Vigil uses. Refused: a draft or pre-release, a tag that
/// is not a plain version, a page outside Vigil's repository, a missing field.
pub fn parse(body: &str) -> Result<Release, String> {
    let value: Value = serde_json::from_str(body).map_err(|_| tr!("The answer is not valid JSON."))?;
    if !value.is_object() {
        return Err(tr!("The answer is not a release."));
    }
    if value.at("draft").as_bool() == Some(true) || value.at("prerelease").as_bool() == Some(true) {
        return Err(tr!("The latest release is a draft or a pre-release."));
    }
    let tag = value
        .at("tag_name")
        .as_str()
        .ok_or_else(|| tr!("The answer has no version."))?;
    let (major, minor, patch) =
        parse_version(tag).ok_or_else(|| tr!("The release's version is not a plain version number."))?;
    let url = value
        .at("html_url")
        .as_str()
        .ok_or_else(|| tr!("The answer has no release page."))?;
    if !valid_release_url(url) {
        return Err(tr!("The release page is not on Vigil's repository."));
    }
    let assets = value
        .at("assets")
        .as_array()
        .map(|list| {
            list.iter()
                .filter_map(|a| a.at("name").as_str())
                .filter(|name| own_asset(name))
                .take(10)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    Ok(Release {
        version: format!("{major}.{minor}.{patch}"),
        url: url.to_string(),
        assets,
    })
}

/// GETs `url` (https, or http on this computer for tests) and returns the body. The request
/// carries only a fixed User-Agent with `version` and the GitHub API's Accept header.
pub fn fetch(url: &str, version: &str) -> Result<String, String> {
    let url = check_endpoint(url)?;
    let agent = agent(TIMEOUT, TIMEOUT);
    let user_agent = format!(
        "Vigil/{}",
        version.chars().filter(|c| c.is_ascii_graphic()).collect::<String>()
    );
    let mut response = agent
        .get(&url)
        .header("User-Agent", user_agent)
        .header("Accept", "application/vnd.github+json")
        .call()
        .map_err(|e| {
            tr!(
                "Could not reach {0}: {1}",
                host(&url),
                crate::privacy::clip(&e.to_string(), 160)
            )
        })?;
    let status = response.status().as_u16();
    if status != 200 {
        return Err(match status {
            403 | 429 => tr!("GitHub refused the request for now (rate limit); try again later."),
            404 => tr!("No published release was found."),
            301..=308 => tr!("The server answered with a redirect, which is not followed."),
            _ => tr!("The server answered with status {0}.", status),
        });
    }
    response
        .body_mut()
        .with_config()
        .limit(MAX_ANSWER)
        .read_to_string()
        .map_err(|_| tr!("The answer was too big or could not be read."))
}

fn host(url: &str) -> &str {
    let rest = url.split("://").nth(1).unwrap_or(url);
    rest.split(['/', '?', '#']).next().unwrap_or(rest)
}

/// Asks `url` for the latest release: `Some` when it is newer than `current`, `None` when this is
/// the latest.
pub fn latest(url: &str, current: &str) -> Result<Option<Release>, String> {
    let release = parse(&fetch(url, current)?)?;
    Ok(is_newer(&release.version, current).then_some(release))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;

    fn answer(tag: &str, url: &str) -> String {
        serde_json::json!({
            "tag_name": tag,
            "html_url": url,
            "draft": false,
            "prerelease": false,
            "assets": [
                {"name": "Vigil_9.1.0_x64-setup.exe"},
                {"name": "Vigil-9.1.0-portable.exe"},
                {"name": "SHA256SUMS.txt"},
                {"name": "evil<script>.exe"}
            ]
        })
        .to_string()
    }

    #[test]
    fn versions_compare_as_numbers() {
        assert_eq!(parse_version("v2.10.0"), Some((2, 10, 0)));
        assert_eq!(parse_version("2.3.1"), Some((2, 3, 1)));
        assert!(is_newer("v2.10.0", "2.9.9"));
        assert!(is_newer("3.0.0", "2.99.99"));
        assert!(!is_newer("v2.3.0", "2.3.0"));
        assert!(!is_newer("2.2.9", "2.3.0"));
        for bad in [
            "2.4.0-beta.1",
            "2.4",
            "2.4.0.1",
            "v",
            "",
            "02.4.0",
            "2.4.x",
            "2.4.0+build",
            " 1 .2.3",
        ] {
            assert_eq!(parse_version(bad), None, "{bad}");
        }
        // A pre-release is never offered, and an odd current version never claims "newer".
        assert!(!is_newer("2.5.0-rc.1", "2.4.0"));
        assert!(!is_newer("2.5.0", "dev"));
    }

    #[test]
    fn only_vigils_release_pages_are_kept() {
        assert!(valid_release_url(
            "https://github.com/andresayac/vigil/releases/tag/v2.4.0"
        ));
        for bad in [
            "https://github.com/someone/vigil/releases/tag/v2.4.0",
            "https://github.com/andresayac/vigil/releases/",
            "https://github.com/andresayac/vigil/releases/tag/v2.4.0?x=1",
            "https://github.com/andresayac/vigil/releases/tag/v2.4.0#x",
            "https://github.com/andresayac/vigil/releases/../../evil",
            "http://github.com/andresayac/vigil/releases/tag/v2.4.0",
            "https://github.com.example.com/andresayac/vigil/releases/tag/v2.4.0",
            "https://github.com/andresayac/vigil/releases/tag/v2 .4.0",
        ] {
            assert!(!valid_release_url(bad), "{bad}");
        }
    }

    #[test]
    fn answers_are_checked() {
        let good = parse(&answer(
            "v9.1.0",
            "https://github.com/andresayac/vigil/releases/tag/v9.1.0",
        ))
        .expect("valid");
        assert_eq!(good.version, "9.1.0");
        assert_eq!(good.assets.len(), 3, "only Vigil's own downloads: {:?}", good.assets);
        // Wrong host or repository.
        assert!(parse(&answer("v9.1.0", "https://evil.example.com/vigil/releases/tag/v9.1.0")).is_err());
        // Markup in the tag is not a version.
        assert!(
            parse(&answer(
                "<b>v9</b>",
                "https://github.com/andresayac/vigil/releases/tag/x"
            ))
            .is_err()
        );
        // Missing fields, not an object, not JSON.
        assert!(parse(r#"{"html_url": "https://github.com/andresayac/vigil/releases/tag/v1.0.0"}"#).is_err());
        assert!(parse(r#"{"tag_name": "v1.0.0"}"#).is_err());
        assert!(parse("[]").is_err());
        assert!(parse("<html>").is_err());
        // Drafts and pre-releases are not offered.
        let pre = answer("v9.1.0", "https://github.com/andresayac/vigil/releases/tag/v9.1.0")
            .replace("\"prerelease\":false", "\"prerelease\":true");
        assert!(parse(&pre).is_err());
    }

    /// A one-request HTTP server on loopback that answers `status` and `body`; returns its URL
    /// and a handle that yields the request it received.
    fn serve(status: &'static str, body: String) -> (String, std::thread::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().map(|a| a.port()).unwrap_or(0);
        let handle = std::thread::spawn(move || {
            let Ok((mut stream, _)) = listener.accept() else {
                return String::new();
            };
            let mut reader = BufReader::new(stream.try_clone().expect("clone"));
            let mut request = String::new();
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                    break;
                }
                request.push_str(&line);
            }
            let reply = format!(
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(reply.as_bytes());
            request
        });
        (
            format!("http://127.0.0.1:{port}/repos/andresayac/vigil/releases/latest"),
            handle,
        )
    }

    #[test]
    fn the_client_sends_nothing_but_its_version() {
        let (url, server) = serve(
            "200 OK",
            answer("v9.1.0", "https://github.com/andresayac/vigil/releases/tag/v9.1.0"),
        );
        let found = latest(&url, "2.3.0").expect("answer").expect("newer");
        assert_eq!(found.version, "9.1.0");
        let request = server.join().unwrap_or_default().to_ascii_lowercase();
        assert!(
            request.starts_with("get /repos/andresayac/vigil/releases/latest"),
            "{request}"
        );
        assert!(request.contains("user-agent: vigil/2.3.0"), "{request}");
        assert!(!request.contains("cookie"), "{request}");
        for header in request.lines().skip(1) {
            let name = header.split(':').next().unwrap_or("");
            assert!(
                matches!(
                    name,
                    "user-agent" | "accept" | "host" | "accept-encoding" | "connection"
                ),
                "unexpected header {header}"
            );
        }
        // The same version: nothing newer.
        let (url, server) = serve(
            "200 OK",
            answer("v2.3.0", "https://github.com/andresayac/vigil/releases/tag/v2.3.0"),
        );
        assert_eq!(latest(&url, "2.3.0"), Ok(None));
        let _ = server.join();
    }

    #[test]
    fn bad_answers_and_addresses_are_refused() {
        let (url, server) = serve("200 OK", "x".repeat(MAX_ANSWER as usize + 10));
        assert!(latest(&url, "2.3.0").is_err());
        let _ = server.join();
        let (url, server) = serve("429 Too Many Requests", "{}".into());
        assert!(latest(&url, "2.3.0").expect_err("rate limit").contains("rate limit"));
        let _ = server.join();
        let (url, server) = serve("302 Found", "{}".into());
        assert!(latest(&url, "2.3.0").expect_err("redirect").contains("redirect"));
        let _ = server.join();
        // Plain http to another computer is never used.
        assert!(fetch("http://203.0.113.5/releases/latest", "2.3.0").is_err());
    }
}
