//! `vigil export`: a saved report as CSV, SARIF, HTML or JSON, for an IT person or another tool.
//! Read-only: it reads the report and writes one new file.

use std::io::Write as _;
use std::path::{Path, PathBuf};

use vigil_i18n::{tl, tr};
use vigil_scan::model::Analysis;

use crate::cli::say;

pub use vigil_scan::export::{Format, Options};

/// The export of a report the window holds as JSON (the loaded report, or the demo one).
pub fn render_report(report: &serde_json::Value, format: Format, options: Options) -> Vec<u8> {
    vigil_scan::export::render(&Analysis::from_value(report), format, options)
}

/// The file name to suggest: `scan-20260101-1000-findings.csv` (`-report.html` for the page).
pub fn suggested_name(report: &serde_json::Value, format: Format) -> String {
    let started = report
        .get("meta")
        .and_then(|m| m.get("started"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    let stamp: String = started
        .chars()
        .filter(|c| c.is_ascii_digit() || *c == 'T')
        .take(13)
        .collect::<String>()
        .replace('T', "-");
    let stamp = if stamp.is_empty() {
        "scan".to_string()
    } else {
        format!("scan-{stamp}")
    };
    match format {
        Format::Html | Format::Json => format!("{stamp}-report.{}", format.extension()),
        Format::Csv | Format::Sarif => format!("{stamp}-findings.{}", format.extension()),
    }
}

const HELP: &str = tl!("\
A saved scan report as a file for an IT person or another tool.

Usage: vigil export --format csv|sarif|html|json --out FILE [options]

  --format NAME   csv (a spreadsheet: one row per finding), sarif (SARIF 2.1.0, for security
                  tools), html (the report page) or json (the report data)
  --out FILE      the file to write; an existing file is kept unless --force
  --report FILE   the report to export (a *-report.json); default: the newest saved one
  --anonymize     replace the user and computer names, the other accounts' names and the
                  profile folders' names, as the AI review does
  --all           include the Microsoft components verified automatically
  --force         replace FILE if it exists
  --lang CODE     language: auto, en, es, fr, pt or zh

Secrets found by the scan are never written: only where they are and what kind they are.");

/// What `vigil export` was asked for.
#[derive(Debug, Default, PartialEq)]
pub(crate) struct Request {
    pub format: Option<Format>,
    pub out: Option<PathBuf>,
    pub report: Option<PathBuf>,
    pub options: Options,
    pub force: bool,
    pub help: bool,
}

pub(crate) fn parse(args: &[String]) -> Result<Request, String> {
    let mut request = Request::default();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        let mut value = |name: &str| iter.next().cloned().ok_or(tr!("{0} needs a value", name));
        match arg.as_str() {
            "-h" | "--help" => request.help = true,
            "--format" => {
                let name = value("--format")?;
                request.format = Some(Format::parse(&name).ok_or(tr!("--format must be csv, sarif, html or json"))?);
            }
            "--out" => request.out = Some(PathBuf::from(value("--out")?)),
            "--report" => request.report = Some(PathBuf::from(value("--report")?)),
            "--anonymize" => request.options.anonymize = true,
            "--all" => request.options.include_trusted = true,
            "--force" => request.force = true,
            "--lang" => {
                value("--lang")?;
            }
            other => return Err(tr!("unknown option {0} (see vigil export --help)", other)),
        }
    }
    Ok(request)
}

/// Writes a file the user chose (an export from the window). While Vigil is elevated nothing on
/// the way is followed: no link at the name or above it (`vigil_actions::write_user_file`).
pub fn write_user_file(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    vigil_actions::write_user_file(path, bytes)
}

/// Writes `bytes` to a new file at `path`; an existing file is an error unless `force`.
pub(crate) fn write_new(path: &Path, bytes: &[u8], force: bool) -> Result<(), String> {
    if vigil_sys::elevation::is_elevated() {
        if !force && std::fs::symlink_metadata(path).is_ok() {
            return Err(tr!("{0} already exists; add --force to replace it", path.display()));
        }
        return write_user_file(path, bytes).map_err(|e| tr!("Could not write {0}: {1}", path.display(), e));
    }
    let mut open = std::fs::OpenOptions::new();
    open.write(true);
    if force {
        open.create(true).truncate(true);
    } else {
        open.create_new(true);
    }
    let mut file = open.open(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::AlreadyExists {
            tr!("{0} already exists; add --force to replace it", path.display())
        } else {
            tr!("Could not write {0}: {1}", path.display(), e)
        }
    })?;
    file.write_all(bytes)
        .and_then(|()| file.flush())
        .map_err(|e| tr!("Could not write {0}: {1}", path.display(), e))
}

/// Writes the export of `analysis` and says where it went.
pub(crate) fn write_export(
    analysis: &Analysis,
    format: Format,
    options: Options,
    out: &Path,
    force: bool,
) -> Result<(), String> {
    let bytes = vigil_scan::export::render(analysis, format, options);
    write_new(out, &bytes, force)?;
    let count = match format {
        Format::Csv | Format::Sarif => vigil_scan::export::count(analysis, options),
        Format::Html | Format::Json => analysis.items.len(),
    };
    say(&tr!("{0} findings exported to {1}", count, out.display()));
    if options.anonymize {
        say(&tr!(
            "Names were replaced: the user, the computer, the other accounts and the profile folders."
        ));
    }
    Ok(())
}

/// Runs `vigil export`.
pub fn cli(args: &[String]) -> Result<(), String> {
    let request = parse(args)?;
    if request.help {
        say(&tr!(HELP));
        return Ok(());
    }
    let format = request
        .format
        .ok_or(tr!("--format is needed (see vigil export --help)"))?;
    let out = request.out.ok_or(tr!("--out is needed (see vigil export --help)"))?;
    let analysis = match &request.report {
        Some(path) => vigil_scan::pipeline::load_report(path)
            .map_err(|e| tr!("Could not open the report {0}: {1}", path.display(), e))?,
        None => {
            let (analysis, path) = crate::mcp::registry::newest_report()
                .ok_or(tr!("No saved report was found; give one with --report"))?;
            say(&tr!("Report: {0}", path.display()));
            analysis
        }
    };
    write_export(&analysis, format, request.options, &out, request.force)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn options_parse() {
        let request = parse(&args(&[
            "--format",
            "SARIF",
            "--out",
            r"C:\x\a.sarif",
            "--anonymize",
            "--all",
            "--force",
            "--lang",
            "es",
        ]))
        .unwrap_or_default();
        assert_eq!(request.format, Some(Format::Sarif));
        assert_eq!(request.out.as_deref(), Some(Path::new(r"C:\x\a.sarif")));
        assert!(request.options.anonymize && request.options.include_trusted && request.force);
        assert!(parse(&args(&["--format", "xml"])).is_err());
        assert!(parse(&args(&["--format"])).is_err());
        assert!(parse(&args(&["--rm"])).is_err());
        assert!(parse(&args(&["-h"])).is_ok_and(|r| r.help));
    }

    #[test]
    fn names_follow_the_scan_time() {
        let report = serde_json::json!({"meta": {"started": "2026-01-01T10:05:30"}});
        assert_eq!(suggested_name(&report, Format::Csv), "scan-20260101-1005-findings.csv");
        assert_eq!(
            suggested_name(&report, Format::Sarif),
            "scan-20260101-1005-findings.sarif"
        );
        assert_eq!(suggested_name(&report, Format::Html), "scan-20260101-1005-report.html");
        assert_eq!(suggested_name(&serde_json::json!({}), Format::Csv), "scan-findings.csv");
    }

    #[test]
    fn an_existing_file_is_kept_unless_forced() {
        let dir = std::env::temp_dir().join(format!("vigil-export-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("findings.csv");
        assert!(write_new(&path, b"first", false).is_ok());
        let refused = write_new(&path, b"second", false);
        assert!(refused.is_err_and(|e| e.contains("--force")));
        assert_eq!(std::fs::read(&path).unwrap_or_default(), b"first");
        assert!(write_new(&path, b"third", true).is_ok());
        assert_eq!(std::fs::read(&path).unwrap_or_default(), b"third");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_saved_report_is_exported() {
        let dir = std::env::temp_dir().join(format!("vigil-export-cli-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::create_dir_all(&dir);
        let mut item = vigil_scan::model::Item::new("exe", "winupd.exe", "");
        item.id = "f1".into();
        item.verdict = "remove".into();
        item.path = Some(r"C:\Users\jdoe\AppData\Roaming\winupd.exe".into());
        let analysis = Analysis {
            items: vec![item],
            ..Analysis::default()
        };
        let report = dir.join("scan-20260101-100000-report.json");
        let _ = std::fs::write(&report, vigil_scan::report::render_json(&analysis));
        let out = dir.join("out.sarif");
        let result = cli(&args(&[
            "--report",
            &report.display().to_string(),
            "--format",
            "sarif",
            "--out",
            &out.display().to_string(),
        ]));
        assert!(result.is_ok(), "{result:?}");
        let text = std::fs::read_to_string(&out).unwrap_or_default();
        assert!(text.contains("\"version\": \"2.1.0\"") && text.contains("winupd.exe"));
        // Again without --force: refused, the file is kept.
        let again = cli(&args(&[
            "--report",
            &report.display().to_string(),
            "--format",
            "csv",
            "--out",
            &out.display().to_string(),
        ]));
        assert!(again.is_err());
        assert!(std::fs::read_to_string(&out).unwrap_or_default().contains("2.1.0"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
