//! Keeps the README in step with the window: every page has a row in its pages table, in the order of the
//! navigation, and every screenshot the README shows exists.

use std::path::{Path, PathBuf};

use crate::shell::PAGES;

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..")
}

fn readme() -> String {
    std::fs::read_to_string(root().join("README.md")).unwrap_or_default()
}

/// The English title of a page, from the window's source catalog.
fn title(key: &str) -> Option<String> {
    let text = std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("locales").join("en.json")).ok()?;
    let catalog: serde_json::Value = serde_json::from_str(&text).ok()?;
    catalog.get(format!("page.{key}"))?.as_str().map(str::to_string)
}

#[test]
fn every_page_has_a_readme_row_in_navigation_order() {
    let readme = readme();
    assert!(!readme.is_empty(), "README.md not found");
    let table = readme
        .find("| Page | What it shows |")
        .expect("the README's pages table");
    let mut last = table;
    for (key, _) in PAGES.iter() {
        let title = title(key).unwrap_or_else(|| panic!("no title for page {key}"));
        let row = format!("| **{title}");
        let at = readme[table..]
            .find(&row)
            .map(|i| i + table)
            .unwrap_or_else(|| panic!("README pages table has no row for {title} ({key})"));
        assert!(at > last, "README row {title} is out of the navigation order");
        last = at;
    }
}

#[test]
fn every_screenshot_the_readme_shows_exists() {
    let readme = readme();
    let mut found = 0;
    for (start, _) in readme.match_indices("docs/screenshots/") {
        let rest = &readme[start..];
        let end = rest
            .find(|c: char| c == ')' || c == '"' || c.is_whitespace())
            .unwrap_or(rest.len());
        let path = &rest[..end];
        assert!(root().join(path).is_file(), "README shows {path}, which does not exist");
        found += 1;
    }
    assert!(found > 0, "the README shows no screenshot");
}
