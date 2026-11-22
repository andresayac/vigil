//! Every recorded insight case (tests/data/insights_cases.json)
//! must come out identical: same texts, same fixes, same order.

use serde_json::Value;
use vigil_maint::Date;
use vigil_maint::hardware::Hardware;
use vigil_maint::insights::{self, Insight, Level};
use vigil_maint::storage::Volume;
use vigil_maint::tuning::TuningState;

const CASES: &str = include_str!("data/insights_cases.json");

#[test]
fn insights_match_the_reference() {
    let doc: Value = serde_json::from_str(CASES).expect("fixture is JSON");
    let cases = doc["cases"].as_array().expect("cases");
    assert!(cases.len() >= 30);
    let mut failures = Vec::new();
    for case in cases {
        let name = case["name"].as_str().unwrap_or("?");
        let hw: Hardware = serde_json::from_value(case["hw"].clone()).expect("hardware");
        let tuning: Option<TuningState> = serde_json::from_value(case["tuning"].clone()).expect("tuning");
        let volumes: Vec<Volume> = serde_json::from_value(case["volumes"].clone()).expect("volumes");
        let uptime = case["uptime_seconds"].as_f64().unwrap_or(0.0);
        let today = Date::parse_iso(case["today"].as_str().unwrap_or("")).expect("date");
        let found = insights::collect(&hw, tuning.as_ref(), &volumes, uptime, Some(today));
        let got = serde_json::to_value(&found).expect("serializes");
        if got != case["expected"] {
            failures.push(format!(
                "{name}:\n  expected: {}\n  got:      {}",
                serde_json::to_string(&case["expected"]).unwrap_or_default(),
                serde_json::to_string(&got).unwrap_or_default()
            ));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn insights_follow_the_language() {
    let run = |lang: &str| {
        let today = Date::parse_iso("2026-03-02").expect("date");
        vigil_i18n::with_language(lang, || insights::system(&Hardware::default(), 20.5 * 86_400.0, today))
    };
    let (english, spanish, chinese) = (run("en"), run("es"), run("zh"));
    let uptime = |found: &[Insight], text: &str| found.iter().find(|i| i.text == text).cloned();
    let en = uptime(&english, "Windows has been running for 20 days.").expect("English uptime insight");
    let es = uptime(&spanish, "Windows lleva 20 días en ejecución.").expect("Spanish uptime insight");
    let zh = uptime(&chinese, "Windows 已连续运行 20 天。").expect("Chinese uptime insight");
    assert!(es.fix.starts_with("Reinicia de vez en cuando"), "{}", es.fix);
    assert!(zh.fix.starts_with("请不时重启"), "{}", zh.fix);
    // Levels and areas are data for the UI and stay the same in every language.
    assert_eq!((en.level, en.area.as_str()), (es.level, es.area.as_str()));
    assert_eq!((en.level, en.area.as_str()), (zh.level, zh.area.as_str()));
    assert_eq!(english.len(), spanish.len());
}

#[test]
fn levels_serialize_lower_case_and_sort_problems_first() {
    let insight = Insight {
        level: Level::Warn,
        area: "Storage".into(),
        text: "t".into(),
        fix: String::new(),
    };
    assert_eq!(serde_json::to_value(&insight).unwrap()["level"], "warn");
    let mut levels = [Level::Ok, Level::Info, Level::Bad, Level::Warn];
    levels.sort();
    assert_eq!(levels, [Level::Bad, Level::Warn, Level::Info, Level::Ok]);
}
