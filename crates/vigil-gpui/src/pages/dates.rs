//! Names of weekdays and months and the "a, b and c" lists in Vigil's five languages, for
//! schedules (Scheduled tasks) and day labels.

const DAY_KEYS: [&str; 7] = [
    "monday",
    "tuesday",
    "wednesday",
    "thursday",
    "friday",
    "saturday",
    "sunday",
];
const MONTH_KEYS: [&str; 12] = [
    "january",
    "february",
    "march",
    "april",
    "may",
    "june",
    "july",
    "august",
    "september",
    "october",
    "november",
    "december",
];

fn days(lang: &str, short: bool) -> [&'static str; 7] {
    match (lang, short) {
        ("es", false) => ["lunes", "martes", "miércoles", "jueves", "viernes", "sábado", "domingo"],
        ("es", true) => ["lun", "mar", "mié", "jue", "vie", "sáb", "dom"],
        ("fr", false) => ["lundi", "mardi", "mercredi", "jeudi", "vendredi", "samedi", "dimanche"],
        ("fr", true) => ["lun.", "mar.", "mer.", "jeu.", "ven.", "sam.", "dim."],
        ("pt", false) => [
            "segunda-feira",
            "terça-feira",
            "quarta-feira",
            "quinta-feira",
            "sexta-feira",
            "sábado",
            "domingo",
        ],
        ("pt", true) => ["seg.", "ter.", "qua.", "qui.", "sex.", "sáb.", "dom."],
        ("zh", false) => ["星期一", "星期二", "星期三", "星期四", "星期五", "星期六", "星期日"],
        ("zh", true) => ["周一", "周二", "周三", "周四", "周五", "周六", "周日"],
        (_, false) => [
            "Monday",
            "Tuesday",
            "Wednesday",
            "Thursday",
            "Friday",
            "Saturday",
            "Sunday",
        ],
        (_, true) => ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"],
    }
}

fn months(lang: &str) -> [&'static str; 12] {
    match lang {
        "es" => [
            "enero",
            "febrero",
            "marzo",
            "abril",
            "mayo",
            "junio",
            "julio",
            "agosto",
            "septiembre",
            "octubre",
            "noviembre",
            "diciembre",
        ],
        "fr" => [
            "janvier",
            "février",
            "mars",
            "avril",
            "mai",
            "juin",
            "juillet",
            "août",
            "septembre",
            "octobre",
            "novembre",
            "décembre",
        ],
        "pt" => [
            "janeiro",
            "fevereiro",
            "março",
            "abril",
            "maio",
            "junho",
            "julho",
            "agosto",
            "setembro",
            "outubro",
            "novembro",
            "dezembro",
        ],
        "zh" => [
            "一月",
            "二月",
            "三月",
            "四月",
            "五月",
            "六月",
            "七月",
            "八月",
            "九月",
            "十月",
            "十一月",
            "十二月",
        ],
        _ => [
            "January",
            "February",
            "March",
            "April",
            "May",
            "June",
            "July",
            "August",
            "September",
            "October",
            "November",
            "December",
        ],
    }
}

/// A weekday by its English key ("monday"); unknown keys stay as they are.
pub fn weekday(key: &str, short: bool) -> String {
    let lang = crate::i18n::language();
    DAY_KEYS
        .iter()
        .position(|d| d.eq_ignore_ascii_case(key))
        .map(|i| days(lang, short)[i].to_string())
        .unwrap_or_else(|| key.to_string())
}

/// A month by its English key ("january") or number ("1").
pub fn month(key: &str) -> String {
    let lang = crate::i18n::language();
    let index = MONTH_KEYS.iter().position(|m| m.eq_ignore_ascii_case(key)).or_else(|| {
        key.parse::<usize>()
            .ok()
            .filter(|n| (1..=12).contains(n))
            .map(|n| n - 1)
    });
    index
        .map(|i| months(lang)[i].to_string())
        .unwrap_or_else(|| key.to_string())
}

/// "a, b and c" in the language.
pub fn list(items: &[String]) -> String {
    let lang = crate::i18n::language();
    let (sep, and) = match lang {
        "es" => (", ", " y "),
        "fr" => (", ", " et "),
        "pt" => (", ", " e "),
        "zh" => ("、", "和"),
        _ => (", ", if items.len() > 2 { ", and " } else { " and " }),
    };
    match items {
        [] => String::new(),
        [one] => one.clone(),
        [head @ .., last] => format!("{}{and}{last}", head.join(sep)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_and_lists() {
        vigil_i18n::with_language("en", || {
            assert_eq!(weekday("monday", false), "Monday");
            assert_eq!(month("3"), "March");
            assert_eq!(list(&["a".into(), "b".into(), "c".into()]), "a, b, and c");
        });
        vigil_i18n::with_language("es", || {
            assert_eq!(weekday("sunday", true), "dom");
            assert_eq!(list(&["a".into(), "b".into()]), "a y b");
        });
    }
}
