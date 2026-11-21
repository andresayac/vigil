//! A calendar date, just enough for "how old is this driver" questions.

use serde::{Deserialize, Serialize};
use windows::Win32::System::SystemInformation::GetLocalTime;

/// A day in the proleptic Gregorian calendar.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Date {
    pub year: i32,
    pub month: u32,
    pub day: u32,
}

impl Date {
    pub fn new(year: i32, month: u32, day: u32) -> Option<Self> {
        if !(1..=12).contains(&month) || day == 0 || day > days_in_month(year, month) {
            return None;
        }
        Some(Self { year, month, day })
    }

    /// Today on this computer's clock (local time).
    pub fn today() -> Self {
        // SAFETY: GetLocalTime only fills and returns a SYSTEMTIME.
        let now = unsafe { GetLocalTime() };
        Self {
            year: now.wYear as i32,
            month: now.wMonth as u32,
            day: now.wDay as u32,
        }
    }

    /// The date at the start of an ISO text: "2024-03-09", "2024-03-09T10:00:00" or "20240309"
    /// (the ISO 8601 date shapes). None if it is not a date.
    pub fn parse_iso(text: &str) -> Option<Self> {
        let head: String = text.chars().take(10).collect();
        let digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
        if head.len() == 10 && head.as_bytes()[4] == b'-' && head.as_bytes()[7] == b'-' {
            let (y, m, d) = (&head[0..4], &head[5..7], &head[8..10]);
            if digits(y) && digits(m) && digits(d) {
                return Self::new(y.parse().ok()?, m.parse().ok()?, d.parse().ok()?);
            }
            return None;
        }
        if head.len() == 8 && digits(&head) {
            return Self::new(
                head[0..4].parse().ok()?,
                head[4..6].parse().ok()?,
                head[6..8].parse().ok()?,
            );
        }
        None
    }

    /// Days since 1970-01-01 (negative before it).
    pub fn ordinal(&self) -> i64 {
        // Howard Hinnant's days_from_civil.
        let y = i64::from(self.year) - i64::from(self.month <= 2);
        let era = if y >= 0 { y } else { y - 399 } / 400;
        let yoe = y - era * 400;
        let m = i64::from(self.month);
        let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + i64::from(self.day) - 1;
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
        era * 146_097 + doe - 719_468
    }

    /// Whole days from `earlier` to `self`.
    pub fn days_since(&self, earlier: &Date) -> i64 {
        self.ordinal() - earlier.ordinal()
    }
}

fn days_in_month(year: i32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if (year % 4 == 0 && year % 100 != 0) || year % 400 == 0 => 29,
        2 => 28,
        _ => 0,
    }
}

impl std::fmt::Display for Date {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:04}-{:02}-{:02}", self.year, self.month, self.day)
    }
}

#[cfg(test)]
mod tests {
    use super::Date;

    #[test]
    fn parses_and_counts_days() {
        let a = Date::parse_iso("2024-01-01T10:00:00").unwrap();
        let b = Date::parse_iso("2026-06-01").unwrap();
        assert_eq!(b.days_since(&a), 882);
        assert_eq!(Date::parse_iso("20240229"), Date::new(2024, 2, 29));
        assert_eq!(Date::parse_iso("2023-02-29"), None);
        assert_eq!(Date::parse_iso("not a date"), None);
        assert_eq!(Date::new(1970, 1, 1).unwrap().ordinal(), 0);
        assert_eq!(a.to_string(), "2024-01-01");
    }
}
