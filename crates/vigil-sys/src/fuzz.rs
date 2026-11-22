//! Deterministic fuzzing for tests: a seeded generator, random and mutated inputs, and a check
//! that a parser neither panics nor stalls on one input. Seeds are fixed, so a failure repeats,
//! and the failing input is printed (hex, cut to 256 bytes) in the message.

#![allow(dead_code)]

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::time::{Duration, Instant};

/// Per-input time limit. Generous for debug builds on a busy CI runner: it catches hangs and
/// quadratic blow-ups, not ordinary slowness.
pub(crate) const LIMIT: Duration = Duration::from_secs(2);

/// xorshift64*: small and fast, good enough to drive parsers.
pub(crate) struct Rng(u64);

impl Rng {
    pub(crate) fn new(seed: u64) -> Self {
        Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1)
    }

    pub(crate) fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    pub(crate) fn below(&mut self, n: usize) -> usize {
        if n == 0 { 0 } else { (self.next() % n as u64) as usize }
    }

    pub(crate) fn chance(&mut self, percent: u64) -> bool {
        self.next() % 100 < percent
    }

    /// Random bytes; lengths are mostly small but reach `max`.
    pub(crate) fn bytes(&mut self, max: usize) -> Vec<u8> {
        let len = if self.chance(80) {
            self.below(max.min(64) + 1)
        } else {
            self.below(max + 1)
        };
        (0..len).map(|_| self.byte()).collect()
    }

    /// A byte, often one that parsers treat specially (zero, all ones, DER tags and lengths).
    pub(crate) fn byte(&mut self) -> u8 {
        const SPECIAL: [u8; 10] = [0, 0xFF, 0x7F, 0x80, 0x30, 0x02, 0x04, 0x06, 0xA0, 0x81];
        if self.chance(30) {
            SPECIAL[self.below(SPECIAL.len())]
        } else {
            self.next() as u8
        }
    }

    /// A character: often one that matters to text parsers (controls, markup, quotes, bidi and
    /// format characters), otherwise ASCII or any scalar value.
    pub(crate) fn any_char(&mut self) -> char {
        const SPECIAL: [char; 18] = [
            '\0', '\r', '\n', '\t', '<', '>', '&', '"', '\'', '\\', '/', '=', ';', ':', '\u{202E}', '\u{FEFF}',
            '\u{FFFF}', 'é',
        ];
        match self.below(4) {
            0 => SPECIAL[self.below(SPECIAL.len())],
            1 => char::from_u32(self.below(0x80) as u32).unwrap_or('?'),
            2 => char::from_u32(self.below(0x11_0000) as u32).unwrap_or('\u{FFFD}'),
            _ => (b'a' + self.below(26) as u8) as char,
        }
    }

    /// A string assembled from `tokens` and random characters.
    pub(crate) fn text(&mut self, max_parts: usize, tokens: &[&str]) -> String {
        let parts = self.below(max_parts + 1);
        let mut out = String::new();
        for _ in 0..parts {
            match self.below(4) {
                0 | 1 if !tokens.is_empty() => out.push_str(tokens[self.below(tokens.len())]),
                2 => out.push(self.any_char()),
                _ => {
                    for _ in 0..self.below(8) {
                        out.push(self.any_char());
                    }
                }
            }
        }
        out
    }

    /// `sample` changed a little: flipped bits, special bytes, a cut, a repeated or removed
    /// slice, inserted bytes, or a 32-bit field set to an extreme value (length fields).
    pub(crate) fn mutate(&mut self, sample: &[u8]) -> Vec<u8> {
        let mut out = sample.to_vec();
        for _ in 0..1 + self.below(4) {
            if out.is_empty() {
                out.push(self.byte());
                continue;
            }
            let at = self.below(out.len());
            match self.below(7) {
                0 => out[at] ^= 1 << self.below(8),
                1 => out[at] = self.byte(),
                2 => out.truncate(at),
                3 => {
                    let end = (at + 1 + self.below(16)).min(out.len());
                    let slice = out[at..end].to_vec();
                    out.splice(at..at, slice);
                }
                4 => {
                    let end = (at + 1 + self.below(16)).min(out.len());
                    out.drain(at..end);
                }
                5 => {
                    let len = out.len() as u32;
                    let value = [0, 1, 0x7FFF_FFFF, 0xFFFF_FFFF, len, len.wrapping_add(1)][self.below(6)];
                    let end = (at + 4).min(out.len());
                    out.splice(at..end, value.to_le_bytes());
                }
                _ => {
                    let insert = self.bytes(16);
                    out.splice(at..at, insert);
                }
            }
        }
        out
    }

    /// `sample` changed a little, staying valid UTF-8.
    pub(crate) fn mutate_text(&mut self, sample: &str, tokens: &[&str]) -> String {
        let mut chars: Vec<char> = sample.chars().collect();
        for _ in 0..1 + self.below(4) {
            let at = self.below(chars.len() + 1);
            match self.below(5) {
                0 => chars.truncate(at),
                1 if at < chars.len() => {
                    let end = (at + 1 + self.below(24)).min(chars.len());
                    chars.drain(at..end);
                }
                2 => {
                    let insert: Vec<char> = self.text(3, tokens).chars().collect();
                    chars.splice(at..at, insert);
                }
                3 if at < chars.len() => {
                    let end = (at + 1 + self.below(40)).min(chars.len());
                    let repeated: Vec<char> = chars[at..end].to_vec();
                    chars.splice(at..at, repeated);
                }
                _ => {
                    let c = self.any_char();
                    if at < chars.len() {
                        chars[at] = c;
                    } else {
                        chars.push(c);
                    }
                }
            }
        }
        chars.into_iter().collect()
    }
}

/// Runs `f` on one input: it must not panic and must finish within [`LIMIT`].
pub(crate) fn check(name: &str, input: &[u8], f: impl FnOnce()) {
    let started = Instant::now();
    let outcome = catch_unwind(AssertUnwindSafe(f));
    let took = started.elapsed();
    assert!(outcome.is_ok(), "{name} panicked on input {}", shown(input));
    assert!(took < LIMIT, "{name} took {took:?} on input {}", shown(input));
}

/// [`check`] for text input.
pub(crate) fn check_text(name: &str, input: &str, f: impl FnOnce()) {
    check(name, input.as_bytes(), f);
}

fn shown(input: &[u8]) -> String {
    let cut = &input[..input.len().min(256)];
    let hex: String = cut.iter().map(|b| format!("{b:02x}")).collect();
    let more = if input.len() > 256 { "…" } else { "" };
    format!("({} bytes) {hex}{more}", input.len())
}
