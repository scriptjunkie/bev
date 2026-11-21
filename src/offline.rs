use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::famous;
use crate::model::NvdRecord;

const WORDLIST: &str = include_str!("wordlist.txt");

/// Decorations in the tradition of Log4Shell and Heartbleed.
const SUFFIXES: &[&str] = &[
    "2Shell", "Shell", "Bleed", "pocalypse", "Doom", "-Gate", "Storm",
];

pub struct OfflineName {
    pub name: String,
    pub tagline: String,
    pub blurb: String,
}

pub fn coin(nvd: &NvdRecord, cve_id: &str) -> OfflineName {
    let mut rng = live_rng();
    coin_from(nvd, cve_id, &mut rng)
}

pub fn coin_from(nvd: &NvdRecord, cve_id: &str, rng: &mut impl FnMut() -> u64) -> OfflineName {
    let keywords = keywords(nvd);
    let mut name = String::new();
    for _ in 0..12 {
        let candidate = compose(&keywords, rng);
        if !famous::name_taken(&candidate, cve_id) {
            name = candidate;
            break;
        }
    }
    if name.is_empty() {
        name = format!("Relic{}", SUFFIXES[(rng() as usize) % SUFFIXES.len()]);
    }
    let tagline = first_sentence(&nvd.description);
    let blurb = if nvd.description.trim().is_empty() {
        "NVD did not publish an English description, so this name came from the wordlist."
            .to_string()
    } else {
        "The wordlist supplied this name. The NVD record is unchanged below.".to_string()
    };
    OfflineName {
        name,
        tagline,
        blurb,
    }
}

pub fn svg(name: &str, nvd: &NvdRecord) -> String {
    let keywords = keywords(nvd);
    let severity = nvd
        .cvss
        .as_ref()
        .map(|c| c.severity.as_str())
        .unwrap_or("UNKNOWN");
    let (start, end, ink) = palette(severity);
    let kind = fnv(name) % 5;
    let mark = shape(kind, ink);
    let size = if name.chars().count() > 18 {
        34
    } else if name.chars().count() > 14 {
        42
    } else {
        52
    };
    let chips = keyword_line(&keywords, name);
    format!(
        r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 640 640" role="img" aria-label="{label}">
  <defs>
    <linearGradient id="wash" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0" stop-color="{start}"/>
      <stop offset="1" stop-color="{end}"/>
    </linearGradient>
  </defs>
  <rect width="640" height="640" fill="url(#wash)"/>
  <rect x="28" y="28" width="584" height="584" fill="none" stroke="{ink}" stroke-opacity="0.35" stroke-width="2"/>
  {mark}
  <text x="320" y="470" text-anchor="middle" fill="{ink}" font-family="Georgia, 'Iowan Old Style', Palatino, serif" font-size="{size}">{name}</text>
  <text x="320" y="524" text-anchor="middle" fill="{ink}" fill-opacity="0.78" font-family="ui-monospace, 'IBM Plex Mono', monospace" font-size="18" letter-spacing="2">{chips}</text>
</svg>
"##,
        label = xml(name),
        name = xml(name),
        chips = xml(&chips),
    )
}

fn compose(keywords: &[String], rng: &mut impl FnMut() -> u64) -> String {
    let use_keyword = !keywords.is_empty() && rng() % 5 < 2;
    let stem = if use_keyword {
        keywords[(rng() as usize) % keywords.len()].clone()
    } else {
        let words = words();
        words[(rng() as usize) % words.len()].to_string()
    };
    let mut suffix = SUFFIXES[(rng() as usize) % SUFFIXES.len()];
    if stem.eq_ignore_ascii_case(suffix.trim_start_matches('-')) {
        suffix = SUFFIXES[((rng() as usize) + 1) % SUFFIXES.len()];
    }
    format!("{stem}{suffix}")
}

fn words() -> Vec<String> {
    WORDLIST
        .lines()
        .map(str::trim)
        .filter(|w| !w.is_empty() && !w.starts_with('#'))
        .map(ToString::to_string)
        .collect()
}

fn keywords(nvd: &NvdRecord) -> Vec<String> {
    let mut raw = String::new();
    if let Some(product) = &nvd.product {
        raw.push_str(product);
        raw.push(' ');
    }
    if let Some(vendor) = &nvd.vendor {
        raw.push_str(vendor);
        raw.push(' ');
    }
    raw.push_str(&nvd.description);
    let mut out = Vec::new();
    for word in raw.split(|c: char| !c.is_ascii_alphabetic()) {
        let lower = word.to_ascii_lowercase();
        if !(4..=12).contains(&lower.len()) || STOP.contains(&lower.as_str()) {
            continue;
        }
        let titled = title_case(&lower);
        if !out.iter().any(|existing: &String| existing.eq_ignore_ascii_case(&titled)) {
            out.push(titled);
        }
        if out.len() == 8 {
            break;
        }
    }
    out
}

fn keyword_line(keywords: &[String], name: &str) -> String {
    let mut picked = Vec::new();
    for word in keywords {
        if name.to_ascii_lowercase().contains(&word.to_ascii_lowercase()) {
            continue;
        }
        picked.push(word.as_str());
        if picked.len() == 2 {
            break;
        }
    }
    if picked.is_empty() {
        "offline mark".into()
    } else {
        picked.join("  ·  ")
    }
}

fn title_case(word: &str) -> String {
    let mut chars = word.chars();
    match chars.next() {
        Some(first) => first.to_ascii_uppercase().to_string() + chars.as_str(),
        None => String::new(),
    }
}

fn first_sentence(description: &str) -> String {
    let sentence = description
        .split(['.', '\n'])
        .find(|s| !s.trim().is_empty())
        .unwrap_or("Named from the wordlist.");
    let text = clip_chars(sentence.trim(), 140);
    if text.is_empty() {
        "Named from the wordlist.".into()
    } else {
        text
    }
}

fn palette(severity: &str) -> (&'static str, &'static str, &'static str) {
    match severity.to_ascii_uppercase().as_str() {
        "CRITICAL" => ("#5c1410", "#e23b2b", "#fff4f1"),
        "HIGH" => ("#6e2e0c", "#e39a3c", "#fff8ee"),
        "MEDIUM" => ("#4e3c14", "#d7b56d", "#fffaf0"),
        "LOW" => ("#14382c", "#3f9d72", "#f3fff8"),
        "NONE" => ("#2c2926", "#8a8175", "#f4efe4"),
        _ => ("#241f1b", "#6e675c", "#f4efe4"),
    }
}

fn shape(kind: u64, ink: &str) -> String {
    match kind {
        0 => format!(
            r#"<circle cx="320" cy="230" r="86" fill="none" stroke="{ink}" stroke-width="16"/>
  <circle cx="320" cy="230" r="28" fill="{ink}"/>"#
        ),
        1 => format!(
            r#"<rect x="232" y="142" width="176" height="176" fill="none" stroke="{ink}" stroke-width="16" transform="rotate(45 320 230)"/>
  <rect x="296" y="206" width="48" height="48" fill="{ink}" transform="rotate(45 320 230)"/>"#
        ),
        2 => format!(
            r#"<path d="M210 300 L320 130 L430 300" fill="none" stroke="{ink}" stroke-width="16" stroke-linejoin="miter"/>
  <path d="M250 300 H390" stroke="{ink}" stroke-width="16"/>"#
        ),
        3 => format!(
            r#"<rect x="214" y="140" width="212" height="180" fill="none" stroke="{ink}" stroke-width="16"/>
  <path d="M214 230 H426" stroke="{ink}" stroke-width="16"/>
  <path d="M320 140 V320" stroke="{ink}" stroke-width="16"/>"#
        ),
        _ => format!(
            r#"<circle cx="320" cy="230" r="92" fill="none" stroke="{ink}" stroke-width="16" stroke-dasharray="40 28"/>
  <circle cx="320" cy="230" r="18" fill="{ink}"/>"#
        ),
    }
}

fn xml(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(ch),
        }
    }
    out
}

fn clip_chars(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        return text.to_string();
    }
    let mut out: String = text.chars().take(max.saturating_sub(1)).collect();
    out.push('…');
    out
}

fn live_rng() -> impl FnMut() -> u64 {
    let mut state = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0xA5A5)
        ^ COUNTER.fetch_add(0x9E37_79B9_7F4A_7C15, Ordering::Relaxed);
    move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    }
}

fn fnv(text: &str) -> u64 {
    let mut hash = 0xcbf29ce484222325u64;
    for byte in text.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

static COUNTER: AtomicU64 = AtomicU64::new(1);

const STOP: &[&str] = &[
    "that", "this", "with", "from", "into", "when", "where", "which", "while", "have", "been",
    "were", "will", "would", "could", "should", "their", "there", "these", "those", "than",
    "then", "them", "they", "your", "about", "after", "before", "under", "over", "also", "only",
    "such", "some", "other", "more", "most", "less", "very", "just", "like", "using", "used",
    "allows", "allow", "allowed", "via", "through", "between", "within", "without", "against",
    "remote", "local", "code", "attacker", "attackers", "user", "users", "issue", "issues",
    "vulnerability", "vulnerabilities", "flaw", "flaws", "bug", "bugs", "cve", "version",
    "versions", "function", "file", "files", "does", "doesn", "not", "and", "the", "for", "are",
    "was", "has", "had", "its", "may", "can", "all", "any", "but", "out", "our", "you",
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Cvss;

    fn seq(values: &'static [u64]) -> impl FnMut() -> u64 {
        let mut i = 0usize;
        move || {
            let value = values[i % values.len()];
            i += 1;
            value
        }
    }

    #[test]
    fn keyword_plus_suffix_can_spell_pickle2shell() {
        let nvd = NvdRecord {
            product: Some("pickle".into()),
            description: "A parser bug.".into(),
            ..NvdRecord::default()
        };
        let named = coin_from(&nvd, "CVE-2026-13313", &mut seq(&[0, 0, 0]));
        assert_eq!(named.name, "Pickle2Shell");
    }

    #[test]
    fn wordlist_name_uses_a_known_decoration() {
        let nvd = NvdRecord::default();
        let named = coin_from(&nvd, "CVE-2026-13313", &mut seq(&[9, 3, 4]));
        assert!(
            SUFFIXES.iter().any(|suffix| named.name.ends_with(suffix)),
            "{}",
            named.name
        );
        let stem = SUFFIXES
            .iter()
            .find(|suffix| named.name.ends_with(*suffix))
            .map(|suffix| named.name.trim_end_matches(suffix))
            .unwrap();
        assert!(words().iter().any(|word| word == stem));
    }

    #[test]
    fn svg_is_local_and_colored_by_severity() {
        let nvd = NvdRecord {
            description: "Telnet stays open on the router.".into(),
            product: Some("router".into()),
            cvss: Some(Cvss {
                version: "3.1".into(),
                score: 9.8,
                severity: "CRITICAL".into(),
                vector: "CVSS:3.1/AV:N".into(),
            }),
            ..NvdRecord::default()
        };
        let named = coin_from(&nvd, "CVE-1", &mut seq(&[0, 0, 2]));
        let drawn = svg(&named.name, &nvd);
        assert!(drawn.contains("<svg"));
        assert!(drawn.contains(&named.name));
        assert!(drawn.contains("#e23b2b"));
        assert!(!drawn.contains("😀"));
        assert!(!drawn.to_lowercase().contains("<script"));
        let low = NvdRecord {
            cvss: Some(Cvss {
                version: "3.1".into(),
                score: 3.1,
                severity: "LOW".into(),
                vector: "CVSS:3.1/AV:L".into(),
            }),
            ..NvdRecord::default()
        };
        let low_svg = svg("QuietStorm", &low);
        assert!(low_svg.contains("#3f9d72"));
        assert!(!low_svg.contains("#e23b2b"));
    }
}
