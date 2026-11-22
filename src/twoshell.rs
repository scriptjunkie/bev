use crate::model::NvdRecord;

/// Offline decorations. Qualifying names already wearing one of these get
/// 2Shell in its place instead of a second suffix.
const REPLACEABLE_SUFFIXES: &[&str] = &[
    "2Shell", "Shell", "Bleed", "pocalypse", "Doom", "-Gate", "Storm",
];

const PHRASES: &[&str] = &[
    "execute arbitrary code",
    "execute arbitrary commands",
    "remote code execution",
    "arbitrary code execution",
    "code execution",
    "command injection",
    "command execution",
    "memory corruption",
    "buffer overflow",
    "heap overflow",
    "heap-based buffer overflow",
    "stack overflow",
    "stack-based buffer overflow",
    "use after free",
    "use-after-free",
    "out-of-bounds write",
    "out of bounds write",
    "double free",
];

const CWE_IDS: &[&str] = &[
    "CWE-787", "CWE-416", "CWE-119", "CWE-120", "CWE-121", "CWE-122", "CWE-94", "CWE-78", "CWE-415",
];

/// True when the NVD record points at code execution or memory corruption.
pub fn qualifies(nvd: &NvdRecord) -> bool {
    description_matches(&nvd.description) || nvd.cwes.iter().any(|c| cwe_matches(c))
}

fn description_matches(description: &str) -> bool {
    let lower = description.to_ascii_lowercase();
    let spaced = lower.replace(['-', '_'], " ");
    if PHRASES.iter().any(|p| lower.contains(p) || spaced.contains(p)) {
        return true;
    }
    has_rce_word(&lower)
}

fn has_rce_word(lower: &str) -> bool {
    let mut start = 0usize;
    let bytes = lower.as_bytes();
    for (i, b) in bytes.iter().enumerate() {
        let alnum = b.is_ascii_alphanumeric();
        if !alnum {
            if i > start && &lower[start..i] == "rce" {
                return true;
            }
            start = i + 1;
        }
    }
    start < lower.len() && &lower[start..] == "rce"
}

fn cwe_matches(raw: &str) -> bool {
    let Some(id) = normalize_cwe(raw) else {
        return false;
    };
    CWE_IDS.iter().any(|c| *c == id)
}

pub fn normalize_cwe(raw: &str) -> Option<String> {
    let upper = raw.trim().to_ascii_uppercase().replace(['–', '—'], "-");
    let rest = upper
        .strip_prefix("CWE-")
        .or_else(|| upper.strip_prefix("CWE"))
        .unwrap_or(&upper)
        .trim()
        .trim_start_matches('-');
    if rest.is_empty() || !rest.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    Some(format!("CWE-{rest}"))
}

/// If the record qualifies, return a single CamelCase word ending in 2Shell.
/// Names that already end with 2Shell or Shell are left alone. Other known
/// offline suffixes are replaced with 2Shell so they are not stacked.
/// Famous, prefilled CVEs are never rewritten.
pub fn maybe_append(name: &str, nvd: &NvdRecord, cve_id: &str) -> String {
    if crate::famous::is_canon(cve_id) {
        return name.to_string();
    }
    if !qualifies(nvd) {
        return name.to_string();
    }
    append_2shell(name)
}

pub fn append_2shell(name: &str) -> String {
    let camel = camel_case(name);
    if camel.is_empty() {
        return camel;
    }
    if ends_with_shell(&camel) {
        return camel;
    }
    if let Some(stem) = strip_known_suffix(&camel) {
        if !stem.is_empty() {
            return format!("{stem}2Shell");
        }
    }
    format!("{camel}2Shell")
}

fn camel_case(name: &str) -> String {
    name.split(|c: char| c.is_whitespace() || c == '-' || c == '_')
        .filter(|w| !w.is_empty())
        .collect::<Vec<_>>()
        .join("")
}

fn folded(name: &str) -> String {
    name.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .flat_map(|c| c.to_lowercase())
        .collect()
}

fn ends_with_shell(name: &str) -> bool {
    let fold = folded(name);
    fold.ends_with("2shell") || fold.ends_with("shell")
}

fn strip_known_suffix(name: &str) -> Option<&str> {
    let fold = folded(name);
    let mut best_len = 0usize;
    let mut best: Option<&str> = None;
    for suffix in REPLACEABLE_SUFFIXES {
        let needle = folded(suffix);
        if needle.is_empty() || !fold.ends_with(&needle) {
            continue;
        }
        if needle.len() < best_len {
            continue;
        }
        // Map folded suffix length back onto the original CamelCase name
        // by counting alphanumeric chars from the end.
        let want = needle.len();
        let mut seen = 0usize;
        for (idx, ch) in name.char_indices().rev() {
            if ch.is_ascii_alphanumeric() {
                seen += 1;
                if seen == want {
                    best = Some(&name[..idx]);
                    best_len = want;
                    break;
                }
            }
        }
    }
    best
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nvd(desc: &str, cwes: &[&str]) -> NvdRecord {
        NvdRecord {
            description: desc.into(),
            cwes: cwes.iter().map(|s| s.to_string()).collect(),
            ..NvdRecord::default()
        }
    }

    fn apply(name: &str, record: &NvdRecord) -> String {
        maybe_append(name, record, "CVE-2026-9001")
    }

    #[test]
    fn phrases_and_rce_are_case_insensitive() {
        assert!(qualifies(&nvd("Remote Code Execution in the parser.", &[])));
        assert!(qualifies(&nvd(
            "Allows an attacker to EXECUTE ARBITRARY CODE.",
            &[]
        )));
        assert!(qualifies(&nvd("This is an RCE in the agent.", &[])));
        assert!(qualifies(&nvd("impact: rce.", &[])));
        assert!(qualifies(&nvd("A use-after-free in the GPU driver.", &[])));
        assert!(qualifies(&nvd(
            "Heap-based buffer overflow in the TIFF decoder.",
            &[]
        )));
        assert!(qualifies(&nvd("Out-of-bounds write to heap memory.", &[])));
        assert!(qualifies(&nvd("Command injection via the debug flag.", &[])));
        assert!(!qualifies(&nvd(
            "A cross-site scripting issue in the admin UI.",
            &[]
        )));
        assert!(!qualifies(&nvd("Commerce module forced a reconnect.", &[])));
    }

    #[test]
    fn cwe_ids_qualify_even_without_the_phrase() {
        assert!(qualifies(&nvd("A bug in the parser.", &["CWE-787"])));
        assert!(qualifies(&nvd("", &["cwe-416"])));
        assert!(qualifies(&nvd("unspecified", &["CWE-78"])));
        assert!(!qualifies(&nvd("A bug in the parser.", &["CWE-79"])));
    }

    #[test]
    fn appends_camelcase_2shell_when_it_qualifies() {
        let overflow = nvd("A buffer overflow in the decoder.", &[]);
        assert_eq!(apply("CaseSlip", &overflow), "CaseSlip2Shell");
        assert_eq!(apply("Paper Harbor", &overflow), "PaperHarbor2Shell");
        assert_eq!(apply("  SVG-Snare ", &overflow), "SVGSnare2Shell");
        let xss = nvd("Cross-site scripting only.", &[]);
        assert_eq!(apply("CaseSlip", &xss), "CaseSlip");
        assert_eq!(apply("Paper Harbor", &xss), "Paper Harbor");
    }

    #[test]
    fn does_not_double_or_stack_known_suffixes() {
        let overflow = nvd("Memory corruption allows RCE.", &[]);
        assert_eq!(apply("Pickle2Shell", &overflow), "Pickle2Shell");
        assert_eq!(apply("PickleShell", &overflow), "PickleShell");
        assert_eq!(apply("pickle2shell", &overflow), "pickle2shell");
        assert_eq!(apply("GateBleed", &overflow), "Gate2Shell");
        assert_eq!(apply("RouterDoom", &overflow), "Router2Shell");
        assert_eq!(apply("Press-Gate", &overflow), "Press2Shell");
        assert_eq!(apply("QuietStorm", &overflow), "Quiet2Shell");
        assert_eq!(apply("Wordpocalypse", &overflow), "Word2Shell");
    }

    #[test]
    fn famous_cves_are_left_alone() {
        let overflow = nvd("A buffer overflow in OpenSSL.", &[]);
        assert_eq!(
            maybe_append("Heartbleed", &overflow, "CVE-2014-0160"),
            "Heartbleed"
        );
        assert_eq!(
            maybe_append("Heartbleed", &overflow, "CVE-2026-0001"),
            "Heart2Shell"
        );
    }
}
