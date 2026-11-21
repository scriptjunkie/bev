use std::fmt;

/// A CVE id with the sequence kept exactly as written, including leading zeros.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CveId {
    pub year: String,
    pub sequence: String,
}

impl CveId {
    pub fn as_id(&self) -> String {
        format!("CVE-{}-{}", self.year, self.sequence)
    }
}

impl fmt::Display for CveId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CVE-{}-{}", self.year, self.sequence)
    }
}

/// Accept `CVE-YYYY-NNNN` with a 4-digit year from 1999 through 2099 and a
/// sequence of 4 to 7 digits. The sequence is not numeric-normalized.
pub fn parse(raw: &str) -> Result<CveId, String> {
    let trimmed = raw.trim().trim_matches('/');
    if trimmed.is_empty() {
        return Err("Type an id first, like CVE-2026-0001.".into());
    }
    if trimmed.chars().any(|c| c.is_whitespace()) {
        return Err("A CVE id has no spaces. It looks like CVE-2021-44228.".into());
    }
    let upper = trimmed.to_ascii_uppercase();
    let Some(rest) = upper.strip_prefix("CVE-") else {
        return Err("CVE ids start with CVE-, as in CVE-2014-0160.".into());
    };
    let Some((year, sequence)) = rest.split_once('-') else {
        return Err("A CVE id needs a year and a sequence: CVE-2024-6387.".into());
    };
    if sequence.contains('-') {
        return Err("That has one hyphen too many. Use CVE-year-sequence.".into());
    }
    if year.len() != 4 || !year.bytes().all(|b| b.is_ascii_digit()) {
        return Err("The year is four digits, from 1999 through 2099.".into());
    }
    let year_n: u32 = year.parse().unwrap_or(0);
    if !(1999..=2099).contains(&year_n) {
        return Err("The year is four digits, from 1999 through 2099.".into());
    }
    if sequence.len() < 4 || sequence.len() > 7 || !sequence.bytes().all(|b| b.is_ascii_digit()) {
        return Err(
            "The sequence is the digits after the year, four to seven of them, like 0160 or 44228."
                .into(),
        );
    }
    Ok(CveId {
        year: year.to_string(),
        sequence: sequence.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_leading_zeros_and_long_sequences() {
        let a = parse("cve-2026-0001").unwrap();
        assert_eq!(a.as_id(), "CVE-2026-0001");
        assert_eq!(a.sequence, "0001");
        let b = parse("CVE-2021-44228").unwrap();
        assert_eq!(b.year, "2021");
        assert_eq!(b.sequence, "44228");
    }

    #[test]
    fn rejects_malformed() {
        assert!(parse("").is_err());
        assert!(parse("heartbleed").is_err());
        assert!(parse("CVE-2014-160").is_err());
        assert!(parse("CVE-2014-0160-1").is_err());
        assert!(parse("CVE 2014 0160").is_err());
        assert!(parse("CVE-1998-0001").is_err());
        assert!(parse("CVE-2014-01234567").is_err());
    }
}
