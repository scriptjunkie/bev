pub struct Canon {
    pub id: &'static str,
    pub name: &'static str,
}

/// Real names. These dossiers are prefilled and must never be coined again.
pub const CANON: &[Canon] = &[
    Canon { id: "CVE-2014-0160", name: "Heartbleed" },
    Canon { id: "CVE-2021-44228", name: "Log4Shell" },
    Canon { id: "CVE-2014-6271", name: "Shellshock" },
    Canon { id: "CVE-2017-5753", name: "Spectre" },
    Canon { id: "CVE-2016-5195", name: "Dirty COW" },
    Canon { id: "CVE-2017-5754", name: "Meltdown" },
    Canon { id: "CVE-2014-3566", name: "POODLE" },
    Canon { id: "CVE-2017-0144", name: "EternalBlue" },
    Canon { id: "CVE-2019-0708", name: "BlueKeep" },
    Canon { id: "CVE-2015-0235", name: "GHOST" },
    Canon { id: "CVE-2015-1538", name: "Stagefright" },
    Canon { id: "CVE-2024-6387", name: "regreSSHion" },
    Canon { id: "CVE-2016-0800", name: "DROWN" },
    Canon { id: "CVE-2017-13077", name: "KRACK" },
    Canon { id: "CVE-2020-1472", name: "Zerologon" },
];

/// The six cards shown on the homepage under "Explore the names".
pub const EXPLORE_IDS: &[&str] = &[
    "CVE-2014-0160",
    "CVE-2026-1337",
    "CVE-2014-6271",
    "CVE-2026-0001",
    "CVE-2017-5753",
    "CVE-2026-101887",
];

pub fn is_canon(cve_id: &str) -> bool {
    let id = cve_id.trim().to_ascii_uppercase();
    CANON.iter().any(|c| c.id == id)
}

pub fn name_taken(name: &str, cve_id: &str) -> bool {
    let folded = fold(name);
    if folded.is_empty() {
        return false;
    }
    CANON.iter().any(|c| fold(c.name) == folded && c.id != cve_id)
        || matches!(
            folded.as_str(),
            "bashdoor" | "wannacry" | "log4jshell" | "dirtycow"
        )
}

fn fold(name: &str) -> String {
    name.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .flat_map(|c| c.to_lowercase())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_aliases_of_other_bugs() {
        assert!(name_taken("Heart bleed", "CVE-2026-0001"));
        assert!(name_taken("DirtyCow", "CVE-2026-0001"));
        assert!(!name_taken("Heartbleed", "CVE-2014-0160"));
        assert!(!name_taken("Latchlight", "CVE-2026-0001"));
    }

    #[test]
    fn canon_ids_are_recognized() {
        assert!(is_canon("cve-2014-0160"));
        assert!(is_canon("CVE-2014-6271"));
        assert!(!is_canon("CVE-2026-0001"));
    }
}
