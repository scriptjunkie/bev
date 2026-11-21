pub struct Canon {
    pub id: &'static str,
    pub name: &'static str,
    pub featured: bool,
}

/// Real names. These dossiers are prefilled and must never be coined again.
pub const CANON: &[Canon] = &[
    Canon { id: "CVE-2014-0160", name: "Heartbleed", featured: true },
    Canon { id: "CVE-2021-44228", name: "Log4Shell", featured: true },
    Canon { id: "CVE-2014-6271", name: "Shellshock", featured: true },
    Canon { id: "CVE-2017-5753", name: "Spectre", featured: true },
    Canon { id: "CVE-2016-5195", name: "Dirty COW", featured: true },
    Canon { id: "CVE-2017-5754", name: "Meltdown", featured: true },
    Canon { id: "CVE-2014-3566", name: "POODLE", featured: false },
    Canon { id: "CVE-2017-0144", name: "EternalBlue", featured: false },
    Canon { id: "CVE-2019-0708", name: "BlueKeep", featured: false },
    Canon { id: "CVE-2015-0235", name: "GHOST", featured: false },
    Canon { id: "CVE-2015-1538", name: "Stagefright", featured: false },
    Canon { id: "CVE-2024-6387", name: "regreSSHion", featured: false },
    Canon { id: "CVE-2016-0800", name: "DROWN", featured: false },
    Canon { id: "CVE-2017-13077", name: "KRACK", featured: false },
    Canon { id: "CVE-2020-1472", name: "Zerologon", featured: false },
];

pub struct Sample {
    pub id: &'static str,
    pub note: &'static str,
}

/// Real NVD entries that are not in the prefilled wall.
pub const SAMPLES: &[Sample] = &[
    Sample {
        id: "CVE-2026-0001",
        note: "Use-after-free in Arm's Bifrost, Valhall, and 5th Gen GPU kernel drivers.",
    },
    Sample {
        id: "CVE-2026-13313",
        note: "Debug code on some ASUS routers lets an authenticated user open Telnet as root.",
    },
    Sample {
        id: "CVE-2026-101887",
        note: "A zero frame-count in a Bluetooth header crashes BlueALSA's LC3plus decoder.",
    },
];

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
}
