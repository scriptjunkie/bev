use serde::{Deserialize, Serialize};

/// A filed branding dossier. Prefilled famous CVEs and generated ones share this shape.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Branding {
    pub cve_id: String,
    pub name: String,
    #[serde(default)]
    pub tagline: String,
    #[serde(default)]
    pub blurb: String,
    #[serde(default)]
    pub logo_file: Option<String>,
    #[serde(default)]
    pub logo_credit: Option<String>,
    #[serde(default)]
    pub official_site: Option<String>,
    #[serde(default)]
    pub official_site_label: Option<String>,
    #[serde(default)]
    pub prefilled: bool,
    #[serde(default)]
    pub naming_model: Option<String>,
    #[serde(default)]
    pub image_model: Option<String>,
    #[serde(default)]
    pub naming_source: String,
    /// "recraft" when OpenRouter drew the mark, "offline" when the SVG was drawn here.
    #[serde(default)]
    pub logo_source: String,
    #[serde(default)]
    pub logo_prompt: Option<String>,
    #[serde(default)]
    pub created_at: String,
    #[serde(default)]
    pub nvd: NvdRecord,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NvdRecord {
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub vendor: Option<String>,
    #[serde(default)]
    pub product: Option<String>,
    #[serde(default)]
    pub affected: Vec<Product>,
    #[serde(default)]
    pub cvss: Option<Cvss>,
    #[serde(default)]
    pub nvd_url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Product {
    pub vendor: String,
    pub product: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Cvss {
    pub version: String,
    pub score: f64,
    pub severity: String,
    pub vector: String,
}

impl Branding {
    pub fn nvd_link(&self) -> String {
        if is_safe_http(&self.nvd.nvd_url) {
            self.nvd.nvd_url.clone()
        } else {
            format!("https://nvd.nist.gov/vuln/detail/{}", self.cve_id)
        }
    }

    pub fn site_link(&self) -> Option<(&str, &str)> {
        let url = self.official_site.as_deref()?;
        if !is_safe_http(url) {
            return None;
        }
        let label = self
            .official_site_label
            .as_deref()
            .filter(|s| !s.is_empty())
            .unwrap_or("Official site");
        Some((url, label))
    }
}

pub fn is_safe_http(url: &str) -> bool {
    let u = url.trim();
    (u.starts_with("https://") || u.starts_with("http://"))
        && !u.chars().any(|c| {
            c.is_whitespace() || c == '"' || c == '\'' || c == '<' || c == '>' || c == '\\'
        })
}

pub fn format_score(score: f64) -> String {
    format!("{score:.1}")
}

pub fn severity_class(severity: &str) -> &'static str {
    match severity.to_ascii_uppercase().as_str() {
        "CRITICAL" => "sev-critical",
        "HIGH" => "sev-high",
        "MEDIUM" => "sev-medium",
        "LOW" => "sev-low",
        "NONE" => "sev-none",
        _ => "sev-unknown",
    }
}

#[cfg(test)]
pub fn sample(id: &str, name: &str) -> Branding {
    Branding {
        cve_id: id.to_string(),
        name: name.to_string(),
        tagline: "A short line.".into(),
        blurb: "Two sentences about the bug.".into(),
        logo_file: None,
        logo_credit: None,
        official_site: None,
        official_site_label: None,
        prefilled: false,
        naming_model: Some("meta-llama/llama-3.1-8b-instruct".into()),
        image_model: Some("recraft/recraft-v4.1-flash-v2".into()),
        naming_source: "model".into(),
        logo_source: "recraft".into(),
        logo_prompt: None,
        created_at: "2026-11-21T00:00:00Z".into(),
        nvd: NvdRecord {
            description: "An English description from NVD.".into(),
            vendor: Some("openssl".into()),
            product: Some("openssl".into()),
            affected: vec![Product {
                vendor: "openssl".into(),
                product: "openssl".into(),
            }],
            cvss: Some(Cvss {
                version: "3.1".into(),
                score: 7.5,
                severity: "HIGH".into(),
                vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N".into(),
            }),
            nvd_url: format!("https://nvd.nist.gov/vuln/detail/{id}"),
        },
    }
}
