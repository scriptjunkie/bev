use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};

use serde_json::Value;

use crate::cve::CveId;
use crate::model::{Cvss, NvdRecord, Product};

const NVD_URL: &str = "https://services.nvd.nist.gov/rest/json/cves/2.0";

pub struct NvdClient {
    agent: ureq::Agent,
    api_key: Option<String>,
    recent: Mutex<VecDeque<Instant>>,
}

#[derive(Debug)]
pub enum NvdError {
    NotFound,
    Failed(String),
}

impl std::fmt::Display for NvdError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NvdError::NotFound => write!(f, "NVD has no record for that id"),
            NvdError::Failed(msg) => write!(f, "{msg}"),
        }
    }
}

impl NvdClient {
    pub fn new(api_key: Option<String>) -> Self {
        let agent = ureq::AgentBuilder::new()
            .timeout_connect(Duration::from_secs(15))
            .timeout_read(Duration::from_secs(40))
            .user_agent("BrandEveryVuln/0.1 (cve branding; +https://nvd.nist.gov/)")
            .build();
        Self {
            agent,
            api_key,
            recent: Mutex::new(VecDeque::new()),
        }
    }

    pub fn fetch(&self, id: &CveId) -> Result<NvdRecord, NvdError> {
        let url = format!("{NVD_URL}?cveId={id}");
        let mut last = String::from("NVD did not answer");
        for attempt in 0..4 {
            self.pace();
            let mut req = self
                .agent
                .get(&url)
                .set("Accept", "application/json");
            if let Some(key) = &self.api_key {
                req = req.set("apiKey", key);
            }
            match req.call() {
                Ok(resp) => {
                    let status = resp.status();
                    let body = resp.into_string().unwrap_or_default();
                    if status == 404 {
                        return Err(NvdError::NotFound);
                    }
                    return parse_body(&body, id);
                }
                Err(ureq::Error::Status(code, resp)) => {
                    let body = resp.into_string().unwrap_or_default();
                    if code == 404 {
                        return Err(NvdError::NotFound);
                    }
                    let snippet = clip(&scrub(&body), 240);
                    last = format!("NVD returned HTTP {code}. {snippet}");
                    if matches!(code, 403 | 429 | 503) && attempt < 3 {
                        let wait = Duration::from_secs(8 + attempt as u64 * 8);
                        eprintln!("nvd {id} HTTP {code}, backing off {}s", wait.as_secs());
                        thread::sleep(wait);
                        continue;
                    }
                    return Err(NvdError::Failed(last));
                }
                Err(err) => {
                    last = format!("Could not reach NVD: {err}");
                    if attempt < 2 {
                        thread::sleep(Duration::from_secs(2));
                        continue;
                    }
                    return Err(NvdError::Failed(last));
                }
            }
        }
        Err(NvdError::Failed(last))
    }

    /// NVD allows about 5 requests / 30s without a key. Stay under that.
    fn pace(&self) {
        let limit = if self.api_key.is_some() { 8 } else { 4 };
        let window = Duration::from_secs(30);
        loop {
            let wait = {
                let mut recent = self.recent.lock().unwrap_or_else(|e| e.into_inner());
                let now = Instant::now();
                while recent
                    .front()
                    .map(|t| now.duration_since(*t) >= window)
                    .unwrap_or(false)
                {
                    recent.pop_front();
                }
                if recent.len() < limit {
                    recent.push_back(now);
                    None
                } else {
                    recent.front().map(|t| window.saturating_sub(now.duration_since(*t)))
                }
            };
            match wait {
                None => break,
                Some(d) => thread::sleep(d + Duration::from_millis(40)),
            }
        }
    }
}

pub fn parse_body(body: &str, id: &CveId) -> Result<NvdRecord, NvdError> {
    let value: Value = serde_json::from_str(body)
        .map_err(|_| NvdError::Failed("NVD returned something that was not JSON.".into()))?;
    let total = value.get("totalResults").and_then(|v| v.as_u64()).unwrap_or(0);
    let vulns = value
        .get("vulnerabilities")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    if vulns.is_empty() || total == 0 {
        return Err(NvdError::NotFound);
    }
    let cve = vulns[0].get("cve").cloned().unwrap_or(Value::Null);
    let description = english_description(&cve).unwrap_or_default();
    let mut hits = Vec::new();
    if let Some(configs) = cve.get("configurations").and_then(|v| v.as_array()) {
        for config in configs {
            walk_node(config, &mut hits);
        }
    }
    let affected = choose_affected(hits);
    let (vendor, product) = affected
        .first()
        .map(|p| (Some(p.vendor.clone()), Some(p.product.clone())))
        .unwrap_or((None, None));
    Ok(NvdRecord {
        description,
        vendor,
        product,
        affected,
        cvss: pick_cvss(cve.get("metrics")),
        nvd_url: format!("https://nvd.nist.gov/vuln/detail/{id}"),
    })
}

fn english_description(cve: &Value) -> Option<String> {
    let list = cve.get("descriptions")?.as_array()?;
    let chosen = list
        .iter()
        .find(|d| d.get("lang").and_then(|l| l.as_str()) == Some("en"))
        .or_else(|| list.first())?;
    let text = chosen.get("value")?.as_str()?.trim();
    if text.is_empty() {
        None
    } else {
        Some(text.to_string())
    }
}

fn walk_node(node: &Value, out: &mut Vec<(String, String, String)>) {
    if let Some(matches) = node.get("cpeMatch").and_then(|v| v.as_array()) {
        for item in matches {
            let vulnerable = item
                .get("vulnerable")
                .and_then(|v| v.as_bool())
                .unwrap_or(true);
            if !vulnerable {
                continue;
            }
            let criteria = item
                .get("criteria")
                .or_else(|| item.get("cpe23Uri"))
                .and_then(|v| v.as_str());
            if let Some(criteria) = criteria {
                if let Some(hit) = parse_cpe(criteria) {
                    out.push(hit);
                }
            }
        }
    }
    for key in ["nodes", "children"] {
        if let Some(children) = node.get(key).and_then(|v| v.as_array()) {
            for child in children {
                walk_node(child, out);
            }
        }
    }
}

/// Configurations list every product that ships the bug, so the first CPE is
/// often a distro or a firmware image. Prefer the component the bug is in.
fn choose_affected(hits: Vec<(String, String, String)>) -> Vec<Product> {
    let mut counts: HashMap<(String, String, String), usize> = HashMap::new();
    let mut order = Vec::new();
    for hit in hits {
        let entry = counts.entry(hit.clone()).or_insert(0);
        if *entry == 0 {
            order.push(hit);
        }
        *entry += 1;
    }
    order.sort_by(|a, b| {
        let sa = cpe_score(a, counts.get(a).copied().unwrap_or(0));
        let sb = cpe_score(b, counts.get(b).copied().unwrap_or(0));
        sb.cmp(&sa)
    });
    order
        .into_iter()
        .take(12)
        .map(|(_, vendor, product)| Product { vendor, product })
        .collect()
}

fn cpe_score(hit: &(String, String, String), count: usize) -> i32 {
    let (part, vendor, product) = hit;
    let mut score = count.min(500) as i32;
    const EXACT: &[(&str, &str)] = &[
        ("openssl", "openssl"),
        ("gnu", "bash"),
        ("gnu", "glibc"),
        ("google", "android"),
        ("linux", "linux_kernel"),
        ("apache", "log4j"),
        ("openbsd", "openssh"),
        ("microsoft", "server_message_block"),
        ("w1.fi", "wpa_supplicant"),
        ("w1.fi", "hostapd"),
    ];
    if EXACT.contains(&(vendor.as_str(), product.as_str())) {
        score += 10_000;
    }
    if matches!(
        vendor.as_str(),
        "apache" | "openssl" | "gnu" | "openbsd" | "linux" | "google" | "microsoft" | "intel" | "arm" | "w1.fi"
    ) {
        score += 1_000;
    }
    if part == "a" {
        score += 100;
    } else if part == "h" {
        score += 40;
    }
    score
}

fn parse_cpe(criteria: &str) -> Option<(String, String, String)> {
    let parts = split_unescaped(criteria);
    if parts.len() < 5 || !parts[0].eq_ignore_ascii_case("cpe") {
        return None;
    }
    let part = parts[2].trim().to_string();
    let vendor = parts[3].trim().to_string();
    let product = parts[4].trim().to_string();
    if !usable(&vendor) || !usable(&product) {
        return None;
    }
    Some((part, vendor, product))
}

fn usable(value: &str) -> bool {
    !value.is_empty() && value != "*" && value != "-"
}

fn split_unescaped(value: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut cur = String::new();
    let mut chars = value.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '\\' {
            if let Some(next) = chars.next() {
                cur.push(next);
            }
        } else if ch == ':' {
            parts.push(std::mem::take(&mut cur));
        } else {
            cur.push(ch);
        }
    }
    parts.push(cur);
    parts
}

fn pick_cvss(metrics: Option<&Value>) -> Option<Cvss> {
    let metrics = metrics?;
    const ORDER: &[(&str, &str)] = &[
        ("cvssMetricV31", "3.1"),
        ("cvssMetricV30", "3.0"),
        ("cvssMetricV40", "4.0"),
        ("cvssMetricV2", "2.0"),
    ];
    for (key, fallback_version) in ORDER {
        let Some(list) = metrics.get(*key).and_then(|v| v.as_array()) else {
            continue;
        };
        let metric = list
            .iter()
            .find(|m| {
                m.get("type").and_then(|t| t.as_str()) == Some("Primary")
                    && m.get("source")
                        .and_then(|s| s.as_str())
                        .map(|s| s.to_ascii_lowercase().contains("nvd"))
                        .unwrap_or(false)
            })
            .or_else(|| {
                list.iter()
                    .find(|m| m.get("type").and_then(|t| t.as_str()) == Some("Primary"))
            })
            .or_else(|| list.first())?;
        let data = metric.get("cvssData")?;
        let score = data.get("baseScore").and_then(|v| v.as_f64())?;
        let version = data
            .get("version")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .unwrap_or(fallback_version)
            .to_string();
        let severity = severity_of(metric, data, score);
        let vector = data
            .get("vectorString")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        return Some(Cvss {
            version,
            score,
            severity,
            vector,
        });
    }
    None
}

fn severity_of(metric: &Value, data: &Value, score: f64) -> String {
    for src in [data, metric] {
        if let Some(text) = src.get("baseSeverity").and_then(|v| v.as_str()) {
            if !text.trim().is_empty() {
                return text.trim().to_ascii_uppercase();
            }
        }
    }
    if score <= 0.0 {
        "NONE"
    } else if score < 4.0 {
        "LOW"
    } else if score < 7.0 {
        "MEDIUM"
    } else if score < 9.0 {
        "HIGH"
    } else {
        "CRITICAL"
    }
    .to_string()
}

fn scrub(text: &str) -> String {
    let mut out = text.to_string();
    while let Some(start) = out.find("sk-or-") {
        let rest = &out[start..];
        let end_rel = rest
            .find(|c: char| c.is_whitespace() || c == '"' || c == '\'')
            .unwrap_or(rest.len().min(80));
        let end = start + end_rel;
        out.replace_range(start..end, "[redacted]");
    }
    out
}

fn clip(text: &str, max: usize) -> String {
    let mut out: String = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if out.chars().count() > max {
        out = out.chars().take(max).collect();
        out.push('…');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id() -> CveId {
        CveId {
            year: "2014".into(),
            sequence: "0160".into(),
        }
    }

    #[test]
    fn prefers_v31_over_v2_and_skips_nonvulnerable_cpe() {
        let body = r#"{
            "totalResults": 1,
            "vulnerabilities": [{
                "cve": {
                    "id": "CVE-2014-0160",
                    "descriptions": [
                        {"lang": "es", "value": "no"},
                        {"lang": "en", "value": "The heartbeat extension read too far."}
                    ],
                    "metrics": {
                        "cvssMetricV2": [{
                            "type": "Primary",
                            "cvssData": {"version": "2.0", "baseScore": 5.0, "vectorString": "AV:N/AC:L/Au:N/C:P/I:N/A:N"},
                            "baseSeverity": "MEDIUM"
                        }],
                        "cvssMetricV31": [{
                            "type": "Primary",
                            "cvssData": {
                                "version": "3.1",
                                "baseScore": 7.5,
                                "baseSeverity": "HIGH",
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
                            }
                        }]
                    },
                    "configurations": [{
                        "nodes": [{
                            "operator": "OR",
                            "cpeMatch": [
                                {"vulnerable": true, "criteria": "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*"},
                                {"vulnerable": false, "criteria": "cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*"}
                            ]
                        }]
                    }]
                }
            }]
        }"#;
        let rec = parse_body(body, &id()).unwrap();
        assert_eq!(rec.description, "The heartbeat extension read too far.");
        assert_eq!(rec.vendor.as_deref(), Some("openssl"));
        assert_eq!(rec.product.as_deref(), Some("openssl"));
        assert_eq!(rec.affected.len(), 1);
        let cvss = rec.cvss.unwrap();
        assert_eq!(cvss.version, "3.1");
        assert_eq!(cvss.score, 7.5);
        assert_eq!(cvss.severity, "HIGH");
    }

    #[test]
    fn prefers_v31_over_v40_and_uses_v40_when_alone() {
        let both = r#"{
            "totalResults": 1,
            "vulnerabilities": [{
                "cve": {
                    "descriptions": [{"lang": "en", "value": "both"}],
                    "metrics": {
                        "cvssMetricV40": [{"type": "Primary", "cvssData": {"version": "4.0", "baseScore": 9.1, "baseSeverity": "CRITICAL", "vectorString": "CVSS:4.0/AV:N"}}],
                        "cvssMetricV31": [{"type": "Primary", "cvssData": {"version": "3.1", "baseScore": 3.5, "baseSeverity": "LOW", "vectorString": "CVSS:3.1/AV:A"}}]
                    }
                }
            }]
        }"#;
        let rec = parse_body(both, &id()).unwrap();
        assert_eq!(rec.cvss.unwrap().version, "3.1");

        let only = r#"{
            "totalResults": 1,
            "vulnerabilities": [{
                "cve": {
                    "descriptions": [{"lang": "en", "value": "v4 only"}],
                    "metrics": {
                        "cvssMetricV40": [{"type": "Primary", "cvssData": {"version": "4.0", "baseScore": 8.9, "baseSeverity": "HIGH", "vectorString": "CVSS:4.0/AV:N"}}]
                    }
                }
            }]
        }"#;
        let rec = parse_body(only, &id()).unwrap();
        let cvss = rec.cvss.unwrap();
        assert_eq!(cvss.version, "4.0");
        assert_eq!(cvss.score, 8.9);
        assert_eq!(cvss.severity, "HIGH");
    }

    #[test]
    fn missing_record_is_not_found() {
        let body = r#"{"totalResults": 0, "vulnerabilities": []}"#;
        match parse_body(body, &id()) {
            Err(NvdError::NotFound) => {}
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn escaped_colon_in_cpe_stays_in_the_product() {
        let parts = split_unescaped(r"cpe:2.3:a:acme:widget\:pro:1.0");
        assert_eq!(parts[3], "acme");
        assert_eq!(parts[4], "widget:pro");
    }
}
