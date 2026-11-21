use crate::cve::{self, CveId};

/// Where this request sits relative to `BASE_DOMAIN`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostClass {
    /// The apex, a raw IP, localhost, or any host when no base domain is set.
    Apex,
    /// `www.<base>`. The desk sends these to the apex.
    Www,
    /// A CVE label in front of the base domain.
    Cve(CveId),
    /// A single label under the base domain that is not a CVE id.
    Invalid { label: String },
}

/// How to write links for this response.
///
/// With no base domain, CVE links stay on paths (`/cve/CVE-...`) so localhost works.
/// With a base domain, CVE links are `scheme://cve-year-seq.base[:port]/`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Site {
    pub base_domain: Option<String>,
    pub scheme: String,
    pub port: Option<u16>,
    pub request_host: String,
}

impl Site {
    pub fn cve(&self, id: &CveId) -> String {
        match &self.base_domain {
            Some(base) => format!("{}/", self.origin(&subdomain_host(id, base))),
            None => format!("/cve/{id}"),
        }
    }

    /// Absolute URL for the print-ready PNG Teemill should fetch.
    pub fn print_png(&self, id: &CveId) -> String {
        match &self.base_domain {
            Some(_) => format!("{}print.png", self.cve(id)),
            None if !self.request_host.is_empty() => {
                format!("{}/cve/{id}/print.png", self.origin(&self.request_host))
            }
            None => format!("/cve/{id}/print.png"),
        }
    }


    pub fn cve_str(&self, id: &str) -> String {
        match cve::parse(id) {
            Ok(id) => self.cve(&id),
            Err(_) => format!("/cve/{id}"),
        }
    }

    /// Canonical URL for a dossier. Subdomain when a base domain is set.
    pub fn canonical_cve(&self, id: &CveId) -> Option<String> {
        if self.base_domain.is_some() {
            return Some(self.cve(id));
        }
        if self.request_host.is_empty() {
            return None;
        }
        Some(format!("{}/cve/{id}", self.origin(&self.request_host)))
    }

    pub fn home(&self) -> String {
        self.absolute_apex("/")
    }

    pub fn explore(&self) -> String {
        self.absolute_apex("/#explore")
    }

    pub fn random(&self) -> String {
        self.absolute_apex("/random")
    }

    pub fn lookup(&self) -> String {
        self.absolute_apex("/lookup")
    }

    /// Apex URL for a path that already starts with `/`.
    pub fn apex_url(&self, path: &str, query: &str) -> String {
        let path = if path.is_empty() { "/" } else { path };
        let mut url = self.absolute_apex(path);
        if !query.is_empty() {
            url.push('?');
            url.push_str(query);
        }
        url
    }

    fn absolute_apex(&self, path: &str) -> String {
        match &self.base_domain {
            Some(base) => format!("{}{path}", self.origin(base)),
            None => path.to_string(),
        }
    }

    fn origin(&self, host: &str) -> String {
        match self.port {
            Some(port) if !default_port(&self.scheme, port) => {
                format!("{}://{host}:{port}", self.scheme)
            }
            _ => format!("{}://{host}", self.scheme),
        }
    }
}

pub fn subdomain_host(id: &CveId, base: &str) -> String {
    format!("cve-{}-{}.{}", id.year, id.sequence, base).to_ascii_lowercase()
}

pub fn normalize_base(raw: &str) -> Option<String> {
    let mut text = raw.trim().to_ascii_lowercase();
    if let Some(rest) = text.strip_prefix("https://") {
        text = rest.to_string();
    } else if let Some(rest) = text.strip_prefix("http://") {
        text = rest.to_string();
    }
    if let Some((host, _)) = text.split_once('/') {
        text = host.to_string();
    }
    let (host, _) = split_host(&text);
    let host = host.trim().trim_matches('.').to_ascii_lowercase();
    if host.is_empty() || host.contains(' ') || host.contains('/') {
        None
    } else {
        Some(host)
    }
}

/// Classify `Host` and build the link style for the response.
pub fn interpret(
    base_domain: Option<&str>,
    host_header: Option<&str>,
    forwarded_proto: Option<&str>,
) -> (HostClass, Site) {
    let base = base_domain.and_then(normalize_base);
    let (hostname, port) = match host_header {
        Some(value) => split_host(value),
        None => (String::new(), None),
    };
    let hostname = hostname.trim().trim_matches('.').to_ascii_lowercase();
    let scheme = scheme_from(forwarded_proto, port);
    let class = classify(&hostname, base.as_deref());
    let site = Site {
        base_domain: base,
        scheme,
        port,
        request_host: hostname,
    };
    (class, site)
}

pub fn classify(hostname: &str, base: Option<&str>) -> HostClass {
    let Some(base) = base.filter(|value| !value.is_empty()) else {
        return HostClass::Apex;
    };
    if hostname.is_empty() || hostname == base {
        return HostClass::Apex;
    }
    if hostname == format!("www.{base}") {
        return HostClass::Www;
    }
    let suffix = format!(".{base}");
    let Some(label) = hostname.strip_suffix(&suffix) else {
        return HostClass::Apex;
    };
    if label.is_empty() || label.contains('.') {
        return HostClass::Invalid {
            label: label.to_string(),
        };
    }
    match parse_label(label) {
        Some(id) => HostClass::Cve(id),
        None => HostClass::Invalid {
            label: label.to_string(),
        },
    }
}

/// `cve-2021-44228` and `2021-44228`, case-insensitive.
pub fn parse_label(label: &str) -> Option<CveId> {
    let lower = label.trim().trim_matches('.').to_ascii_lowercase();
    if lower.is_empty() || lower.contains('.') {
        return None;
    }
    let candidate = if let Some(rest) = lower.strip_prefix("cve-") {
        format!("CVE-{rest}")
    } else {
        format!("CVE-{lower}")
    };
    cve::parse(&candidate).ok()
}

pub fn split_host(raw: &str) -> (String, Option<u16>) {
    let raw = raw.trim();
    if let Some(rest) = raw.strip_prefix('[') {
        if let Some((host, after)) = rest.split_once(']') {
            let port = after.strip_prefix(':').and_then(|value| value.parse().ok());
            return (host.to_string(), port);
        }
    }
    match raw.rsplit_once(':') {
        Some((host, port)) if !host.is_empty() && port.chars().all(|c| c.is_ascii_digit()) => {
            (host.to_string(), port.parse().ok())
        }
        _ => (raw.to_string(), None),
    }
}

fn scheme_from(forwarded_proto: Option<&str>, port: Option<u16>) -> String {
    if let Some(proto) = forwarded_proto {
        let first = proto.split(',').next().unwrap_or("").trim();
        if first.eq_ignore_ascii_case("https") {
            return "https".into();
        }
        if first.eq_ignore_ascii_case("http") {
            return "http".into();
        }
    }
    if port == Some(443) {
        "https".into()
    } else {
        "http".into()
    }
}

fn default_port(scheme: &str, port: u16) -> bool {
    (scheme == "https" && port == 443) || (scheme == "http" && port == 80)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_port_and_accepts_both_label_shapes() {
        let (class, site) = interpret(
            Some("example.test"),
            Some("CVE-2021-44228.Example.Test:8443"),
            None,
        );
        assert_eq!(class, HostClass::Cve(cve::parse("CVE-2021-44228").unwrap()));
        assert_eq!(site.port, Some(8443));
        assert_eq!(site.scheme, "http");
        assert_eq!(site.cve(&cve::parse("CVE-2021-44228").unwrap()), "http://cve-2021-44228.example.test:8443/");

        let (bare, _) = interpret(Some("example.test"), Some("2021-44228.example.test"), Some("https"));
        assert_eq!(bare, HostClass::Cve(cve::parse("CVE-2021-44228").unwrap()));
    }

    #[test]
    fn www_apex_and_invalid_labels() {
        assert_eq!(classify("www.example.test", Some("example.test")), HostClass::Www);
        assert_eq!(classify("example.test", Some("example.test")), HostClass::Apex);
        assert_eq!(classify("127.0.0.1", Some("example.test")), HostClass::Apex);
        assert!(matches!(
            classify("nope.example.test", Some("example.test")),
            HostClass::Invalid { .. }
        ));
        assert!(matches!(
            classify("a.b.example.test", Some("example.test")),
            HostClass::Invalid { .. }
        ));
        assert!(parse_label("cve-1998-0001").is_none());
        assert!(parse_label("cve-2021-160").is_none());
    }

    #[test]
    fn path_links_without_a_base_domain() {
        let (class, site) = interpret(None, Some("127.0.0.1:43123"), None);
        assert_eq!(class, HostClass::Apex);
        let id = cve::parse("CVE-2014-0160").unwrap();
        assert_eq!(site.cve(&id), "/cve/CVE-2014-0160");
        assert_eq!(site.random(), "/random");
        assert_eq!(site.canonical_cve(&id).as_deref(), Some("http://127.0.0.1:43123/cve/CVE-2014-0160"));
    }

    #[test]
    fn forwarded_proto_and_bracketed_ipv6() {
        let (host, port) = split_host("[::1]:43123");
        assert_eq!(host, "::1");
        assert_eq!(port, Some(43123));
        let (_, site) = interpret(Some("brandeveryvuln.com"), Some("brandeveryvuln.com"), Some("https, http"));
        assert_eq!(site.scheme, "https");
        assert_eq!(site.home(), "https://brandeveryvuln.com/");
        assert_eq!(normalize_base("https://Brandeveryvuln.com/path").as_deref(), Some("brandeveryvuln.com"));
    }
}
