use crate::brand::Draft;
use crate::cache;
use crate::host::Site;
use crate::model::{format_score, severity_class, Branding};
use crate::openrouter::Named;
use std::path::Path;

pub enum ExploreCard {
    Filed(Branding),
    Unfiled { id: String },
}

pub fn home(cards: &[ExploreCard], cache_dir: &Path, site: &Site) -> String {
    let mut body = String::new();
    body.push_str(r#"<section class="hero">
      <h1>
        <span class="sr">Every bug gets a name, website, logo, and T-shirt.</span>
        <span class="hero-title" aria-hidden="true">Every bug gets a <span class="swap"><span class="swap-word swap-name"><em>name</em>.</span><span class="swap-word swap-website"><em>website</em>.</span><span class="swap-word swap-logo"><em>logo</em>.</span><span class="swap-word swap-tshirt"><em>T-shirt</em>.</span></span></span>
      </h1>
      <p class="lede">Every vulnerability is important, beautiful, and valued. Some were given clever names, logos, and websites by their creators: Heartbleed was a heartbeat that read too far. Log4Shell was a log line that ran code. Most never got past the number. Until now, that is. Put in any CVE to coin a name and cut a logo. Every CVE is special and deserves its own website.</p>"#);
    body.push_str(&search_form(site));
    body.push_str(&format!(
        r#"<p class="hint">Enter a CVE to generate a site for it. Or <a href="{}">draw a CVE at random</a>.</p>
    </section>"#,
        esc(&site.random())
    ));

    body.push_str(r#"<section class="sec" id="explore">
      <p class="kicker">01 — Selected dossiers</p>
      <h2>Explore the names</h2>
      <div class="grid">"#);
    for item in cards {
        match item {
            ExploreCard::Filed(branding) => body.push_str(&card(branding, cache_dir, site)),
            ExploreCard::Unfiled { id } => body.push_str(&unfiled_card(id, site)),
        }
    }
    body.push_str("</div></section>");
    layout("Brand Every Vuln — a name for every CVE", &body, site, None)
}

pub fn cve_page(branding: &Branding, cache_dir: &Path, site: &Site, teemill_key: Option<&str>) -> String {
    let title = format!("{} · {} · Brand Every Vuln", branding.name, branding.cve_id);
    let canonical = crate::cve::parse(&branding.cve_id)
        .ok()
        .and_then(|id| site.canonical_cve(&id));
    layout(&title, &dossier(branding, cache_dir, None, site, teemill_key), site, canonical.as_deref())
}

pub fn trouble(status_word: &str, title: &str, message: &str, draft: Option<&Draft>, site: &Site) -> String {
    let mut body = String::new();
    body.push_str(r#"<article class="dossier">"#);
    body.push_str(&format!(
        r#"<p class="kicker">{}</p><h1>{}</h1><p class="blurb">{}</p>"#,
        esc(status_word),
        esc(title),
        esc(message)
    ));
    if let Some(draft) = draft {
        if let Some(named) = &draft.named {
            body.push_str(&format!(
                r#"<p class="unstamped">{}</p><p class="blurb">{}</p>"#,
                esc(&named.name),
                esc(&named.tagline)
            ));
            body.push_str(r#"<p class="note-block">That name was not filed. A retry asks again.</p>"#);
        }
        body.push_str(&nvd_block(&draft.nvd));
    }
    body.push_str(&search_form(site));
    body.push_str("</article>");
    layout(&format!("{title} · Brand Every Vuln"), &body, site, None)
}

fn dossier(branding: &Branding, cache_dir: &Path, _draft_name: Option<&Named>, site: &Site, teemill_key: Option<&str>) -> String {
    let mut body = String::new();
    body.push_str(r#"<article class="dossier"><div class="sheet-head"><span class="file-no">"#);
    body.push_str(&esc(&branding.cve_id));
    body.push_str("</span>");
    body.push_str(stamp(branding));
    body.push_str(r#"</div><div class="dossier-hero">"#);
    body.push_str(&plate(branding, cache_dir, true));
    body.push_str("<div>");
    let long = if branding.name.chars().count() > 16 {
        " class=\"long\""
    } else {
        ""
    };
    body.push_str(&format!("<h1{long}>{}</h1>", esc(&branding.name)));
    if !branding.tagline.is_empty() {
        body.push_str(&format!("<p class=\"tagline\">{}</p>", esc(&branding.tagline)));
    }
    if generated_offline(branding) {
        body.push_str(r#"<p class="offline-note">Generated offline</p>"#);
    }
    if !branding.blurb.is_empty() {
        body.push_str(&format!("<p class=\"blurb\">{}</p>", esc(&branding.blurb)));
    }
    body.push_str(r#"<p class="outlinks">"#);
    body.push_str(&format!(
        r#"<a href="{}" target="_blank" rel="noopener noreferrer">NVD entry</a>"#,
        esc(&branding.nvd_link())
    ));
    if let Some((url, label)) = branding.site_link() {
        body.push_str(&format!(
            r#"<a href="{}" target="_blank" rel="noopener noreferrer">{}</a>"#,
            esc(url),
            esc(label)
        ));
    }
    body.push_str("</p></div></div>");
    body.push_str(&metrics(branding));
    body.push_str(&merch(branding, cache_dir, site, teemill_key));
    body.push_str(&nvd_block(&branding.nvd));
    body.push_str(&format!("<p class=\"colophon\">{}</p>", esc(&colophon(branding))));
    body.push_str(&search_form(site));
    body.push_str("</article>");
    body
}

fn nvd_block(nvd: &crate::model::NvdRecord) -> String {
    let mut body = String::from(r#"<h2>What NVD says</h2>"#);
    let paragraphs = paragraphs(&nvd.description);
    if paragraphs.is_empty() {
        body.push_str(r#"<p class="desc">NVD has not published an English description.</p>"#);
    } else {
        for paragraph in paragraphs {
            body.push_str(&format!("<p class=\"desc\">{}</p>", esc(&paragraph)));
        }
    }
    let others: Vec<_> = nvd.affected.iter().skip(1).collect();
    if !others.is_empty() {
        let listed = others
            .iter()
            .take(6)
            .map(|p| format!("{} / {}", pretty(&p.vendor), pretty(&p.product)))
            .collect::<Vec<_>>()
            .join(", ");
        let extra = others.len().saturating_sub(6);
        let more = if extra > 0 {
            format!(" and {extra} more")
        } else {
            String::new()
        };
        body.push_str(&format!(
            r#"<p class="also">Also named in the CPE data: {}{}.</p>"#,
            esc(&listed),
            esc(&more)
        ));
    }
    if let Some(cvss) = &nvd.cvss {
        if !cvss.vector.is_empty() {
            body.push_str(&format!(
                r#"<p class="vector">{}</p>"#,
                esc(&cvss.vector)
            ));
        }
    } else {
        body.push_str(r#"<p class="vector">No CVSS vector is published for this id.</p>"#);
    }
    body
}

fn metrics(branding: &Branding) -> String {
    let (score, severity, class, version) = match &branding.nvd.cvss {
        Some(cvss) => (
            format_score(cvss.score),
            cvss.severity.clone(),
            severity_class(&cvss.severity),
            format!("CVSS {}", cvss.version),
        ),
        None => ("—".into(), "Not scored".into(), "sev-unknown", "CVSS".into()),
    };
    let vendor = branding
        .nvd
        .vendor
        .as_deref()
        .map(pretty)
        .unwrap_or_else(|| "Not listed".into());
    let product = branding
        .nvd
        .product
        .as_deref()
        .map(pretty)
        .unwrap_or_else(|| "Not listed".into());
    format!(
        r#"<dl class="metrics">
          <div><dt>{version}</dt><dd class="score {class}">{score}</dd></div>
          <div><dt>Severity</dt><dd class="{class}">{severity}</dd></div>
          <div><dt>Vendor</dt><dd class="product">{vendor}</dd></div>
          <div><dt>Product</dt><dd class="product">{product}</dd></div>
        </dl>"#,
        version = esc(&version),
        class = class,
        score = esc(&score),
        severity = esc(&severity),
        vendor = esc(&vendor),
        product = esc(&product),
    )
}

fn generated_offline(branding: &Branding) -> bool {
    !branding.prefilled
        && (branding.naming_source == "offline" || branding.logo_source == "offline")
}

fn stamp(branding: &Branding) -> &'static str {
    if branding.prefilled {
        r#"<span class="stamp stamp-file">On file</span>"#
    } else {
        r#"<span class="stamp stamp-new">Just coined</span>"#
    }
}

fn colophon(branding: &Branding) -> String {
    let when = or_dash(&branding.created_at);
    if branding.prefilled {
        let credit = public_credit(branding.logo_credit.as_deref()).unwrap_or_else(|| {
            "No separate logo was published under a license this desk can keep.".to_string()
        });
        return format!("This is the name it already had. Filed {when}. {credit}");
    }
    let name_offline = branding.naming_source == "offline";
    let logo_offline = branding.logo_source == "offline";
    if name_offline && logo_offline {
        format!("Name and mark generated offline from the NVD record. Filed {when}. Not an official vendor mark.")
    } else if name_offline {
        format!("Name drawn offline from the wordlist. Mark generated for this CVE. Filed {when}. Not an official vendor mark.")
    } else if logo_offline {
        format!("Name generated for this CVE. Mark drawn offline. Filed {when}. Not an official vendor mark.")
    } else {
        format!("Name and mark generated for this CVE. Filed {when}. Not an official vendor mark.")
    }
}

/// Credit shown on the page. Saved branding may name a model; the HTML does not.
fn public_credit(credit: Option<&str>) -> Option<String> {
    let credit = credit.map(str::trim).filter(|s| !s.is_empty())?;
    if mentions_model(credit) {
        Some("Name and mark generated for this CVE. Not an official vendor mark.".into())
    } else {
        Some(credit.to_string())
    }
}

fn mentions_model(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    lower.contains("llama") || lower.contains("recraft") || lower.contains("openrouter")
}

fn card(branding: &Branding, cache_dir: &Path, site: &Site) -> String {
    format!(
        r#"<a class="card" href="{href}">{plate}<div class="card-meta"><p class="id">{id}</p><h3>{name}</h3></div></a>"#,
        href = esc(&site.cve_str(&branding.cve_id)),
        id = esc(&branding.cve_id),
        plate = plate(branding, cache_dir, false),
        name = esc(&branding.name),
    )
}

fn unfiled_card(id: &str, site: &Site) -> String {
    format!(
        r#"<a class="card card-unfiled" href="{href}"><div class="plate monogram" aria-hidden="true"><span>?</span></div><div class="card-meta"><p class="id">{id}</p><h3>Not named yet</h3><p class="card-sub">Click to generate</p></div></a>"#,
        href = esc(&site.cve_str(id)),
        id = esc(id),
    )
}


fn merch(branding: &Branding, cache_dir: &Path, site: &Site, teemill_key: Option<&str>) -> String {
    if branding.prefilled {
        return String::new();
    }
    if teemill_key.filter(|k| !k.is_empty()).is_none() {
        return String::new();
    }
    let Ok(id) = crate::cve::parse(&branding.cve_id) else {
        return String::new();
    };
    let Some(file) = branding.logo_file.as_deref() else {
        return String::new();
    };
    if cache::logo_path(cache_dir, &id, file).is_none() {
        return String::new();
    }
    format!(
        r#"<section class="merch">
  <div class="shirt" aria-hidden="true">
    <svg class="shirt-svg" viewBox="0 0 200 220" xmlns="http://www.w3.org/2000/svg">
      <defs>
        <clipPath id="shirt-print">
          <rect x="62" y="78" width="76" height="76" rx="6"/>
        </clipPath>
      </defs>
      <path class="shirt-body" d="M72 42c2-18 54-18 56 0l26 16 36 26-22 28-14-10v86H46V102L32 112 10 84l36-26z"/>
      <path class="shirt-collar" d="M82 42c6 14 30 14 36 0"/>
      <rect class="shirt-print-bg" x="62" y="78" width="76" height="76" rx="6"/>
      <image href="/cve/{cve}/logo" x="66" y="82" width="68" height="68" preserveAspectRatio="xMidYMid meet" clip-path="url(#shirt-print)"/>
    </svg>
  </div>
  <div class="merch-copy">
    <a class="shirt-buy" href="{href}">Purchase this on a T-shirt</a>
  </div>
</section>"#,
        cve = esc(&branding.cve_id),
        href = esc(&site.shirt(&id)),
    )
}

pub fn shirt_error(title: &str, message: &str, dossier_url: &str, site: &Site) -> String {
    let mut body = String::new();
    body.push_str(r#"<article class="dossier">"#);
    body.push_str(&format!(
        r#"<p class="kicker">T-shirt</p><h1>{}</h1><p class="blurb">{}</p><p><a href="{}">Back to the dossier</a></p>"#,
        esc(title),
        esc(message),
        esc(dossier_url),
    ));
    body.push_str(&search_form(site));
    body.push_str("</article>");
    layout(&format!("{title} · Brand Every Vuln"), &body, site, None)
}

fn plate(branding: &Branding, cache_dir: &Path, large: bool) -> String {
    let class = if large { "plate plate-lg" } else { "plate" };
    let has_logo = branding.logo_file.as_deref().and_then(|name| {
        crate::cve::parse(&branding.cve_id)
            .ok()
            .and_then(|id| cache::logo_path(cache_dir, &id, name))
    });
    if has_logo.is_some() {
        format!(
            r#"<div class="{class}"><img src="/cve/{id}/logo" alt="{alt} logo"></div>"#,
            id = esc(&branding.cve_id),
            alt = esc(&branding.name),
        )
    } else {
        format!(
            r#"<div class="{class} monogram" aria-hidden="true"><span>{}</span></div>"#,
            esc(&initials(&branding.name))
        )
    }
}

fn search_form(site: &Site) -> String {
    format!(
        r#"<form class="search" action="{action}" method="get">
      <label class="sr" for="cve-id">CVE identifier</label>
      <input id="cve-id" name="id" placeholder="CVE-2026-0001" autocomplete="off" spellcheck="false" autocapitalize="characters" maxlength="22" required>
      <button type="submit">Name it</button>
    </form>"#,
        action = esc(&site.lookup()),
    )
}

fn layout(title: &str, body: &str, site: &Site, canonical: Option<&str>) -> String {
    let canonical = canonical
        .map(|url| format!(r#"<link rel="canonical" href="{}">"#, esc(url)))
        .unwrap_or_default();
    let base_attr = site
        .base_domain
        .as_deref()
        .map(|base| format!(r#" data-base-domain="{}""#, esc(base)))
        .unwrap_or_default();
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<meta name="description" content="Brand Every Vuln gives every CVE a name, logo, and website.">
<meta property="og:site_name" content="Brand Every Vuln">
<meta property="og:title" content="{title}">
<meta property="og:description" content="Brand Every Vuln gives every CVE a name, logo, and website.">
{canonical}
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<link rel="stylesheet" href="/static/app.css">
<script src="/static/app.js" defer></script>
</head>
<body{base_attr}>
<div class="frame">
<header class="top">
  <a class="word" href="{home}"><span class="seal" aria-hidden="true"></span>Brand Every Vuln</a>
  <nav>
    <a href="{explore}">Explore</a>
    <a class="btn" href="{random}">Random CVE</a>
  </nav>
</header>
{body}
<footer class="foot">
  <p>Famous names on the wall are the real ones. Anything else is named on the first request and saved.</p>
  <p>Descriptions and scores come from the NVD CVE 2.0 API.</p>
</footer>
</div>
</body>
</html>"#,
        title = esc(title),
        base_attr = base_attr,
        home = esc(&site.home()),
        explore = esc(&site.explore()),
        random = esc(&site.random()),
    )
}

fn paragraphs(text: &str) -> Vec<String> {
    text.split("\n\n")
        .map(|block| block.split_whitespace().collect::<Vec<_>>().join(" "))
        .filter(|line| !line.is_empty())
        .collect()
}

fn pretty(value: &str) -> String {
    value.replace('_', " ")
}

fn initials(name: &str) -> String {
    let mut out = String::new();
    for word in name.split_whitespace() {
        if let Some(ch) = word.chars().find(|c| c.is_ascii_alphabetic()) {
            out.push(ch.to_ascii_uppercase());
        }
        if out.chars().count() == 2 {
            break;
        }
    }
    if out.is_empty() {
        out.push('·');
    }
    out
}

fn or_dash(value: &str) -> &str {
    if value.is_empty() { "an unknown time" } else { value }
}

pub fn esc(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(ch),
        }
    }
    out
}

pub const FAVICON: &str = r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32">
<rect width="32" height="32" fill="#14110e"/>
<rect x="6" y="6" width="20" height="20" fill="#f4efe4"/>
<rect x="6" y="6" width="8" height="8" fill="#e23b2b"/>
</svg>"##;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::sample;

    #[test]
    fn escapes_markup_in_the_description() {
        let mut branding = sample("CVE-2026-0001", "Latchlight");
        branding.nvd.description = "A <script>alert(1)</script> bug.".into();
        branding.tagline = "Quotes \" and <angles>".into();
        let html = cve_page(&branding, Path::new("/nope"), &crate::host::Site {
            base_domain: None,
            scheme: "http".into(),
            port: Some(43123),
            request_host: "127.0.0.1".into(),
        }, None);
        assert!(!html.contains("<script>"));
        assert!(html.contains("&lt;script&gt;"));
        assert!(html.contains("&quot;"));
        assert!(html.contains("Latchlight"));
        assert!(html.contains("7.5"));
    }

    #[test]
    fn home_renders_explore_section_with_cards() {
        let mut filed = sample("CVE-2014-0160", "Heartbleed");
        filed.prefilled = true;
        let cards = vec![
            ExploreCard::Filed(filed),
            ExploreCard::Unfiled { id: "CVE-2026-1337".into() },
        ];
        let site = crate::host::Site {
            base_domain: Some("brandeveryvuln.com".into()),
            scheme: "https".into(),
            port: None,
            request_host: "brandeveryvuln.com".into(),
        };
        let page = home(&cards, Path::new("/nope"), &site);
        assert!(page.contains("Explore the names"));
        assert!(page.contains("Every bug gets a name, website, logo, and T-shirt."));
        assert!(page.contains(r#"<span class="swap-word swap-name"><em>name</em>.</span>"#));
        assert!(page.contains(r#"<span class="swap-word swap-website"><em>website</em>.</span>"#));
        assert!(page.contains(r#"<span class="swap-word swap-logo"><em>logo</em>.</span>"#));
        assert!(page.contains(r#"<span class="swap-word swap-tshirt"><em>T-shirt</em>.</span>"#));
        assert!(page.contains(r#"aria-hidden="true""#));
        assert!(page.contains("data-base-domain=\"brandeveryvuln.com\""));
        assert!(page.contains(r#"<script src="/static/app.js" defer></script>"#));
        assert!(page.contains("https://cve-2014-0160.brandeveryvuln.com/"));
        assert!(page.contains("https://cve-2026-1337.brandeveryvuln.com/"));
        assert!(page.contains("Not named yet"));
        assert!(page.contains("Click to generate"));
        assert!(!page.contains("Names that stuck"));
    }

    #[test]
    fn generated_pages_offer_a_shirt_when_a_logo_and_key_are_present() {
        let mut branding = sample("CVE-2026-1337", "CharSlice");
        branding.logo_file = Some("logo.webp".into());
        branding.tagline = "A thin slice of a query log.".into();
        let dir = std::env::temp_dir().join("bev-merch-test");
        let dossier = dir.join("2026").join("1337");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dossier).unwrap();
        std::fs::write(dossier.join("logo.webp"), b"not-a-real-image").unwrap();
        let site = crate::host::Site {
            base_domain: Some("brandeveryvuln.com".into()),
            scheme: "https".into(),
            port: None,
            request_host: "cve-2026-1337.brandeveryvuln.com".into(),
        };
        let page = cve_page(&branding, &dir, &site, Some("test-teemill-key"));
        assert!(page.contains("Purchase this on a T-shirt"));
        assert!(page.contains("https://cve-2026-1337.brandeveryvuln.com/shirt"));
        assert!(page.contains(r#"<a class="shirt-buy""#));
        assert!(!page.contains("data-teemill-key"));
        assert!(!page.contains("teemill.com/omnis"));
        branding.prefilled = true;
        let famous = cve_page(&branding, &dir, &site, Some("test-teemill-key"));
        assert!(!famous.contains("Purchase this on a T-shirt"));
        assert!(!famous.contains("/shirt"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn assert_no_model_ids(html: &str) {
        let lower = html.to_ascii_lowercase();
        for needle in ["llama", "recraft", "openrouter"] {
            assert!(
                !lower.contains(needle),
                "page leaked {needle}: {}",
                html
            );
        }
    }

    fn test_site() -> crate::host::Site {
        crate::host::Site {
            base_domain: Some("brandeveryvuln.com".into()),
            scheme: "https".into(),
            port: None,
            request_host: "brandeveryvuln.com".into(),
        }
    }

    #[test]
    fn generated_pages_do_not_name_models() {
        let mut branding = sample("CVE-2026-0001", "Ghostpage");
        branding.logo_credit = Some(
            "Generated by recraft/recraft-v4.1-flash-v2 for this name. Not an official vendor mark."
                .into(),
        );
        let page = cve_page(&branding, Path::new("/nope"), &test_site(), None);
        assert!(page.contains(
            "Name and mark generated for this CVE. Filed 2026-11-21T00:00:00Z. Not an official vendor mark."
        ));
        assert!(!page.contains("Coined "));
        assert!(!page.contains("Mark cut by"));
        assert_no_model_ids(&page);
    }

    #[test]
    fn offline_pages_keep_the_fallback_note_without_model_ids() {
        let mut branding = sample("CVE-2026-0001", "Ghostpage");
        branding.naming_source = "offline".into();
        branding.logo_source = "recraft".into();
        let named_offline = cve_page(&branding, Path::new("/nope"), &test_site(), None);
        assert!(named_offline.contains("Name drawn offline from the wordlist."));
        assert!(named_offline.contains("Mark generated for this CVE."));
        assert!(named_offline.contains("Generated offline"));
        assert_no_model_ids(&named_offline);

        branding.naming_source = "model".into();
        branding.logo_source = "offline".into();
        let mark_offline = cve_page(&branding, Path::new("/nope"), &test_site(), None);
        assert!(mark_offline.contains("Name generated for this CVE."));
        assert!(mark_offline.contains("Mark drawn offline."));
        assert_no_model_ids(&mark_offline);

        branding.naming_source = "offline".into();
        branding.logo_source = "offline".into();
        let both = cve_page(&branding, Path::new("/nope"), &test_site(), None);
        assert!(both.contains("Name and mark generated offline from the NVD record."));
        assert_no_model_ids(&both);
    }

    #[test]
    fn prefilled_credits_keep_license_text_and_drop_model_ids() {
        let mut branding = sample("CVE-2014-0160", "Heartbleed");
        branding.prefilled = true;
        branding.logo_credit =
            Some("Heartbleed logo by Leena Kurjenniska / Codenomicon, CC0, from heartbleed.com.".into());
        let page = cve_page(&branding, Path::new("/nope"), &test_site(), None);
        assert!(page.contains("This is the name it already had."));
        assert!(page.contains("Heartbleed logo by Leena Kurjenniska / Codenomicon, CC0, from heartbleed.com."));
        assert_no_model_ids(&page);

        branding.logo_credit = Some(
            "Generated by recraft/recraft-v4.1-flash-v2 for this name. Not an official vendor mark."
                .into(),
        );
        let sanitized = cve_page(&branding, Path::new("/nope"), &test_site(), None);
        assert!(sanitized.contains("Name and mark generated for this CVE. Not an official vendor mark."));
        assert_no_model_ids(&sanitized);
    }

    #[test]
    fn home_page_does_not_name_models() {
        let mut filed = sample("CVE-2014-0160", "Heartbleed");
        filed.prefilled = true;
        let page = home(
            &[ExploreCard::Filed(filed), ExploreCard::Unfiled { id: "CVE-2026-1337".into() }],
            Path::new("/nope"),
            &test_site(),
        );
        assert_no_model_ids(&page);
    }
}
