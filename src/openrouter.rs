use std::time::Duration;

use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};

use crate::cve::CveId;
use crate::model::NvdRecord;

pub const NAMING_MODEL: &str = "meta-llama/llama-3.1-8b-instruct";
pub const IMAGE_MODEL: &str = "recraft/recraft-v4.1-flash-v2";

const CHAT_URL: &str = "https://openrouter.ai/api/v1/chat/completions";
const IMAGE_URL: &str = "https://openrouter.ai/api/v1/images";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Named {
    pub name: String,
    pub tagline: String,
    pub blurb: String,
    pub logo_prompt: String,
    pub source: &'static str,
}

pub struct ImageCut {
    pub bytes: Vec<u8>,
    pub ext: &'static str,
}

pub struct OpenRouter {
    agent: ureq::Agent,
}

impl OpenRouter {
    pub fn new() -> Self {
        let agent = ureq::AgentBuilder::new()
            .timeout_connect(Duration::from_secs(15))
            .timeout_read(Duration::from_secs(120))
            .user_agent("BrandEveryVuln/0.1")
            .build();
        Self { agent }
    }

    pub fn coin_name(
        &self,
        key: &str,
        id: &CveId,
        nvd: &NvdRecord,
        taken: impl Fn(&str) -> bool,
    ) -> Result<Named, String> {
        let prompt = naming_prompt(id, nvd);
        let body = json!({
            "model": NAMING_MODEL,
            "temperature": 0.6,
            "max_tokens": 600,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt}
            ]
        });
        match post_json(&self.agent, CHAT_URL, key, &body) {
            Ok(value) => {
                let text = message_text(&value).unwrap_or_default();
                if text.trim().is_empty() {
                    eprintln!("name {id}: empty model response, using offline wordlist");
                    return Ok(offline_named(id, nvd));
                }
                Ok(interpret_naming(&text, &id.as_id(), &nvd.description, taken))
            }
            Err(err) => Err(err),
        }
    }

    pub fn cut_logo(&self, key: &str, named: &Named) -> Result<ImageCut, String> {
        let prompt = logo_prompt(named);
        let full = json!({
            "model": IMAGE_MODEL,
            "prompt": prompt,
            "n": 1,
            "aspect_ratio": "1:1"
        });
        let value = match post_json(&self.agent, IMAGE_URL, key, &full) {
            Ok(value) => value,
            Err(err) if err.starts_with("HTTP 400") => {
                eprintln!("logo rejected aspect_ratio, retrying with prompt only");
                let bare = json!({"model": IMAGE_MODEL, "prompt": prompt});
                post_json(&self.agent, IMAGE_URL, key, &bare)?
            }
            Err(err) => return Err(err),
        };
        decode_image(&self.agent, &value)
    }
}

const SYSTEM_PROMPT: &str = "\
You name software vulnerabilities the way Heartbleed, Shellshock, Log4Shell, Spectre, and Dirty COW were named.

Rules:
- Invent an original name. Never reuse Heartbleed, Shellshock, Bashdoor, Log4Shell, Spectre, Meltdown, POODLE, EternalBlue, BlueKeep, Dirty COW, GHOST, Stagefright, DROWN, KRACK, Zerologon, regreSSHion, or WannaCry.
- One to three words. Title Case or an expressive compound. No CVE id. No version numbers.
- Do not use the words Critical, Vulnerability, Flaw, Bug, Issue, CVE, RCE, or Unauthenticated as the name.
- Hint at the mechanism or a metaphor. Do not describe the severity.
- tagline: one sentence, under 120 characters, concrete.
- blurb: two sentences, under 320 characters, plain language.
- logo_prompt: one sentence describing a single iconic symbol for a square logo. No letters, no words, no watermark. Name the shapes and two or three colors.

Return only a JSON object with the keys name, tagline, blurb, and logo_prompt. No markdown.";

fn naming_prompt(id: &CveId, nvd: &NvdRecord) -> String {
    let vendor = nvd.vendor.as_deref().unwrap_or("not listed");
    let product = nvd.product.as_deref().unwrap_or("not listed");
    let others = nvd
        .affected
        .iter()
        .skip(1)
        .take(5)
        .map(|p| format!("{}/{}", p.vendor, p.product))
        .collect::<Vec<_>>()
        .join(", ");
    let cvss = match &nvd.cvss {
        Some(c) => format!(
            "CVSS {} base score {} {} vector {}",
            c.version,
            format_score(c.score),
            c.severity,
            c.vector
        ),
        None => "CVSS: not scored in NVD.".into(),
    };
    let description = clip_chars(&nvd.description, 1500);
    format!(
        "Generate a branding name for {id}.\nDescription: {description}\nVendor: {vendor}\nProduct: {product}\nOther affected products: {others}\n{cvss}\n"
    )
}

fn format_score(score: f64) -> String {
    format!("{score:.1}")
}

pub fn interpret_naming(
    raw: &str,
    cve_id: &str,
    description: &str,
    taken: impl Fn(&str) -> bool,
) -> Named {
    let cleaned = strip_fences(raw);
    if let Some(slice) = extract_json_object(&cleaned) {
        if let Ok(value) = serde_json::from_str::<Value>(slice) {
            if let Some(named) = named_from_value(&value, cve_id, description, &taken) {
                return named;
            }
        }
    }
    // The model sometimes wraps the object in prose or smart quotes.
    let softened = cleaned
        .replace(['“', '”'], "\"")
        .replace(['‘', '’'], "'");
    if let Some(slice) = extract_json_object(&softened) {
        if let Ok(value) = serde_json::from_str::<Value>(slice) {
            if let Some(named) = named_from_value(&value, cve_id, description, &taken) {
                return named;
            }
        }
    }
    eprintln!("name parse failed, using offline wordlist. raw={}", clip_chars(raw, 400));
    offline_named_from(cve_id, description)
}

fn named_from_value(
    value: &Value,
    cve_id: &str,
    description: &str,
    taken: &impl Fn(&str) -> bool,
) -> Option<Named> {
    let obj = value.as_object().or_else(|| {
        value
            .as_array()
            .and_then(|a| a.first())
            .and_then(|v| v.as_object())
    })?;
    let name = field(obj, &["name", "title", "brand"])?;
    let name = clean_name(&name, cve_id, taken)?;
    let tagline = field(obj, &["tagline", "slogan", "line"]).unwrap_or_default();
    let blurb = field(obj, &["blurb", "description", "summary"]).unwrap_or_default();
    let logo = field(obj, &["logo_prompt", "logo_concept", "prompt"]).unwrap_or_default();
    let tagline = tidy_sentence(&tagline, 160).unwrap_or_else(|| fallback_tagline(description));
    let blurb = tidy_sentence(&blurb, 420).unwrap_or_else(|| clip_chars(description, 280));
    let logo_prompt = if logo.trim().is_empty() {
        default_logo_prompt(&name)
    } else {
        clip_chars(&logo, 400)
    };
    Some(Named {
        name,
        tagline,
        blurb,
        logo_prompt,
        source: "model",
    })
}

fn field(obj: &serde_json::Map<String, Value>, keys: &[&str]) -> Option<String> {
    for key in keys {
        if let Some(value) = obj.get(*key) {
            let text = match value {
                Value::String(s) => s.clone(),
                Value::Number(n) => n.to_string(),
                _ => continue,
            };
            if !text.trim().is_empty() {
                return Some(text);
            }
        }
    }
    None
}

fn clean_name(raw: &str, cve_id: &str, taken: &impl Fn(&str) -> bool) -> Option<String> {
    let trimmed = raw.trim().trim_matches(|c| c == '"' || c == '\'' || c == '.');
    let trimmed = trimmed.trim();
    if trimmed.is_empty() || trimmed.chars().count() > 36 {
        return None;
    }
    if trimmed.to_ascii_uppercase().starts_with("CVE-") {
        return None;
    }
    let words: Vec<&str> = trimmed.split_whitespace().collect();
    if words.is_empty() || words.len() > 3 {
        return None;
    }
    if !words.iter().all(|w| valid_word(w)) {
        return None;
    }
    const GENERIC: &[&str] = &[
        "vulnerability",
        "critical",
        "unnamed",
        "exploit",
        "bug",
        "flaw",
        "issue",
        "cve",
        "rce",
        "severe",
        "unauthenticated",
    ];
    if words.len() == 1 && GENERIC.contains(&words[0].to_ascii_lowercase().as_str()) {
        return None;
    }
    if taken(trimmed) {
        return None;
    }
    if trimmed.eq_ignore_ascii_case(cve_id) {
        return None;
    }
    Some(words.join(" "))
}

fn valid_word(word: &str) -> bool {
    let chars: Vec<char> = word.chars().collect();
    if chars.len() < 2 || chars.len() > 20 {
        return false;
    }
    if !chars.iter().any(|c| c.is_ascii_alphabetic()) {
        return false;
    }
    chars.iter().all(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '\'')
}

fn offline_named(id: &CveId, nvd: &NvdRecord) -> Named {
    offline_named_from(&id.as_id(), &nvd.description)
}

fn offline_named_from(cve_id: &str, description: &str) -> Named {
    let record = NvdRecord {
        description: description.to_string(),
        ..NvdRecord::default()
    };
    let coined = crate::offline::coin(&record, cve_id);
    Named {
        logo_prompt: default_logo_prompt(&coined.name),
        tagline: coined.tagline,
        blurb: coined.blurb,
        name: coined.name,
        source: "offline",
    }
}

fn fallback_tagline(description: &str) -> String {
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

fn default_logo_prompt(name: &str) -> String {
    format!(
        "A single bold geometric emblem for a mark called {name}: a cracked seal formed from a circle and a wedge, flat vector, centered, solid deep-ink background, cream and signal-red only"
    )
}

fn logo_prompt(named: &Named) -> String {
    format!(
        "Square logo mark for a software vulnerability called \"{}\". {}. Flat vector, one bold centered symbol, generous padding, solid background, no text, no letters, no numbers, no watermark, no photorealism, crisp edges.",
        named.name.replace('"', ""),
        named.logo_prompt.trim()
    )
}

fn tidy_sentence(text: &str, max: usize) -> Option<String> {
    let collapsed = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if collapsed.is_empty() {
        return None;
    }
    Some(clip_chars(&collapsed, max))
}

fn strip_fences(text: &str) -> String {
    let trimmed = text.trim();
    let Some(rest) = trimmed.strip_prefix("```") else {
        return trimmed.to_string();
    };
    let rest = rest.trim_start_matches(|c: char| c != '\n');
    let rest = rest.trim_start_matches('\n');
    match rest.rfind("```") {
        Some(end) => rest[..end].trim().to_string(),
        None => rest.trim().to_string(),
    }
}

fn extract_json_object(text: &str) -> Option<&str> {
    let start = text.find('{')?;
    let bytes = text.as_bytes();
    let mut depth = 0i32;
    let mut in_string = false;
    let mut escaped = false;
    for (idx, &byte) in bytes.iter().enumerate().skip(start) {
        if in_string {
            if escaped {
                escaped = false;
                continue;
            }
            if byte == b'\\' {
                escaped = true;
                continue;
            }
            if byte == b'"' {
                in_string = false;
            }
            continue;
        }
        match byte {
            b'"' => in_string = true,
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(&text[start..=idx]);
                }
            }
            _ => {}
        }
    }
    None
}

fn message_text(value: &Value) -> Option<String> {
    let content = value.pointer("/choices/0/message/content")?;
    match content {
        Value::String(text) => Some(text.clone()),
        Value::Array(parts) => {
            let mut out = String::new();
            for part in parts {
                if let Some(text) = part.get("text").and_then(|t| t.as_str()) {
                    out.push_str(text);
                } else if let Some(text) = part.as_str() {
                    out.push_str(text);
                }
            }
            if out.is_empty() {
                None
            } else {
                Some(out)
            }
        }
        _ => None,
    }
}

fn decode_image(agent: &ureq::Agent, value: &Value) -> Result<ImageCut, String> {
    if let Some(message) = value.pointer("/error/message").and_then(|v| v.as_str()) {
        return Err(format!("OpenRouter image error: {}", clip_chars(&scrub(message), 300)));
    }
    let first = value
        .get("data")
        .and_then(|v| v.as_array())
        .and_then(|a| a.first())
        .ok_or_else(|| "OpenRouter returned no image.".to_string())?;
    let media = first.get("media_type").and_then(|v| v.as_str());
    if let Some(url) = first.get("url").and_then(|v| v.as_str()) {
        if url.starts_with("https://") {
            let bytes = download(agent, url)?;
            let ext = sniff(&bytes, media).ok_or_else(|| "The image URL was not a known image.".to_string())?;
            return Ok(ImageCut { bytes, ext });
        }
    }
    let b64 = first
        .get("b64_json")
        .or_else(|| first.get("b64"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| "OpenRouter returned an image with neither bytes nor a URL.".to_string())?;
    let b64 = b64.trim();
    let b64 = b64.split("base64,").last().unwrap_or(b64);
    let bytes = STANDARD
        .decode(b64.trim())
        .map_err(|e| format!("could not decode the logo: {e}"))?;
    if bytes.len() < 32 {
        return Err("the logo was empty.".into());
    }
    let ext = sniff(&bytes, media).ok_or_else(|| "the logo was not a png, jpeg, webp, gif, or svg.".to_string())?;
    Ok(ImageCut { bytes, ext })
}

fn download(agent: &ureq::Agent, url: &str) -> Result<Vec<u8>, String> {
    let resp = agent
        .get(url)
        .call()
        .map_err(|e| format!("could not download the logo: {}", scrub(&e.to_string())))?;
    let mut buf = Vec::new();
    resp.into_reader()
        .take(8 * 1024 * 1024)
        .read_to_end(&mut buf)
        .map_err(|e| format!("could not read the logo: {e}"))?;
    Ok(buf)
}

fn sniff(bytes: &[u8], media: Option<&str>) -> Option<&'static str> {
    if bytes.starts_with(b"\x89PNG") {
        return Some("png");
    }
    if bytes.starts_with(&[0xFF, 0xD8, 0xFF]) {
        return Some("jpg");
    }
    if bytes.len() > 12 && &bytes[..4] == b"RIFF" && &bytes[8..12] == b"WEBP" {
        return Some("webp");
    }
    if bytes.starts_with(b"GIF8") {
        return Some("gif");
    }
    let head = String::from_utf8_lossy(&bytes[..bytes.len().min(80)]).to_ascii_lowercase();
    if head.contains("<svg") || head.contains("<?xml") {
        return Some("svg");
    }
    match media {
        Some("image/png") => Some("png"),
        Some("image/jpeg") => Some("jpg"),
        Some("image/webp") => Some("webp"),
        Some("image/gif") => Some("gif"),
        Some("image/svg+xml") => Some("svg"),
        _ => None,
    }
}

enum CallFail {
    Retry(String),
    Fatal(String),
}

fn post_json(agent: &ureq::Agent, url: &str, key: &str, body: &Value) -> Result<Value, String> {
    let payload = serde_json::to_string(body).map_err(|e| e.to_string())?;
    let mut last = String::from("OpenRouter did not answer");
    for attempt in 0..3 {
        match send(agent, url, key, &payload) {
            Ok(text) => {
                return serde_json::from_str(&text).map_err(|_| {
                    format!("OpenRouter returned non-JSON: {}", clip_chars(&scrub(&text), 300))
                });
            }
            Err(CallFail::Fatal(msg)) => return Err(msg),
            Err(CallFail::Retry(msg)) => {
                last = msg;
                std::thread::sleep(Duration::from_millis(700 * (attempt as u64 + 1)));
            }
        }
    }
    Err(last)
}

fn send(agent: &ureq::Agent, url: &str, key: &str, payload: &str) -> Result<String, CallFail> {
    let result = agent
        .post(url)
        .set("Authorization", &format!("Bearer {key}"))
        .set("Content-Type", "application/json")
        .set("X-Title", "BrandEveryVuln")
        .send_string(payload);
    match result {
        Ok(resp) => resp
            .into_string()
            .map_err(|e| CallFail::Retry(format!("could not read OpenRouter: {e}"))),
        Err(ureq::Error::Status(code, resp)) => {
            let text = scrub(&resp.into_string().unwrap_or_default());
            let msg = format!("HTTP {code}: {}", clip_chars(&text, 300));
            if matches!(code, 429 | 500 | 502 | 503 | 504) {
                Err(CallFail::Retry(msg))
            } else if code == 401 {
                Err(CallFail::Fatal(
                    "OpenRouter refused the API key. Check OPENROUTER_API_KEY.".into(),
                ))
            } else if code == 402 {
                Err(CallFail::Fatal(
                    "OpenRouter has no credits left, so the mark could not be cut.".into(),
                ))
            } else {
                Err(CallFail::Fatal(msg))
            }
        }
        Err(err) => Err(CallFail::Retry(format!(
            "could not reach OpenRouter: {}",
            scrub(&err.to_string())
        ))),
    }
}

fn scrub(text: &str) -> String {
    let mut out = text.to_string();
    while let Some(start) = out.find("sk-or-") {
        let rest = &out[start..];
        let end_rel = rest
            .find(|c: char| c.is_whitespace() || c == '"' || c == '\'')
            .unwrap_or(rest.len().min(90));
        out.replace_range(start..start + end_rel, "[redacted]");
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

use std::io::Read;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_fenced_json_and_rejects_a_stolen_name() {
        let raw = "```json\n{\"name\":\"Heartbleed\",\"tagline\":\"nope\",\"blurb\":\"nope\",\"logo_prompt\":\"a heart\"}\n```";
        let named = interpret_naming(raw, "CVE-2026-0001", "A use after free.", |n| {
            n.eq_ignore_ascii_case("heartbleed")
        });
        assert_eq!(named.source, "offline");
        assert_ne!(named.name.to_ascii_lowercase(), "heartbleed");
        assert!(named.name.chars().any(|c| c.is_ascii_alphabetic()));
    }

    #[test]
    fn parses_a_clean_object() {
        let raw = r#"{"name":"Latchlight","tagline":"The driver keeps a pointer it already freed.","blurb":"A local process can still use GPU memory the kernel released. The window is small and the impact is not.","logo_prompt":"A circle broken by a wedge, cream on ink."}"#;
        let named = interpret_naming(raw, "CVE-2026-0001", "unused", |_| false);
        assert_eq!(named.source, "model");
        assert_eq!(named.name, "Latchlight");
        assert!(named.tagline.contains("pointer"));
    }

    #[test]
    fn extracts_object_from_prose() {
        let raw = "Sure!\n{\"name\":\"Paper Harbor\",\"tagline\":\"A short line about the parser.\",\"blurb\":\"One. Two.\",\"logo_prompt\":\"a folded sheet\"}\nThanks";
        let named = interpret_naming(raw, "CVE-2020-0001", "desc", |_| false);
        assert_eq!(named.name, "Paper Harbor");
    }
}
