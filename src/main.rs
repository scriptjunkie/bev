//! BrandEveryVuln is intentionally synchronous: tiny_http and ureq, no async runtime.
mod brand;
mod cache;
mod cve;
mod famous;
mod host;
mod html;
mod model;
mod nvd;
mod offline;
mod openrouter;
mod paths;
mod print;

use std::fs;
use std::io::{Cursor, Read};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use tiny_http::{Header, Method, Request, Response, Server, StatusCode};

use crate::brand::{App, BrandError};
use crate::cve::CveId;
use crate::host::{HostClass, Site};
use crate::html::ExploreCard;

const FONTS: &[&str] = &[
    "fraunces-normal-560.woff2",
    "fraunces-italic-560.woff2",
    "outfit-normal-400.woff2",
    "outfit-normal-500.woff2",
    "outfit-normal-600.woff2",
    "ibm-plex-mono-normal-400.woff2",
    "ibm-plex-mono-normal-500.woff2",
];

const CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; font-src 'self'; img-src 'self'; connect-src 'self' https://teemill.com; form-action 'self'; base-uri 'none'; frame-ancestors 'none'";

fn main() {
    load_dotenv();
    let app = Arc::new(App::from_env());
    let found = famous::CANON
        .iter()
        .filter(|canon| {
            cve::parse(canon.id)
                .ok()
                .and_then(|id| cache::load(&app.cache_dir, &id).ok().flatten())
                .is_some()
        })
        .count();
    let server = match Server::http(&app.bind) {
        Ok(server) => server,
        Err(err) => {
            eprintln!("could not bind {}: {err}", app.bind);
            std::process::exit(1);
        }
    };
    let server = Arc::new(server);
    eprintln!("BrandEveryVuln listening on http://{}", app.bind);
    eprintln!("project root {}", paths::project_root().display());
    eprintln!("cache {}", app.cache_dir.display());
    eprintln!(
        "openrouter {}",
        if app.openrouter_key.is_some() { "key set" } else { "no key" }
    );
    eprintln!("prefilled dossiers {found}/{}", famous::CANON.len());
    match &app.base_domain {
        Some(domain) => eprintln!("base domain {domain} (CVE pages also live at cve-year-seq.{domain})"),
        None => eprintln!("base domain unset (CVE links stay on /cve/<id>)"),
    }

    let mut workers = Vec::new();
    for _ in 0..4 {
        let server = Arc::clone(&server);
        let app = Arc::clone(&app);
        workers.push(thread::spawn(move || loop {
            match server.recv() {
                Ok(request) => route(&app, request),
                Err(err) => {
                    eprintln!("server stopped: {err}");
                    break;
                }
            }
        }));
    }
    for worker in workers {
        let _ = worker.join();
    }
}

fn route(app: &App, request: Request) {
    let host = header_value(&request, "Host");
    let proto = header_value(&request, "X-Forwarded-Proto");
    let (class, site) = host::interpret(app.base_domain.as_deref(), host.as_deref(), proto.as_deref());
    let method = request.method().clone();
    let url = request.url().to_string();
    let (path, query) = split_url(&url);
    let path = percent_decode(&path, false);

    if method == Method::Post {
        return save_teemill(app, request, &class, &site, &path);
    }
    if method != Method::Get && method != Method::Head {
        let page = html::trouble(
            "405",
            "That method doesn't open a file.",
            "The desk only answers GET.",
            None,
            &site,
        );
        return respond(request, html_response(405, page));
    }

    // Root-relative assets are served on every host, including CVE subdomains.
    if let Some(response) = asset_response(&path) {
        return respond(request, response);
    }

    match class {
        HostClass::Www => {
            let location = site.apex_url(&path, query);
            return respond(request, redirect(&location));
        }
        HostClass::Invalid { label } => {
            let page = html::trouble(
                "Unknown address",
                "That subdomain isn't a CVE.",
                &format!("“{label}” is not a dossier. Hosts look like cve-2021-44228 or 2021-44228, in front of the base domain."),
                None,
                &site,
            );
            return respond(request, html_response(404, page));
        }
        HostClass::Cve(id) if path == "/" => return serve_cve(app, request, &site, &id),
        HostClass::Cve(id) if path == "/print.png" => return respond(request, print_response(app, &site, &id)),
        HostClass::Cve(id) if path == "/logo" => return respond(request, logo_response(app, &site, &id)),
        HostClass::Apex | HostClass::Cve(_) => {}
    }

    if path == "/" {
        return respond(request, html_response(200, render_home(app, &site)));
    }
    if path == "/random" {
        let id = random_id(app);
        return respond(request, redirect(&site.cve(&id)));
    }
    if path == "/lookup" {
        let raw = query_param(query, "id").unwrap_or_default();
        return match cve::parse(&raw) {
            Ok(id) => respond(request, redirect(&site.cve(&id))),
            Err(message) => respond(request, html_response(400, invalid_page(&site, &message))),
        };
    }
    if let Some(rest) = path.strip_prefix("/cve/") {
        return cve_route(app, request, &site, rest);
    }
    respond(request, html_response(404, missing_page(&site)));
}

fn asset_response(path: &str) -> Option<Response<Cursor<Vec<u8>>>> {
    if path == "/favicon.svg" {
        return Some(bytes_response(200, "image/svg+xml", html::FAVICON.as_bytes(), "public, max-age=86400"));
    }
    if path == "/static/app.css" {
        let css = read_project("static/app.css").unwrap_or_else(|| b"body{font-family:georgia,serif}".to_vec());
        return Some(bytes_response(200, "text/css; charset=utf-8", &css, "public, max-age=3600"));
    }
    if path == "/static/app.js" {
        let js = read_project("static/app.js").unwrap_or_default();
        return Some(bytes_response(200, "application/javascript; charset=utf-8", &js, "public, max-age=3600"));
    }
    if let Some(name) = path.strip_prefix("/static/fonts/") {
        if FONTS.contains(&name) {
            if let Some(bytes) = read_project(&format!("static/fonts/{name}")) {
                return Some(bytes_response(200, "font/woff2", &bytes, "public, max-age=604800"));
            }
        }
        return Some(html_response(404, missing_page(&host::Site {
            base_domain: None,
            scheme: "http".into(),
            port: None,
            request_host: String::new(),
        })));
    }
    None
}

fn header_value(request: &Request, name: &str) -> Option<String> {
    request.headers().iter().find_map(|header| {
        if header.field.as_str().as_str().eq_ignore_ascii_case(name) {
            Some(header.value.as_str().trim().to_string())
        } else {
            None
        }
    })
}

fn cve_route(app: &App, request: Request, site: &Site, rest: &str) {
    let (raw, extra) = if let Some(id) = rest.strip_suffix("/logo") {
        (id.trim_end_matches('/'), "logo")
    } else if let Some(id) = rest.strip_suffix("/print.png") {
        (id.trim_end_matches('/'), "print")
    } else {
        (rest.trim_end_matches('/'), "page")
    };
    let id = match cve::parse(raw) {
        Ok(id) => id,
        Err(message) => return respond(request, html_response(400, invalid_page(site, &message))),
    };
    if extra == "page" && raw != id.as_id() {
        return respond(request, redirect(&site.cve(&id)));
    }
    match extra {
        "logo" => respond(request, logo_response(app, site, &id)),
        "print" => respond(request, print_response(app, site, &id)),
        _ => serve_cve(app, request, site, &id),
    }
}

fn serve_cve(app: &App, request: Request, site: &Site, id: &CveId) {
    match app.resolve(id) {
        Ok(branding) => respond(request, html_response(200, html::cve_page(&branding, &app.cache_dir, site, app.teemill_key.as_deref()))),
        Err(BrandError::NotFound) => respond(
            request,
            html_response(
                404,
                html::trouble(
                    "Empty folder",
                    "NVD has no record under that id.",
                    &format!("{id} is shaped like a CVE, and the file is empty. It may be reserved, rejected without a public record, or not assigned yet."),
                    None,
                    site,
                ),
            ),
        ),
        Err(BrandError::Failed { message, draft }) => respond(
            request,
            html_response(
                502,
                html::trouble("The desk stopped", "This one did not get filed.", &message, draft.as_ref(), site),
            ),
        ),
    }
}

fn logo_response(app: &App, site: &Site, id: &CveId) -> Response<Cursor<Vec<u8>>> {
    let branding = match cache::load(&app.cache_dir, id) {
        Ok(Some(branding)) => branding,
        _ => {
            return html_response(
                404,
                html::trouble("No mark", "There is no logo on file for that id.", "Open the dossier first. A mark is cut only when a name is filed.", None, site),
            )
        }
    };
    let Some(name) = branding.logo_file.as_deref() else {
        return html_response(
            404,
            html::trouble("No mark", "This name was filed without a logo image.", "The page uses a monogram instead.", None, site),
        );
    };
    let Some(path) = cache::logo_path(&app.cache_dir, id, name) else {
        return html_response(404, missing_page(site));
    };
    match fs::read(&path) {
        Ok(bytes) => bytes_response(200, cache::content_type(name), &bytes, "public, max-age=86400"),
        Err(_) => html_response(404, missing_page(site)),
    }
}

fn print_response(app: &App, site: &Site, id: &CveId) -> Response<Cursor<Vec<u8>>> {
    let branding = match cache::load(&app.cache_dir, id) {
        Ok(Some(branding)) => branding,
        _ => {
            return html_response(
                404,
                html::trouble("No mark", "There is no logo on file for that id.", "Open the dossier first. A print file is cut only when a name is filed.", None, site),
            )
        }
    };
    let Some(name) = branding.logo_file.as_deref() else {
        return html_response(
            404,
            html::trouble("No mark", "This name was filed without a logo image.", "The page uses a monogram instead, which is not printed.", None, site),
        );
    };
    let Some(path) = cache::logo_path(&app.cache_dir, id, name) else {
        return html_response(404, missing_page(site));
    };
    let cached = crate::print::cache_path(&app.cache_dir, id);
    if let (Ok(logo_meta), Ok(print_meta)) = (std::fs::metadata(&path), std::fs::metadata(&cached)) {
        if let (Ok(logo_m), Ok(print_m)) = (logo_meta.modified(), print_meta.modified()) {
            if print_m >= logo_m {
                if let Ok(bytes) = std::fs::read(&cached) {
                    return bytes_response(200, "image/png", &bytes, "public, max-age=86400");
                }
            }
        }
    }
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(_) => return html_response(404, missing_page(site)),
    };
    match crate::print::logo_to_png(&bytes, name) {
        Ok(png) => {
            if let Some(parent) = cached.parent() {
                let _ = std::fs::create_dir_all(parent);
                let _ = std::fs::write(&cached, &png);
            }
            bytes_response(200, "image/png", &png, "public, max-age=86400")
        }
        Err(err) => {
            eprintln!("print {id}: {err}");
            html_response(
                500,
                html::trouble("No print", "The logo could not be prepared for print.", "Try again in a moment, or open the dossier logo instead.", None, site),
            )
        }
    }
}

fn save_teemill(app: &App, mut request: Request, class: &HostClass, site: &Site, path: &str) {
    let id = match class {
        HostClass::Cve(id) if path == "/teemill" => id.clone(),
        _ => {
            let Some(rest) = path.strip_prefix("/cve/") else {
                let page = html::trouble("405", "That method doesn't open a file.", "The desk only answers GET, except to remember a T-shirt link.", None, site);
                return respond(request, html_response(405, page));
            };
            let Some(raw) = rest.strip_suffix("/teemill") else {
                let page = html::trouble("405", "That method doesn't open a file.", "The desk only answers GET, except to remember a T-shirt link.", None, site);
                return respond(request, html_response(405, page));
            };
            match cve::parse(raw.trim_end_matches('/')) {
                Ok(id) => id,
                Err(message) => return respond(request, html_response(400, invalid_page(site, &message))),
            }
        }
    };
    let mut raw = String::new();
    let read = request.as_reader().take(8 * 1024).read_to_string(&mut raw);
    if read.is_err() {
        return respond(request, json_response(400, r#"{"ok":false,"error":"could not read the request"}"#));
    }
    let value: serde_json::Value = match serde_json::from_str(&raw) {
        Ok(value) => value,
        Err(_) => return respond(request, json_response(400, r#"{"ok":false,"error":"send a JSON object with a url"}"#)),
    };
    let Some(url) = value.get("url").and_then(|v| v.as_str()) else {
        return respond(request, json_response(400, r#"{"ok":false,"error":"send a JSON object with a url"}"#));
    };
    if !crate::print::is_teemill_product_url(url) {
        return respond(request, json_response(400, r#"{"ok":false,"error":"that is not a Teemill product URL"}"#));
    };
    let branding = match cache::load(&app.cache_dir, &id) {
        Ok(Some(branding)) => branding,
        Ok(None) => return respond(request, json_response(404, r#"{"ok":false,"error":"no dossier is on file"}"#)),
        Err(err) => {
            eprintln!("teemill load {id}: {err}");
            return respond(request, json_response(500, r#"{"ok":false,"error":"could not open the dossier"}"#));
        }
    };
    if branding.prefilled {
        return respond(request, json_response(403, r#"{"ok":false,"error":"famous names are not sold as shirts here"}"#));
    }
    let mut branding = branding;
    branding.teemill_url = Some(url.trim().to_string());
    if let Err(err) = cache::store(&app.cache_dir, &id, &branding, None) {
        eprintln!("teemill store {id}: {err}");
        return respond(request, json_response(500, r#"{"ok":false,"error":"could not save the T-shirt link"}"#));
    }
    respond(request, json_response(200, r#"{"ok":true}"#));
}

fn json_response(status: u16, body: &str) -> Response<Cursor<Vec<u8>>> {
    Response::from_data(body.as_bytes().to_vec())
        .with_status_code(StatusCode(status))
        .with_header(header("Content-Type", "application/json; charset=utf-8"))
        .with_header(header("Cache-Control", "no-store"))
        .with_header(header("X-Content-Type-Options", "nosniff"))
}

fn render_home(app: &App, site: &Site) -> String {
    let cards = famous::EXPLORE_IDS
        .iter()
        .filter_map(|raw| {
            let id = cve::parse(raw).ok()?;
            match cache::load(&app.cache_dir, &id) {
                Ok(Some(branding)) => Some(ExploreCard::Filed(branding)),
                Ok(None) => Some(ExploreCard::Unfiled { id: id.as_id() }),
                Err(err) => {
                    eprintln!("explore {}: {err}", id);
                    Some(ExploreCard::Unfiled { id: id.as_id() })
                }
            }
        })
        .collect::<Vec<_>>();
    html::home(&cards, &app.cache_dir, site)
}

fn invalid_page(site: &Site, message: &str) -> String {
    html::trouble(
        "Rejected",
        "That isn't a CVE id.",
        &format!("{message} An id looks like CVE-2026-0001."),
        None,
        site,
    )
}

fn missing_page(site: &Site) -> String {
    html::trouble(
        "404",
        "This desk doesn't have that page.",
        "Try the wall, or name a CVE from the search box.",
        None,
        site,
    )
}

fn random_id(app: &App) -> CveId {
    if let Some(id) = app.nvd.fetch_random_kev(mix) {
        return id;
    }
    let ids = cache::list_ids(&app.cache_dir);
    if !ids.is_empty() {
        let id = &ids[(mix() as usize) % ids.len()];
        if let Ok(parsed) = cve::parse(id) {
            return parsed;
        }
    }
    let canon = &famous::CANON[(mix() as usize) % famous::CANON.len()];
    cve::parse(canon.id).expect("canon id")
}

fn mix() -> u64 {
    static N: AtomicU64 = AtomicU64::new(1);
    let tick = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(1);
    let n = N.fetch_add(1, Ordering::Relaxed);
    let mut x = tick.wrapping_add(n.wrapping_mul(0x9E37_79B9_7F4A_7C15));
    x ^= x >> 30;
    x = x.wrapping_mul(0xBF58_476D_1CE4_E5B9);
    x ^= x >> 27;
    x
}

fn split_url(url: &str) -> (&str, &str) {
    match url.split_once('?') {
        Some((path, query)) => (path, query),
        None => (url, ""),
    }
}

fn query_param(query: &str, key: &str) -> Option<String> {
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        if percent_decode(k, true) == key {
            return Some(percent_decode(v, true));
        }
    }
    None
}

fn percent_decode(text: &str, plus_is_space: bool) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(value) = u8::from_str_radix(std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or(""), 16) {
                out.push(value);
                i += 3;
                continue;
            }
        }
        if plus_is_space && bytes[i] == b'+' {
            out.push(b' ');
        } else {
            out.push(bytes[i]);
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn read_project(rel: &str) -> Option<Vec<u8>> {
    let path = paths::project_root().join(rel);
    fs::read(path).ok()
}

fn header(name: &str, value: &str) -> Header {
    Header::from_bytes(name.as_bytes(), value.as_bytes()).expect("header")
}

fn html_response(status: u16, body: String) -> Response<Cursor<Vec<u8>>> {
    Response::from_data(body.into_bytes())
        .with_status_code(StatusCode(status))
        .with_header(header("Content-Type", "text/html; charset=utf-8"))
        .with_header(header("Cache-Control", "no-store"))
        .with_header(header("X-Content-Type-Options", "nosniff"))
        .with_header(header("Content-Security-Policy", CSP))
        .with_header(header("Referrer-Policy", "no-referrer"))
}

fn bytes_response(status: u16, content_type: &str, body: &[u8], cache: &str) -> Response<Cursor<Vec<u8>>> {
    Response::from_data(body.to_vec())
        .with_status_code(StatusCode(status))
        .with_header(header("Content-Type", content_type))
        .with_header(header("Cache-Control", cache))
        .with_header(header("X-Content-Type-Options", "nosniff"))
}

fn redirect(location: &str) -> Response<Cursor<Vec<u8>>> {
    Response::from_data(Vec::new())
        .with_status_code(StatusCode(302))
        .with_header(header("Location", location))
        .with_header(header("Cache-Control", "no-store"))
}

fn respond(request: Request, response: Response<Cursor<Vec<u8>>>) {
    if let Err(err) = request.respond(response) {
        eprintln!("respond: {err}");
    }
}

fn load_dotenv() {
    let path = paths::project_root().join(".env");
    let Ok(text) = fs::read_to_string(path) else {
        return;
    };
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line);
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        if key.is_empty() || std::env::var(key).is_ok() {
            continue;
        }
        let value = value.trim().trim_matches('"').trim_matches('\'');
        std::env::set_var(key, value);
    }
}
