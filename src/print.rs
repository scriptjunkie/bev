use std::io::Cursor;
use std::path::Path;
use std::time::Duration;

use ab_glyph::{Font, FontRef, PxScale, ScaleFont, point};
use image::imageops::FilterType;
use image::{ImageFormat, ImageReader, Rgba, RgbaImage};

const PRINT_EDGE: u32 = 2000;
const SITE_CAPTION: &str = "brandeveryvuln.com";
/// Dark ink that stays readable on Teemill's White RNA1 shirts.
const INK: Rgba<u8> = Rgba([28, 23, 18, 255]);
const FOOTER: Rgba<u8> = Rgba([255, 255, 255, 255]);
const FONT_NAME: &[u8] = include_bytes!("../static/fonts/outfit-semibold.ttf");
const FONT_SITE: &[u8] = include_bytes!("../static/fonts/outfit-regular.ttf");
const CACHE_NAME: &str = "print-v2.png";

/// Convert a filed logo (webp, png, jpeg, gif, or svg) into a print-ready PNG
/// whose longest edge is at least `PRINT_EDGE` pixels, with the vulnerability
/// name and brandeveryvuln.com captioned underneath.
pub fn logo_to_png(bytes: &[u8], file_name: &str, name: &str) -> Result<Vec<u8>, String> {
    let logo = logo_to_rgba(bytes, file_name)?;
    let framed = with_caption(&logo, name)?;
    let mut buf = Cursor::new(Vec::new());
    framed
        .write_to(&mut buf, ImageFormat::Png)
        .map_err(|e| format!("could not encode print PNG: {e}"))?;
    Ok(buf.into_inner())
}

fn logo_to_rgba(bytes: &[u8], file_name: &str) -> Result<RgbaImage, String> {
    let ext = file_name
        .rsplit('.')
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    match ext.as_str() {
        "svg" => svg_to_rgba(bytes),
        "png" | "jpg" | "jpeg" | "webp" | "gif" => raster_to_rgba(bytes),
        other => Err(format!("cannot print a .{other} logo")),
    }
}

fn raster_to_rgba(bytes: &[u8]) -> Result<RgbaImage, String> {
    let img = ImageReader::new(Cursor::new(bytes))
        .with_guessed_format()
        .map_err(|e| format!("could not read logo: {e}"))?
        .decode()
        .map_err(|e| format!("could not decode logo: {e}"))?;
    let img = img.into_rgba8();
    let (w, h) = img.dimensions();
    if w == 0 || h == 0 {
        return Err("logo has no pixels".into());
    }
    let long = w.max(h);
    if long < PRINT_EDGE {
        let scale = PRINT_EDGE as f32 / long as f32;
        let nw = ((w as f32) * scale).round().max(1.0) as u32;
        let nh = ((h as f32) * scale).round().max(1.0) as u32;
        Ok(image::imageops::resize(&img, nw, nh, FilterType::Lanczos3))
    } else {
        Ok(img)
    }
}

fn svg_to_rgba(bytes: &[u8]) -> Result<RgbaImage, String> {
    let mut opt = resvg::usvg::Options::default();
    opt.fontdb_mut().load_system_fonts();
    let tree = resvg::usvg::Tree::from_data(bytes, &opt)
        .map_err(|e| format!("could not parse SVG logo: {e}"))?;
    let size = tree.size();
    let width = size.width();
    let height = size.height();
    if width <= 0.0 || height <= 0.0 {
        return Err("SVG logo has no size".into());
    }
    let zoom = PRINT_EDGE as f32 / width.max(height);
    let w = (width * zoom).round().max(1.0) as u32;
    let h = (height * zoom).round().max(1.0) as u32;
    let mut pixmap = resvg::tiny_skia::Pixmap::new(w, h).ok_or("could not allocate print canvas")?;
    let transform = resvg::tiny_skia::Transform::from_scale(zoom, zoom);
    resvg::render(&tree, transform, &mut pixmap.as_mut());
    let png = pixmap
        .encode_png()
        .map_err(|e| format!("could not encode print PNG: {e}"))?;
    let img = ImageReader::new(Cursor::new(png))
        .with_guessed_format()
        .map_err(|e| format!("could not reread SVG print: {e}"))?
        .decode()
        .map_err(|e| format!("could not reread SVG print: {e}"))?;
    Ok(img.into_rgba8())
}

fn with_caption(logo: &RgbaImage, name: &str) -> Result<RgbaImage, String> {
    let (logo_w, logo_h) = logo.dimensions();
    let name = tidy_name(name);
    let font_name =
        FontRef::try_from_slice(FONT_NAME).map_err(|e| format!("could not read caption font: {e}"))?;
    let font_site =
        FontRef::try_from_slice(FONT_SITE).map_err(|e| format!("could not read caption font: {e}"))?;

    let max_text = (logo_w as f32 * 0.88).max(1.0);
    let name_size = fit_size(&font_name, &name, logo_w as f32 * 0.045, max_text);
    let site_size = fit_size(&font_site, SITE_CAPTION, logo_w as f32 * 0.028, max_text);
    let pad_top = (logo_w as f32 * 0.035).round().max(24.0);
    let gap = (logo_w as f32 * 0.01).round().max(8.0);
    let pad_bottom = (logo_w as f32 * 0.04).round().max(28.0);

    let name_line = if name.is_empty() {
        None
    } else {
        Some(measure(&font_name, &name, name_size))
    };
    let site_line = measure(&font_site, SITE_CAPTION, site_size);

    let mut footer_h = pad_top + pad_bottom;
    if let Some(line) = &name_line {
        footer_h += line.height;
        footer_h += gap;
    }
    footer_h += site_line.height;
    let footer_h = footer_h.round().max(1.0) as u32;

    let mut canvas = RgbaImage::from_pixel(logo_w, logo_h + footer_h, FOOTER);
    image::imageops::replace(&mut canvas, logo, 0, 0);

    let cx = logo_w as f32 / 2.0;
    let mut y = logo_h as f32 + pad_top;
    if let Some(line) = &name_line {
        draw_centered_line(
            &mut canvas,
            &font_name,
            &name,
            name_size,
            cx,
            y + line.ascent,
            INK,
        );
        y += line.height + gap;
    }
    draw_centered_line(
        &mut canvas,
        &font_site,
        SITE_CAPTION,
        site_size,
        cx,
        y + site_line.ascent,
        INK,
    );
    Ok(canvas)
}

struct LineMetrics {
    height: f32,
    ascent: f32,
}

fn measure(font: &FontRef<'_>, _text: &str, size: f32) -> LineMetrics {
    let scaled = font.as_scaled(PxScale::from(size.max(1.0)));
    LineMetrics {
        height: (scaled.ascent() - scaled.descent() + scaled.line_gap()).max(size),
        ascent: scaled.ascent(),
    }
}

fn line_width(font: &FontRef<'_>, text: &str, size: f32) -> f32 {
    let scale = PxScale::from(size.max(1.0));
    let scaled = font.as_scaled(scale);
    let mut width = 0.0;
    let mut last = None;
    for ch in text.chars() {
        let id = font.glyph_id(ch);
        if let Some(prev) = last {
            width += scaled.kern(prev, id);
        }
        width += scaled.h_advance(id);
        last = Some(id);
    }
    width
}

fn fit_size(font: &FontRef<'_>, text: &str, wanted: f32, max_width: f32) -> f32 {
    if text.is_empty() {
        return wanted.max(1.0);
    }
    let mut size = wanted.max(1.0);
    let width = line_width(font, text, size);
    if width > max_width && width > 0.0 {
        size = (size * max_width / width).max(12.0);
    }
    size
}

fn draw_centered_line(
    img: &mut RgbaImage,
    font: &FontRef<'_>,
    text: &str,
    size: f32,
    cx: f32,
    baseline: f32,
    color: Rgba<u8>,
) {
    let scale = PxScale::from(size.max(1.0));
    let scaled = font.as_scaled(scale);
    let width = line_width(font, text, size);
    let mut x = cx - width / 2.0;
    let mut last = None;
    for ch in text.chars() {
        let id = font.glyph_id(ch);
        if let Some(prev) = last {
            x += scaled.kern(prev, id);
        }
        let glyph = id.with_scale_and_position(scale, point(x, baseline));
        if let Some(outlined) = font.outline_glyph(glyph) {
            let bounds = outlined.px_bounds();
            outlined.draw(|dx, dy, coverage| {
                if coverage <= 0.0 {
                    return;
                }
                let px = bounds.min.x as i32 + dx as i32;
                let py = bounds.min.y as i32 + dy as i32;
                if px < 0 || py < 0 {
                    return;
                }
                let (w, h) = img.dimensions();
                if (px as u32) >= w || (py as u32) >= h {
                    return;
                }
                blend(img.get_pixel_mut(px as u32, py as u32), color, coverage);
            });
        }
        x += scaled.h_advance(id);
        last = Some(id);
    }
}

fn blend(px: &mut Rgba<u8>, color: Rgba<u8>, cover: f32) {
    let a = (color[3] as f32 / 255.0) * cover.clamp(0.0, 1.0);
    if a <= 0.0 {
        return;
    }
    for i in 0..3 {
        px.0[i] = (px.0[i] as f32 * (1.0 - a) + color.0[i] as f32 * a).round() as u8;
    }
    let dst_a = px.0[3] as f32 / 255.0;
    px.0[3] = ((dst_a + a * (1.0 - dst_a)) * 255.0).round().clamp(0.0, 255.0) as u8;
}

fn tidy_name(name: &str) -> String {
    name.split_whitespace().collect::<Vec<_>>().join(" ")
}

const TEEMILL_CREATE: &str = "https://teemill.com/omnis/v3/product/create";

/// Create a custom Teemill product and return its https product URL.
pub fn create_product(key: &str, image_url: &str, name: &str, description: &str) -> Result<String, String> {
    let payload = serde_json::json!({
        "image_url": image_url,
        "item_code": "RNA1",
        "colours": "White",
        "name": name,
        "description": description,
        "price": 20.00
    });
    let body = serde_json::to_string(&payload).map_err(|e| e.to_string())?;
    let agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(90))
        .build();
    let result = agent
        .post(TEEMILL_CREATE)
        .set("Authorization", &format!("Bearer {key}"))
        .set("Content-Type", "application/json")
        .set("Accept", "application/json")
        .send_string(&body);
    let text = match result {
        Ok(resp) => resp
            .into_string()
            .map_err(|e| format!("could not read Teemill: {e}"))?,
        Err(ureq::Error::Status(code, resp)) => {
            let _ = resp.into_string();
            return Err(format!("Teemill returned HTTP {code}"));
        }
        Err(err) => return Err(format!("could not reach Teemill: {err}")),
    };
    let value: serde_json::Value = serde_json::from_str(&text)
        .map_err(|_| "Teemill returned a response that was not JSON".to_string())?;
    let url = value
        .get("url")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "Teemill did not return a product URL".to_string())?;
    if !is_teemill_product_url(url) {
        return Err("Teemill returned a URL that is not a product page".into());
    }
    Ok(url.to_string())
}

/// Accept only https product pages on teemill.com.
pub fn is_teemill_product_url(raw: &str) -> bool {
    let raw = raw.trim();
    let Some(rest) = raw.strip_prefix("https://") else {
        return false;
    };
    if rest.is_empty() || rest.contains('@') || rest.contains('\\') || rest.contains("://") {
        return false;
    }
    let host = rest.split(['/', '?', '#']).next().unwrap_or("");
    let host = host
        .rsplit_once(']')
        .map(|(_, after)| after) // junk after ipv6, reject below
        .unwrap_or(host);
    let host = host.split(':').next().unwrap_or("").trim().to_ascii_lowercase();
    host == "teemill.com" || (host.ends_with(".teemill.com") && host.len() > ".teemill.com".len())
}

pub fn cache_path(root: &Path, id: &crate::cve::CveId) -> std::path::PathBuf {
    crate::cache::dossier_dir(root, id).join(CACHE_NAME)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tiny_red_png() -> Vec<u8> {
        let mut src = image::RgbaImage::new(2, 2);
        for px in src.pixels_mut() {
            *px = image::Rgba([200, 30, 20, 255]);
        }
        let mut buf = Cursor::new(Vec::new());
        src.write_to(&mut buf, ImageFormat::Png).unwrap();
        buf.into_inner()
    }

    fn luma(px: Rgba<u8>) -> u8 {
        ((px[0] as u16 + px[1] as u16 + px[2] as u16) / 3) as u8
    }

    fn footer_has_ink(img: &image::DynamicImage, logo_h: u32) -> bool {
        let rgba = img.to_rgba8();
        let (w, h) = rgba.dimensions();
        let mut ink = 0u32;
        for y in logo_h..h {
            for x in 0..w {
                let px = *rgba.get_pixel(x, y);
                if px[3] > 200 && luma(px) < 80 {
                    ink += 1;
                }
            }
        }
        ink > 200
    }

    #[test]
    fn upscales_a_tiny_png_and_keeps_png_magic() {
        let out = logo_to_png(&tiny_red_png(), "logo.png", "Ghostpage").unwrap();
        assert_eq!(&out[..8], b"\x89PNG\r\n\x1a\n");
        let decoded = image::load_from_memory(&out).unwrap();
        assert_eq!(decoded.width(), PRINT_EDGE);
        assert!(decoded.height() > PRINT_EDGE);
        let rgba = decoded.to_rgba8();
        assert_eq!(rgba.get_pixel(0, 0).0, [200, 30, 20, 255]);
        assert_eq!(
            rgba.get_pixel(0, decoded.height() - 1).0,
            [255, 255, 255, 255]
        );
        assert!(footer_has_ink(&decoded, PRINT_EDGE));
    }

    #[test]
    fn renders_a_simple_svg() {
        let svg = br##"<svg xmlns="http://www.w3.org/2000/svg" width="100" height="80">
            <rect width="100" height="80" fill="#123456"/>
        </svg>"##;
        let out = logo_to_png(svg, "logo.svg", "Ghostpage").unwrap();
        assert_eq!(&out[..8], b"\x89PNG\r\n\x1a\n");
        let decoded = image::load_from_memory(&out).unwrap();
        assert_eq!(decoded.width(), PRINT_EDGE);
        assert!(decoded.height() > 1600);
        let rgba = decoded.to_rgba8();
        let mid = *rgba.get_pixel(100, 100);
        assert!(mid[2] > mid[0] && mid[2] > mid[1], "logo area should stay blue, got {mid:?}");
        assert!(footer_has_ink(&decoded, 1600));
    }

    #[test]
    fn captions_the_name_and_site_on_a_white_footer() {
        let out = logo_to_png(&tiny_red_png(), "logo.png", "Ghostpage").unwrap();
        let decoded = image::load_from_memory(&out).unwrap();
        let logo_h = PRINT_EDGE;
        // The logo should still dominate the canvas.
        assert!(decoded.height() < logo_h + logo_h / 3);
        assert!(footer_has_ink(&decoded, logo_h));
        // Ink should be concentrated near the horizontal center, not the corners.
        let rgba = decoded.to_rgba8();
        let (w, h) = rgba.dimensions();
        let mut center = 0u32;
        let mut edge = 0u32;
        for y in logo_h..h {
            for x in 0..w {
                let px = *rgba.get_pixel(x, y);
                if px[3] > 200 && luma(px) < 80 {
                    if (x as i32 - (w as i32 / 2)).unsigned_abs() < w / 4 {
                        center += 1;
                    }
                    if x < 40 || x + 40 >= w {
                        edge += 1;
                    }
                }
            }
        }
        assert!(center > edge * 4, "caption should be centered, center={center} edge={edge}");
    }

    #[test]
    fn shrinks_a_long_name_to_fit_the_footer() {
        let long = "An Unreasonably Long Vulnerability Name That Would Overflow";
        let out = logo_to_png(&tiny_red_png(), "logo.png", long).unwrap();
        let decoded = image::load_from_memory(&out).unwrap();
        let rgba = decoded.to_rgba8();
        let (w, h) = rgba.dimensions();
        // No dark ink in the extreme side margins of the footer.
        for y in PRINT_EDGE..h {
            for x in (0..12).chain((w - 12)..w) {
                let px = *rgba.get_pixel(x, y);
                assert!(
                    luma(px) > 200,
                    "caption overflowed at ({x},{y}) {:?}",
                    px.0
                );
            }
        }
        assert!(footer_has_ink(&decoded, PRINT_EDGE));
    }

    #[test]
    fn cache_file_is_versioned() {
        let id = crate::cve::CveId {
            year: "2026".into(),
            sequence: "0001".into(),
        };
        let path = cache_path(Path::new("/tmp/cache"), &id);
        assert!(path.ends_with("2026/0001/print-v2.png"));
    }

    #[test]
    fn accepts_only_https_teemill_hosts() {
        assert!(is_teemill_product_url("https://teemill.com/custom/abc"));
        assert!(is_teemill_product_url(
            "https://shop.teemill.com/product/foo?x=1"
        ));
        assert!(!is_teemill_product_url("http://teemill.com/x"));
        assert!(!is_teemill_product_url("https://evil.com/teemill.com"));
        assert!(!is_teemill_product_url("https://teemill.com.evil.test/x"));
        assert!(!is_teemill_product_url("https://user@teemill.com/x"));
        assert!(!is_teemill_product_url("https://notteemill.com/x"));
        assert!(!is_teemill_product_url("https://teemill.com.attacker.com/"));
    }
}
