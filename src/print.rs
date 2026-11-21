use std::io::Cursor;
use std::path::Path;

use image::imageops::FilterType;
use image::{ImageFormat, ImageReader};

const PRINT_EDGE: u32 = 2000;

/// Convert a filed logo (webp, png, jpeg, gif, or svg) into a print-ready PNG
/// whose longest edge is at least `PRINT_EDGE` pixels.
pub fn logo_to_png(bytes: &[u8], file_name: &str) -> Result<Vec<u8>, String> {
    let ext = file_name
        .rsplit('.')
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    match ext.as_str() {
        "svg" => svg_to_png(bytes),
        "png" | "jpg" | "jpeg" | "webp" | "gif" => raster_to_png(bytes),
        other => Err(format!("cannot print a .{other} logo")),
    }
}

fn raster_to_png(bytes: &[u8]) -> Result<Vec<u8>, String> {
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
    let out = if long < PRINT_EDGE {
        let scale = PRINT_EDGE as f32 / long as f32;
        let nw = ((w as f32) * scale).round().max(1.0) as u32;
        let nh = ((h as f32) * scale).round().max(1.0) as u32;
        image::imageops::resize(&img, nw, nh, FilterType::Lanczos3)
    } else {
        img
    };
    let mut buf = Cursor::new(Vec::new());
    out.write_to(&mut buf, ImageFormat::Png)
        .map_err(|e| format!("could not encode print PNG: {e}"))?;
    Ok(buf.into_inner())
}

fn svg_to_png(bytes: &[u8]) -> Result<Vec<u8>, String> {
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
    pixmap
        .encode_png()
        .map_err(|e| format!("could not encode print PNG: {e}"))
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
    crate::cache::dossier_dir(root, id).join("print.png")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upscales_a_tiny_png_and_keeps_png_magic() {
        let mut src = image::RgbaImage::new(2, 2);
        for px in src.pixels_mut() {
            *px = image::Rgba([200, 30, 20, 255]);
        }
        let mut buf = Cursor::new(Vec::new());
        src.write_to(&mut buf, ImageFormat::Png).unwrap();
        let out = logo_to_png(&buf.into_inner(), "logo.png").unwrap();
        assert_eq!(&out[..8], b"\x89PNG\r\n\x1a\n");
        let decoded = image::load_from_memory(&out).unwrap();
        assert_eq!(decoded.width().max(decoded.height()), PRINT_EDGE);
    }

    #[test]
    fn renders_a_simple_svg() {
        let svg = br##"<svg xmlns="http://www.w3.org/2000/svg" width="100" height="80">
            <rect width="100" height="80" fill="#123456"/>
        </svg>"##;
        let out = logo_to_png(svg, "logo.svg").unwrap();
        assert_eq!(&out[..8], b"\x89PNG\r\n\x1a\n");
        let decoded = image::load_from_memory(&out).unwrap();
        assert_eq!(decoded.width(), PRINT_EDGE);
        assert_eq!(decoded.height(), 1600);
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
