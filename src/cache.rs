use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use crate::cve::CveId;
use crate::model::Branding;

pub fn dossier_dir(root: &Path, id: &CveId) -> PathBuf {
    root.join(&id.year).join(&id.sequence)
}

pub fn load(root: &Path, id: &CveId) -> Result<Option<Branding>, String> {
    let path = dossier_dir(root, id).join("branding.json");
    let marker = dossier_dir(root, id).join(".prefilled");
    if !path.is_file() {
        if marker.is_file() {
            return Err(format!(
                "{id} is a prefilled dossier and its branding.json is missing. It will not be coined again."
            ));
        }
        return Ok(None);
    }
    let text = fs::read_to_string(&path).map_err(|e| format!("could not read {id}: {e}"))?;
    match serde_json::from_str::<Branding>(&text) {
        Ok(branding) if !branding.name.trim().is_empty() => Ok(Some(branding)),
        Ok(_) if marker.is_file() => Err(format!(
            "{id} is prefilled but the filed name is empty. It will not be coined again."
        )),
        Ok(_) => Ok(None),
        Err(err) if marker.is_file() => Err(format!(
            "{id} is a prefilled dossier and branding.json is damaged ({err}). It will not be regenerated."
        )),
        Err(_) => Ok(None),
    }
}

pub fn store(root: &Path, id: &CveId, branding: &Branding, logo: Option<(&[u8], &str)>) -> Result<(), String> {
    let dir = dossier_dir(root, id);
    if dir.join(".prefilled").is_file() {
        return Err(format!("refusing to overwrite the prefilled dossier for {id}"));
    }
    if let Some(existing) = load(root, id)? {
        if existing.prefilled {
            return Err(format!("refusing to overwrite the prefilled dossier for {id}"));
        }
    }
    fs::create_dir_all(&dir).map_err(|e| format!("could not create {}: {e}", dir.display()))?;
    if let Some((bytes, ext)) = logo {
        if !matches!(ext, "png" | "jpg" | "jpeg" | "webp" | "gif" | "svg") {
            return Err(format!("unsupported logo type {ext}"));
        }
        let final_name = format!("logo.{ext}");
        write_atomic(&dir.join(format!(".{final_name}.tmp")), &dir.join(&final_name), bytes)?;
    }
    let json = serde_json::to_vec_pretty(branding).map_err(|e| e.to_string())?;
    write_atomic(&dir.join(".branding.json.tmp"), &dir.join("branding.json"), &json)?;
    Ok(())
}

pub fn logo_path(root: &Path, id: &CveId, file_name: &str) -> Option<PathBuf> {
    if !matches!(
        file_name,
        "logo.png" | "logo.jpg" | "logo.jpeg" | "logo.webp" | "logo.gif" | "logo.svg"
    ) {
        return None;
    }
    let path = dossier_dir(root, id).join(file_name);
    if path.is_file() {
        Some(path)
    } else {
        None
    }
}

pub fn content_type(file_name: &str) -> &'static str {
    match file_name.rsplit('.').next() {
        Some("png") => "image/png",
        Some("jpg") | Some("jpeg") => "image/jpeg",
        Some("webp") => "image/webp",
        Some("gif") => "image/gif",
        Some("svg") => "image/svg+xml",
        _ => "application/octet-stream",
    }
}

/// Cross-process guard so two servers don't coin the same CVE at once.
pub struct FileLock {
    path: PathBuf,
}

impl FileLock {
    /// `Ok(None)` means another live lock is held. A lock older than three minutes is replaced.
    pub fn try_acquire(dir: &Path) -> Result<Option<Self>, String> {
        fs::create_dir_all(dir).map_err(|e| format!("could not create {}: {e}", dir.display()))?;
        let path = dir.join(".lock");
        if let Some(age) = lock_age(&path) {
            if age > Duration::from_secs(180) {
                let _ = fs::remove_file(&path);
            }
        }
        match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(mut file) => {
                let _ = writeln!(file, "{}", std::process::id());
                Ok(Some(Self { path }))
            }
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => Ok(None),
            Err(err) => Err(format!("could not lock {}: {err}", dir.display())),
        }
    }
}

impl Drop for FileLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

fn lock_age(path: &Path) -> Option<Duration> {
    let modified = fs::metadata(path).ok()?.modified().ok()?;
    SystemTime::now().duration_since(modified).ok()
}

fn write_atomic(tmp: &Path, final_path: &Path, bytes: &[u8]) -> Result<(), String> {
    {
        let mut file = File::create(tmp).map_err(|e| format!("could not write {}: {e}", tmp.display()))?;
        file.write_all(bytes)
            .map_err(|e| format!("could not write {}: {e}", tmp.display()))?;
        file.sync_all().ok();
    }
    fs::rename(tmp, final_path).map_err(|e| format!("could not file {}: {e}", final_path.display()))?;
    Ok(())
}

pub fn list_ids(root: &Path) -> Vec<String> {
    let mut ids = Vec::new();
    let Ok(years) = fs::read_dir(root) else {
        return ids;
    };
    for year in years.flatten() {
        let yname = year.file_name().to_string_lossy().to_string();
        if yname.len() != 4 || !yname.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        let Ok(seqs) = fs::read_dir(year.path()) else {
            continue;
        };
        for seq in seqs.flatten() {
            let sname = seq.file_name().to_string_lossy().to_string();
            if sname.bytes().all(|b| b.is_ascii_digit())
                && (4..=7).contains(&sname.len())
                && seq.path().join("branding.json").is_file()
            {
                ids.push(format!("CVE-{yname}-{sname}"));
            }
        }
    }
    ids
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::sample;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("vulnmark-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn roundtrip_keeps_sequence_directory() {
        let root = scratch("round");
        let id = CveId {
            year: "2021".into(),
            sequence: "44228".into(),
        };
        let branding = sample("CVE-2021-44228", "Log4Shell");
        store(&root, &id, &branding, Some((b"png-bytes", "png"))).unwrap();
        assert!(root.join("2021/44228/branding.json").is_file());
        assert!(root.join("2021/44228/logo.png").is_file());
        let loaded = load(&root, &id).unwrap().unwrap();
        assert_eq!(loaded.name, "Log4Shell");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn prefilled_marker_is_never_overwritten() {
        let root = scratch("prefill");
        let id = CveId {
            year: "2014".into(),
            sequence: "0160".into(),
        };
        let dir = dossier_dir(&root, &id);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join(".prefilled"), "canonical\n").unwrap();
        let mut branding = sample("CVE-2014-0160", "Heartbleed");
        branding.prefilled = true;
        let err = store(&root, &id, &branding, None).unwrap_err();
        assert!(err.contains("prefilled"));
        fs::write(
            dir.join("branding.json"),
            serde_json::to_vec(&branding).unwrap(),
        )
        .unwrap();
        let loaded = load(&root, &id).unwrap().unwrap();
        assert!(loaded.prefilled);
        assert_eq!(loaded.name, "Heartbleed");
        let _ = fs::remove_dir_all(&root);
    }
}
