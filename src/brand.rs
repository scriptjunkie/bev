use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::cache::{self, FileLock};
use crate::cve::CveId;
use crate::famous;
use crate::model::{Branding, NvdRecord};
use crate::nvd::{NvdClient, NvdError};
use crate::offline;
use crate::openrouter::{ImageCut, Named, OpenRouter, IMAGE_MODEL, NAMING_MODEL};

pub struct App {
    pub bind: String,
    pub cache_dir: PathBuf,
    pub base_domain: Option<String>,
    pub openrouter_key: Option<String>,
    pub nvd: NvdClient,
    pub ai: OpenRouter,
    locks: Mutex<HashMap<String, Arc<Mutex<()>>>>,
}

pub struct Draft {
    pub nvd: NvdRecord,
    pub named: Option<Named>,
}

pub enum BrandError {
    NotFound,
    Failed { message: String, draft: Option<Draft> },
}

impl App {
    pub fn from_env() -> Self {
        let bind = std::env::var("BIND").unwrap_or_else(|_| "0.0.0.0:43123".into());
        let cache_dir = match std::env::var("CACHE_DIR") {
            Ok(value) if !value.trim().is_empty() => PathBuf::from(value.trim()),
            _ => crate::paths::project_root().join("cache"),
        };
        let openrouter_key = std::env::var("OPENROUTER_API_KEY")
            .ok()
            .map(|k| k.trim().to_string())
            .filter(|k| !k.is_empty() && !k.chars().any(|c| c.is_whitespace()));
        let nvd_key = std::env::var("NVD_API_KEY")
            .ok()
            .map(|k| k.trim().to_string())
            .filter(|k| !k.is_empty() && !k.chars().any(|c| c.is_whitespace()));
        let base_domain = std::env::var("BASE_DOMAIN")
            .ok()
            .and_then(|value| crate::host::normalize_base(&value));
        Self {
            bind,
            cache_dir,
            base_domain,
            openrouter_key,
            nvd: NvdClient::new(nvd_key),
            ai: OpenRouter::new(),
            locks: Mutex::new(HashMap::new()),
        }
    }

    pub fn resolve(&self, id: &CveId) -> Result<Branding, BrandError> {
        if let Some(branding) = self.read_ready(id)? {
            return Ok(branding);
        }
        let lock = self.cve_lock(&id.as_id());
        let _guard = lock.lock().unwrap_or_else(|err| err.into_inner());
        if let Some(branding) = self.read_ready(id)? {
            return Ok(branding);
        }
        let dir = cache::dossier_dir(&self.cache_dir, id);
        let mut held = None;
        for _ in 0..80 {
            if let Some(branding) = self.read_ready(id)? {
                return Ok(branding);
            }
            match FileLock::try_acquire(&dir) {
                Ok(Some(file_lock)) => {
                    held = Some(file_lock);
                    break;
                }
                Ok(None) => thread::sleep(Duration::from_millis(400)),
                Err(message) => {
                    return Err(BrandError::Failed {
                        message,
                        draft: None,
                    })
                }
            }
        }
        let Some(file_lock) = held else {
            if let Some(branding) = self.read_ready(id)? {
                return Ok(branding);
            }
            return Err(BrandError::Failed {
                message: format!(
                    "Another request is still filing {id}. Wait a moment and open it again."
                ),
                draft: None,
            });
        };
        if let Some(branding) = self.read_ready(id)? {
            drop(file_lock);
            return Ok(branding);
        }
        let branding = self.generate(id)?;
        drop(file_lock);
        Ok(branding)
    }

    fn read_ready(&self, id: &CveId) -> Result<Option<Branding>, BrandError> {
        match cache::load(&self.cache_dir, id) {
            Ok(value) => Ok(value),
            Err(message) => Err(BrandError::Failed {
                message,
                draft: None,
            }),
        }
    }

    fn generate(&self, id: &CveId) -> Result<Branding, BrandError> {
        if let Some(branding) = self.read_ready(id)? {
            return Ok(branding);
        }
        eprintln!("nvd {id}");
        let nvd = match self.nvd.fetch(id) {
            Ok(record) => record,
            Err(NvdError::NotFound) => return Err(BrandError::NotFound),
            Err(NvdError::Failed(message)) => {
                return Err(BrandError::Failed {
                    message,
                    draft: None,
                })
            }
        };
        let named = match self.openrouter_key.as_deref() {
            Some(key) => {
                eprintln!("name {id} via {NAMING_MODEL}");
                match self.ai.coin_name(key, id, &nvd, |name| famous::name_taken(name, &id.as_id())) {
                    Ok(named) => named,
                    Err(message) => {
                        eprintln!("name {id} offline ({message})");
                        offline_named(id, &nvd)
                    }
                }
            }
            None => {
                eprintln!("name {id} offline (no OpenRouter key)");
                offline_named(id, &nvd)
            }
        };
        eprintln!("name {id} -> {} ({})", named.name, named.source);
        let (image, logo_source) = match self.openrouter_key.as_deref() {
            Some(key) => {
                eprintln!("logo {id} via {IMAGE_MODEL}");
                match self.ai.cut_logo(key, &named) {
                    Ok(image) => (image, "recraft"),
                    Err(message) => {
                        eprintln!("logo {id} offline ({message})");
                        (offline_logo(&named, &nvd), "offline")
                    }
                }
            }
            None => {
                eprintln!("logo {id} offline (no OpenRouter key)");
                (offline_logo(&named, &nvd), "offline")
            }
        };
        let branding = assemble(id, nvd, &named, &image, logo_source);
        cache::store(
            &self.cache_dir,
            id,
            &branding,
            Some((image.bytes.as_slice(), image.ext)),
        )
        .map_err(|message| BrandError::Failed {
            message,
            draft: None,
        })?;
        eprintln!(
            "filed {id} at {}/{}/{}",
            self.cache_dir.display(),
            id.year,
            id.sequence
        );
        Ok(branding)
    }

    fn cve_lock(&self, id: &str) -> Arc<Mutex<()>> {
        let mut map = self.locks.lock().unwrap_or_else(|err| err.into_inner());
        map.entry(id.to_string())
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    }
}

fn offline_named(id: &CveId, nvd: &NvdRecord) -> Named {
    let coined = offline::coin(nvd, &id.as_id());
    Named {
        name: coined.name,
        tagline: coined.tagline,
        blurb: coined.blurb,
        logo_prompt: String::new(),
        source: "offline",
    }
}

fn offline_logo(named: &Named, nvd: &NvdRecord) -> ImageCut {
    ImageCut {
        bytes: offline::svg(&named.name, nvd).into_bytes(),
        ext: "svg",
    }
}

fn assemble(id: &CveId, nvd: NvdRecord, named: &Named, image: &ImageCut, logo_source: &str) -> Branding {
    let name_offline = named.source == "offline";
    let logo_offline = logo_source == "offline";
    let logo_credit = if logo_offline {
        "Drawn offline as an SVG from the name and the NVD record. Not an official vendor mark."
            .to_string()
    } else {
        format!("Generated by {IMAGE_MODEL} for this name. Not an official vendor mark.")
    };
    Branding {
        cve_id: id.as_id(),
        name: named.name.clone(),
        tagline: named.tagline.clone(),
        blurb: named.blurb.clone(),
        logo_file: Some(format!("logo.{}", image.ext)),
        logo_credit: Some(logo_credit),
        official_site: None,
        official_site_label: None,
        prefilled: false,
        naming_model: if name_offline {
            None
        } else {
            Some(NAMING_MODEL.to_string())
        },
        image_model: if logo_offline {
            None
        } else {
            Some(IMAGE_MODEL.to_string())
        },
        naming_source: if name_offline { "offline" } else { "model" }.to_string(),
        logo_source: logo_source.to_string(),
        logo_prompt: if named.logo_prompt.is_empty() {
            None
        } else {
            Some(named.logo_prompt.clone())
        },
        created_at: now_rfc3339(),
        nvd,
    }
}

pub fn now_rfc3339() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    rfc3339(secs)
}

fn rfc3339(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let tod = secs % 86_400;
    let (year, month, day) = civil_from_days(days);
    let hour = tod / 3600;
    let minute = (tod % 3600) / 60;
    let second = tod % 60;
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

pub(crate) fn civil_from_days(days_since_unix: i64) -> (i32, u32, u32) {
    let z = days_since_unix + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let mut year = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    if month <= 2 {
        year += 1;
    }
    (year as i32, month as u32, day as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unix_epoch_and_a_known_instant() {
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339(1_700_000_000), "2023-11-14T22:13:20Z");
    }
}
