use std::path::{Path, PathBuf};

/// Directory that holds `static/`, `.env`, and the default `cache/`.
///
/// Order: `PROJECT_ROOT` if set, the current directory when it looks like this
/// project, then walk up from the executable until `static/` appears, then the
/// directory recorded at compile time.
pub fn project_root() -> PathBuf {
    let from_env = std::env::var("PROJECT_ROOT").ok();
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let exe = std::env::current_exe().ok();
    resolve_project_root(from_env.as_deref(), &cwd, exe.as_deref())
}

pub fn resolve_project_root(project_root_env: Option<&str>, cwd: &Path, exe: Option<&Path>) -> PathBuf {
    if let Some(value) = project_root_env.map(str::trim).filter(|value| !value.is_empty()) {
        return PathBuf::from(value);
    }
    if is_project_dir(cwd) {
        return cwd.to_path_buf();
    }
    if let Some(found) = exe.and_then(walk_for_static) {
        return found;
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn is_project_dir(dir: &Path) -> bool {
    dir.join("Cargo.toml").is_file() || dir.join("static").is_dir()
}

fn walk_for_static(exe: &Path) -> Option<PathBuf> {
    let mut dir = exe.parent()?.to_path_buf();
    loop {
        if dir.join("static").is_dir() {
            return Some(dir);
        }
        if !dir.pop() {
            return None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "brandeveryvuln-paths-{name}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn project_root_env_wins() {
        let cwd = scratch("cwd");
        let root = resolve_project_root(Some(" /srv/brand "), &cwd, None);
        assert_eq!(root, PathBuf::from("/srv/brand"));
        let _ = fs::remove_dir_all(&cwd);
    }

    #[test]
    fn cwd_with_cargo_toml_or_static_is_the_root() {
        let cwd = scratch("proj");
        fs::write(cwd.join("Cargo.toml"), "[package]\nname = \"x\"\n").unwrap();
        assert_eq!(resolve_project_root(None, &cwd, None), cwd);
        fs::remove_file(cwd.join("Cargo.toml")).unwrap();
        fs::create_dir(cwd.join("static")).unwrap();
        assert_eq!(resolve_project_root(Some("  "), &cwd, None), cwd);
        let _ = fs::remove_dir_all(&cwd);
    }

    #[test]
    fn walks_up_from_the_executable_to_static() {
        let root = scratch("exe");
        fs::create_dir_all(root.join("target/release")).unwrap();
        fs::create_dir(root.join("static")).unwrap();
        let exe = root.join("target/release/vulnmark");
        let elsewhere = scratch("empty");
        assert_eq!(resolve_project_root(None, &elsewhere, Some(&exe)), root);
        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&elsewhere);
    }
}
