use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use uuid::Uuid;

pub(crate) fn write_atomic_unique(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    let tmp = unique_tmp_path(path)?;
    fs::write(&tmp, bytes).with_context(|| format!("write {}", tmp.display()))?;
    match fs::rename(&tmp, path).with_context(|| format!("replace {}", path.display())) {
        Ok(()) => Ok(()),
        Err(error) => {
            let _ = fs::remove_file(&tmp);
            Err(error)
        }
    }
}

fn unique_tmp_path(path: &Path) -> Result<PathBuf> {
    let file_name = path
        .file_name()
        .ok_or_else(|| anyhow!("path {} has no file name", path.display()))?
        .to_string_lossy();
    Ok(path.with_file_name(format!(
        ".{file_name}.{}.{}.tmp",
        std::process::id(),
        Uuid::new_v4()
    )))
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::write_atomic_unique;

    #[test]
    fn atomic_write_uses_unique_temp_file_and_leaves_legacy_tmp_alone() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("profile.json");
        let stale_tmp = path.with_extension("tmp");
        fs::write(&stale_tmp, b"stale").expect("write stale tmp");

        write_atomic_unique(&path, b"fresh").expect("write atomic");

        assert_eq!(fs::read(&path).expect("read output"), b"fresh");
        assert_eq!(fs::read(&stale_tmp).expect("read stale tmp"), b"stale");
    }

    #[test]
    fn atomic_write_cleans_unique_temp_file_after_replace_failure() {
        let dir = tempdir().expect("tempdir");
        let target_dir = dir.path().join("target");
        fs::create_dir(&target_dir).expect("create target dir");

        let error = write_atomic_unique(&target_dir, b"fresh").expect_err("replace should fail");
        assert!(error.to_string().contains("replace"));
        let leftovers: Vec<_> = fs::read_dir(dir.path())
            .expect("read dir")
            .map(|entry| {
                entry
                    .expect("entry")
                    .file_name()
                    .to_string_lossy()
                    .to_string()
            })
            .filter(|name| name.starts_with(".target.") && name.ends_with(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "leftover temp files: {leftovers:?}");
    }
}
