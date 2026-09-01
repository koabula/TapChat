use std::path::PathBuf;

use anyhow::{Result, bail};

const CACHE_NAMESPACE: &str = "attachment-cache";
const CACHE_OBJECTS_DIR: &str = "objects";
const CACHE_EXTENSION: &str = ".enc";
const CACHE_ID_LEN: usize = 64;

/// Platform-independent identifier for a profile-encrypted media cache entry.
///
/// `destination_id` is an opaque Core/platform contract, not an OS path. Its
/// encoded form therefore always uses `/`; `parse` also accepts `\` so pending
/// downloads persisted by older Windows builds remain recoverable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EncryptedCacheDestination {
    cache_id: String,
}

impl EncryptedCacheDestination {
    pub(crate) fn from_cache_id(cache_id: &str) -> Result<Self> {
        if cache_id.len() != CACHE_ID_LEN
            || !cache_id
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            bail!("invalid encrypted media cache id");
        }
        Ok(Self {
            cache_id: cache_id.to_string(),
        })
    }

    pub(crate) fn parse(destination_id: &str) -> Result<Option<Self>> {
        let normalized = destination_id.replace('\\', "/");
        let mut segments = normalized.split('/');
        if segments.next() != Some(CACHE_NAMESPACE) {
            return Ok(None);
        }
        let Some(file_name) = segments.next() else {
            bail!("invalid encrypted media cache destination");
        };
        if segments.next().is_some() || file_name.is_empty() {
            bail!("invalid encrypted media cache destination");
        }
        let Some(cache_id) = file_name.strip_suffix(CACHE_EXTENSION) else {
            bail!("invalid encrypted media cache destination");
        };
        Self::from_cache_id(cache_id).map(Some)
    }

    pub(crate) fn cache_id(&self) -> &str {
        &self.cache_id
    }

    pub(crate) fn destination_id(&self) -> String {
        format!("{CACHE_NAMESPACE}/{}{CACHE_EXTENSION}", self.cache_id)
    }

    pub(crate) fn relative_path(&self) -> PathBuf {
        PathBuf::from(CACHE_OBJECTS_DIR).join(format!("{}{CACHE_EXTENSION}", self.cache_id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CACHE_ID: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn destination_encoding_is_platform_independent() {
        let destination = EncryptedCacheDestination::from_cache_id(CACHE_ID).expect("cache id");
        assert_eq!(
            destination.destination_id(),
            format!("attachment-cache/{CACHE_ID}.enc")
        );
    }

    #[test]
    fn parser_accepts_canonical_and_legacy_windows_separators() {
        for destination_id in [
            format!("attachment-cache/{CACHE_ID}.enc"),
            format!("attachment-cache\\{CACHE_ID}.enc"),
        ] {
            let parsed = EncryptedCacheDestination::parse(&destination_id)
                .expect("valid destination")
                .expect("encrypted cache destination");
            assert_eq!(parsed.cache_id(), CACHE_ID);
            assert_eq!(
                parsed.relative_path(),
                PathBuf::from("objects").join(format!("{CACHE_ID}.enc"))
            );
        }
    }

    #[test]
    fn parser_rejects_malformed_or_traversing_cache_destinations() {
        for destination_id in [
            "attachment-cache",
            "attachment-cache/../outside.enc",
            "attachment-cache/not-a-digest.enc",
            "attachment-cache/0123.txt",
            "attachment-cache/nested/0123.enc",
        ] {
            assert!(EncryptedCacheDestination::parse(destination_id).is_err());
        }
        assert!(
            EncryptedCacheDestination::parse("ordinary-download/photo.jpg")
                .expect("ordinary destination")
                .is_none()
        );
    }
}
