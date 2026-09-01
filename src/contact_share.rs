use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::error::{CoreError, CoreResult};
use crate::model::CURRENT_MODEL_VERSION;

pub fn encode_contact_share_url(
    base_url: &str,
    secret: &str,
    user_id: &str,
    share_id: &str,
) -> CoreResult<String> {
    if base_url.trim().is_empty()
        || secret.is_empty()
        || user_id.trim().is_empty()
        || share_id.trim().is_empty()
    {
        return Err(CoreError::invalid_input(
            "contact share URL inputs must not be empty",
        ));
    }
    let payload = serde_json::json!({
        "version": CURRENT_MODEL_VERSION,
        "service": "contact_share",
        "userId": user_id,
        "shareId": share_id,
    });
    let payload_bytes = serde_json::to_vec(&payload)
        .map_err(|_| CoreError::invalid_state("failed to encode contact share payload"))?;
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
        .map_err(|_| CoreError::invalid_state("failed to initialize contact share signer"))?;
    mac.update(&payload_bytes);
    let signature = mac.finalize().into_bytes();
    let token = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(payload_bytes),
        URL_SAFE_NO_PAD.encode(signature)
    );
    Ok(format!(
        "{}/v1/contact-share/{token}",
        base_url.trim_end_matches('/')
    ))
}

#[cfg(test)]
mod tests {
    use super::encode_contact_share_url;

    #[test]
    fn encoder_only_emits_canonical_contact_share_path() {
        let url = encode_contact_share_url(
            "https://runtime.example/",
            "0123456789abcdef0123456789abcdef",
            "user:alice",
            "share:1",
        )
        .expect("contact share URL");
        assert!(url.starts_with("https://runtime.example/v1/contact-share/"));
        assert!(!url.contains("identity-bundle"));
    }
}
