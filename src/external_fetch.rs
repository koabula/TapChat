use std::fmt::{Display, Formatter};
use std::time::Duration;

use futures_util::StreamExt;
use reqwest::header::{ACCEPT, CONTENT_TYPE};
use reqwest::{Client, StatusCode};
use url::Url;

use crate::model::{GroupInviteDocument, Validate};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_JSON_BYTES: usize = 512 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExternalResourceKind {
    ContactShare,
    GroupInvite,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalFetchError {
    code: &'static str,
    safe_detail: &'static str,
}

impl ExternalFetchError {
    fn rejected(detail: &'static str) -> Self {
        Self {
            code: "external_url_rejected",
            safe_detail: detail,
        }
    }

    fn new(code: &'static str, detail: &'static str) -> Self {
        Self {
            code,
            safe_detail: detail,
        }
    }

    pub fn code(&self) -> &'static str {
        self.code
    }
}

impl Display for ExternalFetchError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.code, self.safe_detail)
    }
}

impl std::error::Error for ExternalFetchError {}

pub fn validate_external_url(
    raw_url: &str,
    purpose: ExternalResourceKind,
) -> Result<Url, ExternalFetchError> {
    let url = parse_http_url(raw_url)?;
    validate_tapchat_path(&url, purpose)?;
    Ok(url)
}

pub async fn fetch_external_json(
    raw_url: &str,
    purpose: ExternalResourceKind,
) -> Result<String, ExternalFetchError> {
    tokio::time::timeout(
        REQUEST_TIMEOUT,
        fetch_external_json_within_deadline(raw_url, purpose),
    )
    .await
    .map_err(|_| ExternalFetchError::new("external_fetch_timeout", "external fetch timed out"))?
}

async fn fetch_external_json_within_deadline(
    raw_url: &str,
    purpose: ExternalResourceKind,
) -> Result<String, ExternalFetchError> {
    let url = validate_external_url(raw_url, purpose)?;
    let response = build_client()?
        .get(url)
        .header(ACCEPT, "application/json")
        .send()
        .await
        .map_err(map_reqwest_error)?;

    if response.status().is_redirection() {
        return Err(ExternalFetchError::rejected(
            "external URL redirects are not allowed",
        ));
    }
    if !response.status().is_success() {
        return Err(http_status_error(response.status()));
    }
    validate_json_content_type(response.headers().get(CONTENT_TYPE))?;
    if response
        .content_length()
        .is_some_and(|length| length > MAX_JSON_BYTES as u64)
    {
        return Err(response_too_large());
    }

    let mut body = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(map_reqwest_error)?;
        if body.len().saturating_add(chunk.len()) > MAX_JSON_BYTES {
            return Err(response_too_large());
        }
        body.extend_from_slice(&chunk);
    }
    String::from_utf8(body).map_err(|_| {
        ExternalFetchError::new(
            "external_content_type_invalid",
            "external JSON response must be UTF-8",
        )
    })
}

pub fn validate_group_invite_transport_binding(
    invite_url: &str,
    invite: &GroupInviteDocument,
) -> Result<(), ExternalFetchError> {
    invite
        .validate()
        .map_err(|_| ExternalFetchError::rejected("group invite document is invalid"))?;
    let invite_url = validate_external_url(invite_url, ExternalResourceKind::GroupInvite)?;
    let invite_segments = decoded_path_segments(&invite_url)?;

    if invite_segments.len() == 4
        && (invite_segments[2] != invite.group_id || invite_segments[3] != invite.invite_id)
    {
        return Err(ExternalFetchError::rejected(
            "group invite URL does not match the invite document",
        ));
    }

    let join_url = parse_http_url(&invite.join_request_endpoint)?;
    if !same_origin(&invite_url, &join_url) {
        return Err(ExternalFetchError::rejected(
            "group join endpoint must use the invite origin",
        ));
    }
    let join_segments = decoded_path_segments(&join_url)?;
    if join_segments.as_slice() != ["v1", "groups", invite.group_id.as_str(), "join-requests"] {
        return Err(ExternalFetchError::rejected(
            "group join endpoint path is invalid",
        ));
    }
    Ok(())
}

fn parse_http_url(raw_url: &str) -> Result<Url, ExternalFetchError> {
    let url = Url::parse(raw_url.trim())
        .map_err(|_| ExternalFetchError::rejected("external URL is invalid"))?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(ExternalFetchError::rejected(
            "external URL scheme is not allowed",
        ));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(ExternalFetchError::rejected(
            "external URL credentials are not allowed",
        ));
    }
    if url.host().is_none() {
        return Err(ExternalFetchError::rejected("external URL host is missing"));
    }
    Ok(url)
}

fn validate_tapchat_path(
    url: &Url,
    purpose: ExternalResourceKind,
) -> Result<(), ExternalFetchError> {
    let segments = decoded_path_segments(url)?;
    let valid = match purpose {
        ExternalResourceKind::ContactShare => {
            matches!(segments.as_slice(), [v1, contact_share, token]
                if v1 == "v1" && contact_share == "contact-share" && !token.is_empty())
                || matches!(segments.as_slice(), [v1, shared_state, user_id, identity_bundle]
                    if v1 == "v1"
                        && shared_state == "shared-state"
                        && !user_id.is_empty()
                        && identity_bundle == "identity-bundle")
        }
        ExternalResourceKind::GroupInvite => {
            matches!(segments.as_slice(), [v1, group_invite, token]
                if v1 == "v1" && group_invite == "group-invite" && !token.is_empty())
                || matches!(segments.as_slice(), [v1, group_invite, group_id, invite_id]
                    if v1 == "v1"
                        && group_invite == "group-invite"
                        && !group_id.is_empty()
                        && !invite_id.is_empty())
        }
    };
    if valid {
        Ok(())
    } else {
        Err(ExternalFetchError::rejected(
            "external URL path is not a TapChat endpoint",
        ))
    }
}

fn decoded_path_segments(url: &Url) -> Result<Vec<String>, ExternalFetchError> {
    url.path_segments()
        .ok_or_else(|| ExternalFetchError::rejected("external URL path is invalid"))?
        .map(|segment| {
            urlencoding::decode(segment)
                .map(|decoded| decoded.into_owned())
                .map_err(|_| ExternalFetchError::rejected("external URL path is invalid"))
        })
        .collect()
}

fn same_origin(left: &Url, right: &Url) -> bool {
    left.scheme() == right.scheme()
        && left.host_str() == right.host_str()
        && left.port_or_known_default() == right.port_or_known_default()
}

fn build_client() -> Result<Client, ExternalFetchError> {
    Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(REQUEST_TIMEOUT)
        .build()
        .map_err(|_| {
            ExternalFetchError::new(
                "external_url_rejected",
                "external fetch client could not be created",
            )
        })
}

fn validate_json_content_type(
    content_type: Option<&reqwest::header::HeaderValue>,
) -> Result<(), ExternalFetchError> {
    let media_type = content_type
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .map(str::trim)
        .unwrap_or_default();
    if media_type == "application/json" || media_type.ends_with("+json") {
        Ok(())
    } else {
        Err(ExternalFetchError::new(
            "external_content_type_invalid",
            "external response is not JSON",
        ))
    }
}

fn response_too_large() -> ExternalFetchError {
    ExternalFetchError::new(
        "external_response_too_large",
        "external JSON response exceeds the configured limit",
    )
}

fn map_reqwest_error(error: reqwest::Error) -> ExternalFetchError {
    if error.is_timeout() {
        ExternalFetchError::new("external_fetch_timeout", "external fetch timed out")
    } else {
        ExternalFetchError::new("external_url_rejected", "external fetch failed")
    }
}

fn http_status_error(status: StatusCode) -> ExternalFetchError {
    let detail = if status.is_server_error() {
        "external service returned a server error"
    } else {
        "external service rejected the request"
    };
    ExternalFetchError::new("external_fetch_http_status", detail)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    use crate::model::{CURRENT_MODEL_VERSION, GroupJoinPolicy};

    fn serve_once(status: &str, content_type: &str, body: String, extra_headers: &str) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test server");
        let address = listener.local_addr().expect("server address");
        let content_type = content_type.to_string();
        let status = status.to_string();
        let extra_headers = extra_headers.to_string();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept request");
            let mut request = [0_u8; 2048];
            let _ = stream.read(&mut request);
            write!(
                stream,
                "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n{extra_headers}Connection: close\r\n\r\n{body}",
                body.len(),
            )
            .expect("write response");
        });
        format!("http://{address}/v1/contact-share/test-token")
    }

    fn sample_invite(join_request_endpoint: String) -> GroupInviteDocument {
        GroupInviteDocument {
            version: CURRENT_MODEL_VERSION.into(),
            group_id: "group:project".into(),
            title: "Project".into(),
            invite_id: "invite:one".into(),
            join_policy: GroupJoinPolicy::ApprovalRequired,
            inviter_user_id: "user:alice".into(),
            inviter_device_id: "device:alice:laptop".into(),
            inviter_contact_share_url: None,
            owner_user_id: "user:alice".into(),
            owner_contact_share_url: None,
            join_request_endpoint,
            created_at: 1,
            expires_at: u64::MAX,
            max_uses: None,
            signature: "invite-capability".into(),
        }
    }

    #[test]
    fn url_policy_accepts_lan_fake_ip_and_canonical_paths() {
        for url in [
            "http://127.0.0.1:8787/v1/contact-share/token",
            "https://198.18.0.1/v1/contact-share/token",
            "https://192.168.1.2/v1/shared-state/user%3Aalice/identity-bundle",
        ] {
            validate_external_url(url, ExternalResourceKind::ContactShare)
                .expect("TapChat contact URL should be accepted");
        }
        validate_external_url(
            "http://10.0.0.2/v1/group-invite/group%3Aproject/invite%3Aone",
            ExternalResourceKind::GroupInvite,
        )
        .expect("TapChat group URL should be accepted");
    }

    #[test]
    fn invalid_paths_credentials_and_schemes_are_rejected() {
        for url in [
            "https://example.com/not-tapchat",
            "https://user:pass@example.com/v1/contact-share/token",
            "file:///v1/contact-share/token",
        ] {
            assert_eq!(
                validate_external_url(url, ExternalResourceKind::ContactShare)
                    .unwrap_err()
                    .code(),
                "external_url_rejected"
            );
        }
    }

    #[test]
    fn group_invite_binding_requires_matching_origin_path_and_ids() {
        let invite_url = "https://worker.example/v1/group-invite/group%3Aproject/invite%3Aone";
        let valid =
            sample_invite("https://worker.example/v1/groups/group%3Aproject/join-requests".into());
        validate_group_invite_transport_binding(invite_url, &valid)
            .expect("valid group transport binding");

        let cross_origin = sample_invite(
            "https://internal.example/v1/groups/group%3Aproject/join-requests".into(),
        );
        assert!(validate_group_invite_transport_binding(invite_url, &cross_origin).is_err());

        let wrong_path = sample_invite("https://worker.example/v1/storage/prepare-upload".into());
        assert!(validate_group_invite_transport_binding(invite_url, &wrong_path).is_err());

        let wrong_ids = "https://worker.example/v1/group-invite/group%3Aother/invite%3Aone";
        assert!(validate_group_invite_transport_binding(wrong_ids, &valid).is_err());
    }

    #[tokio::test]
    async fn local_http_fetch_is_allowed_without_network_approval() {
        let url = serve_once("200 OK", "application/json", "{\"ok\":true}".into(), "");
        let body = fetch_external_json(&url, ExternalResourceKind::ContactShare)
            .await
            .expect("local TapChat URL should be fetched");
        assert_eq!(body, "{\"ok\":true}");
    }

    #[tokio::test]
    async fn redirects_are_rejected() {
        let url = serve_once(
            "302 Found",
            "application/json",
            String::new(),
            "Location: http://127.0.0.1/v1/contact-share/other\r\n",
        );
        let error = fetch_external_json(&url, ExternalResourceKind::ContactShare)
            .await
            .expect_err("redirect must fail");
        assert_eq!(error.code(), "external_url_rejected");
    }

    #[tokio::test]
    async fn content_type_and_streaming_size_limits_are_enforced() {
        let wrong_type_url = serve_once("200 OK", "text/plain", "{}".into(), "");
        let wrong_type = fetch_external_json(&wrong_type_url, ExternalResourceKind::ContactShare)
            .await
            .expect_err("non-JSON response must fail");
        assert_eq!(wrong_type.code(), "external_content_type_invalid");

        let oversized_url = serve_once(
            "200 OK",
            "application/json",
            "x".repeat(MAX_JSON_BYTES + 1),
            "",
        );
        let oversized = fetch_external_json(&oversized_url, ExternalResourceKind::ContactShare)
            .await
            .expect_err("oversized response must fail");
        assert_eq!(oversized.code(), "external_response_too_large");
    }
}
