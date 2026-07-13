use std::fmt::{Display, Formatter};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};

use futures_util::StreamExt;
use reqwest::header::{ACCEPT, CONTENT_TYPE, LOCATION};
use reqwest::{Client, StatusCode};
use url::{Host, Url};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const APPROVAL_TTL: Duration = Duration::from_secs(60);
const MAX_REDIRECTS: usize = 3;
const MAX_JSON_BYTES: usize = 512 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExternalResourceKind {
    ContactShare,
    GroupInvite,
}

impl ExternalResourceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ContactShare => "contact_share",
            Self::GroupInvite => "group_invite",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExternalNetworkClass {
    Public,
    Private,
}

#[derive(Debug, Clone)]
pub struct ExternalUrlAssessment {
    url: Url,
    origin: String,
    addresses: Vec<IpAddr>,
    purpose: ExternalResourceKind,
    network_class: ExternalNetworkClass,
}

impl ExternalUrlAssessment {
    pub fn origin(&self) -> &str {
        &self.origin
    }

    pub fn network_class(&self) -> ExternalNetworkClass {
        self.network_class
    }

    pub fn insecure_http(&self) -> bool {
        self.url.scheme() == "http"
    }

    pub fn approve(self) -> ExternalUrlApproval {
        ExternalUrlApproval {
            origin: self.origin,
            addresses: self.addresses,
            purpose: self.purpose,
            expires_at: Instant::now() + APPROVAL_TTL,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ExternalUrlApproval {
    origin: String,
    addresses: Vec<IpAddr>,
    purpose: ExternalResourceKind,
    expires_at: Instant,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalFetchError {
    code: &'static str,
    safe_detail: &'static str,
    origin: Option<String>,
}

impl ExternalFetchError {
    fn rejected(detail: &'static str) -> Self {
        Self {
            code: "external_url_rejected",
            safe_detail: detail,
            origin: None,
        }
    }

    fn approval_required(origin: String) -> Self {
        Self {
            code: "private_network_approval_required",
            safe_detail: "private network access requires explicit approval",
            origin: Some(origin),
        }
    }

    fn new(code: &'static str, detail: &'static str) -> Self {
        Self {
            code,
            safe_detail: detail,
            origin: None,
        }
    }

    pub fn code(&self) -> &'static str {
        self.code
    }

    pub fn origin(&self) -> Option<&str> {
        self.origin.as_deref()
    }
}

impl Display for ExternalFetchError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.code, self.safe_detail)
    }
}

impl std::error::Error for ExternalFetchError {}

pub async fn assess_external_url(
    raw_url: &str,
    purpose: ExternalResourceKind,
) -> Result<ExternalUrlAssessment, ExternalFetchError> {
    assess_parsed_url(parse_external_url(raw_url)?, purpose).await
}

pub async fn fetch_external_json(
    raw_url: &str,
    purpose: ExternalResourceKind,
    approval: Option<ExternalUrlApproval>,
) -> Result<String, ExternalFetchError> {
    tokio::time::timeout(
        REQUEST_TIMEOUT,
        fetch_external_json_within_deadline(raw_url, purpose, approval),
    )
    .await
    .map_err(|_| ExternalFetchError::new("external_fetch_timeout", "external fetch timed out"))?
}

async fn fetch_external_json_within_deadline(
    raw_url: &str,
    purpose: ExternalResourceKind,
    approval: Option<ExternalUrlApproval>,
) -> Result<String, ExternalFetchError> {
    let mut url = parse_external_url(raw_url)?;
    let mut previous_scheme: Option<String> = None;

    for redirect_count in 0..=MAX_REDIRECTS {
        let assessment = assess_parsed_url(url.clone(), purpose).await?;
        if previous_scheme.as_deref() == Some("https") && url.scheme() != "https" {
            return Err(ExternalFetchError::rejected(
                "HTTPS redirects may not downgrade",
            ));
        }
        verify_network_approval(&assessment, approval.as_ref())?;

        let response = build_pinned_client(&assessment)?
            .get(url.clone())
            .header(ACCEPT, "application/json")
            .send()
            .await
            .map_err(map_reqwest_error)?;

        if response.status().is_redirection() {
            if redirect_count == MAX_REDIRECTS {
                return Err(ExternalFetchError::rejected("too many redirects"));
            }
            let location = response
                .headers()
                .get(LOCATION)
                .and_then(|value| value.to_str().ok())
                .ok_or_else(|| ExternalFetchError::rejected("redirect location is invalid"))?;
            previous_scheme = Some(url.scheme().to_string());
            url = url
                .join(location)
                .map_err(|_| ExternalFetchError::rejected("redirect location is invalid"))?;
            continue;
        }

        if !response.status().is_success() {
            return Err(http_status_error(response.status()));
        }
        validate_json_content_type(response.headers().get(CONTENT_TYPE))?;
        if response
            .content_length()
            .is_some_and(|length| length > MAX_JSON_BYTES as u64)
        {
            return Err(ExternalFetchError::new(
                "external_response_too_large",
                "external JSON response exceeds the configured limit",
            ));
        }

        let mut body = Vec::new();
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(map_reqwest_error)?;
            if body.len().saturating_add(chunk.len()) > MAX_JSON_BYTES {
                return Err(ExternalFetchError::new(
                    "external_response_too_large",
                    "external JSON response exceeds the configured limit",
                ));
            }
            body.extend_from_slice(&chunk);
        }
        return String::from_utf8(body).map_err(|_| {
            ExternalFetchError::new(
                "external_content_type_invalid",
                "external JSON response must be UTF-8",
            )
        });
    }

    Err(ExternalFetchError::rejected("too many redirects"))
}

fn parse_external_url(raw_url: &str) -> Result<Url, ExternalFetchError> {
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

async fn assess_parsed_url(
    url: Url,
    purpose: ExternalResourceKind,
) -> Result<ExternalUrlAssessment, ExternalFetchError> {
    let origin = normalized_origin(&url)?;
    let addresses = resolve_addresses(&url).await?;
    let mut has_private = false;
    for address in &addresses {
        match classify_address(*address) {
            AddressDisposition::Public => {}
            AddressDisposition::Private => has_private = true,
            AddressDisposition::Forbidden => {
                return Err(ExternalFetchError::rejected(
                    "external URL resolves to a forbidden address",
                ));
            }
        }
    }
    let network_class = if has_private {
        ExternalNetworkClass::Private
    } else {
        ExternalNetworkClass::Public
    };
    if network_class == ExternalNetworkClass::Public && url.scheme() != "https" {
        return Err(ExternalFetchError::rejected(
            "public external URLs must use HTTPS",
        ));
    }
    Ok(ExternalUrlAssessment {
        url,
        origin,
        addresses,
        purpose,
        network_class,
    })
}

async fn resolve_addresses(url: &Url) -> Result<Vec<IpAddr>, ExternalFetchError> {
    let host = url
        .host()
        .ok_or_else(|| ExternalFetchError::rejected("external URL host is missing"))?;
    let mut addresses = match host {
        Host::Ipv4(address) => vec![IpAddr::V4(address)],
        Host::Ipv6(address) => vec![IpAddr::V6(address)],
        Host::Domain(domain) => {
            tokio::net::lookup_host((domain, url.port_or_known_default().unwrap_or(443)))
                .await
                .map_err(|_| {
                    ExternalFetchError::new(
                        "external_url_rejected",
                        "external URL DNS lookup failed",
                    )
                })?
                .map(|socket| socket.ip())
                .collect()
        }
    };
    addresses.sort();
    addresses.dedup();
    if addresses.is_empty() {
        return Err(ExternalFetchError::rejected(
            "external URL has no resolved address",
        ));
    }
    Ok(addresses)
}

fn verify_network_approval(
    assessment: &ExternalUrlAssessment,
    approval: Option<&ExternalUrlApproval>,
) -> Result<(), ExternalFetchError> {
    if assessment.network_class == ExternalNetworkClass::Public {
        return Ok(());
    }
    let approved = approval.is_some_and(|approval| {
        approval.expires_at > Instant::now()
            && approval.purpose == assessment.purpose
            && approval.origin == assessment.origin
            && approval.addresses == assessment.addresses
    });
    if approved {
        Ok(())
    } else {
        Err(ExternalFetchError::approval_required(
            assessment.origin.clone(),
        ))
    }
}

fn build_pinned_client(assessment: &ExternalUrlAssessment) -> Result<Client, ExternalFetchError> {
    let port = assessment.url.port_or_known_default().unwrap_or(443);
    let mut builder = Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(REQUEST_TIMEOUT);
    if let Some(Host::Domain(domain)) = assessment.url.host() {
        let sockets: Vec<SocketAddr> = assessment
            .addresses
            .iter()
            .map(|address| SocketAddr::new(*address, port))
            .collect();
        builder = builder.resolve_to_addrs(domain, &sockets);
    }
    builder.build().map_err(|_| {
        ExternalFetchError::new(
            "external_url_rejected",
            "external fetch client could not be created",
        )
    })
}

fn normalized_origin(url: &Url) -> Result<String, ExternalFetchError> {
    let host = url
        .host_str()
        .ok_or_else(|| ExternalFetchError::rejected("external URL host is missing"))?;
    let port = url.port_or_known_default().unwrap_or(443);
    Ok(format!("{}://{}:{}", url.scheme(), host, port))
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AddressDisposition {
    Public,
    Private,
    Forbidden,
}

fn classify_address(address: IpAddr) -> AddressDisposition {
    match address {
        IpAddr::V4(address) => classify_ipv4(address),
        IpAddr::V6(address) => classify_ipv6(address),
    }
}

fn classify_ipv4(address: Ipv4Addr) -> AddressDisposition {
    let octets = address.octets();
    if address.is_unspecified()
        || address.is_multicast()
        || address.is_broadcast()
        || address.is_link_local()
        || address.is_documentation()
        || (octets[0] == 198 && matches!(octets[1], 18 | 19))
        || octets[0] >= 240
    {
        AddressDisposition::Forbidden
    } else if address.is_loopback()
        || address.is_private()
        || (octets[0] == 100 && (64..=127).contains(&octets[1]))
    {
        AddressDisposition::Private
    } else {
        AddressDisposition::Public
    }
}

fn classify_ipv6(address: Ipv6Addr) -> AddressDisposition {
    if let Some(mapped) = address.to_ipv4_mapped() {
        return classify_ipv4(mapped);
    }
    let segments = address.segments();
    let is_documentation = segments[0] == 0x2001 && segments[1] == 0x0db8;
    if address.is_unspecified()
        || address.is_multicast()
        || address.is_unicast_link_local()
        || is_documentation
    {
        AddressDisposition::Forbidden
    } else if address.is_loopback() || (segments[0] & 0xfe00) == 0xfc00 {
        AddressDisposition::Private
    } else {
        AddressDisposition::Public
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    fn serve_once(content_type: &str, body: String) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test server");
        let address = listener.local_addr().expect("server address");
        let content_type = content_type.to_string();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept request");
            let mut request = [0_u8; 2048];
            let _ = stream.read(&mut request);
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                content_type,
                body.len(),
                body
            )
            .expect("write response");
        });
        format!("http://{address}/document")
    }

    #[test]
    fn address_policy_distinguishes_public_private_and_forbidden_ranges() {
        assert_eq!(
            classify_address("8.8.8.8".parse().unwrap()),
            AddressDisposition::Public
        );
        assert_eq!(
            classify_address("127.0.0.1".parse().unwrap()),
            AddressDisposition::Private
        );
        assert_eq!(
            classify_address("10.0.0.1".parse().unwrap()),
            AddressDisposition::Private
        );
        assert_eq!(
            classify_address("100.64.0.1".parse().unwrap()),
            AddressDisposition::Private
        );
        assert_eq!(
            classify_address("169.254.169.254".parse().unwrap()),
            AddressDisposition::Forbidden
        );
        assert_eq!(
            classify_address("2001:db8::1".parse().unwrap()),
            AddressDisposition::Forbidden
        );
    }

    #[test]
    fn url_credentials_and_unsupported_schemes_are_rejected() {
        assert_eq!(
            parse_external_url("https://user:pass@example.com/share")
                .unwrap_err()
                .code(),
            "external_url_rejected"
        );
        assert_eq!(
            parse_external_url("file:///etc/passwd").unwrap_err().code(),
            "external_url_rejected"
        );
    }

    #[tokio::test]
    async fn private_http_requires_a_matching_one_shot_approval() {
        let unapproved = fetch_external_json(
            "http://127.0.0.1:9/document",
            ExternalResourceKind::ContactShare,
            None,
        )
        .await
        .expect_err("private URL must require approval");
        assert_eq!(unapproved.code(), "private_network_approval_required");

        let url = serve_once("application/json", "{\"ok\":true}".into());
        let assessment = assess_external_url(&url, ExternalResourceKind::ContactShare)
            .await
            .expect("assessment");
        assert_eq!(assessment.network_class(), ExternalNetworkClass::Private);
        let body = fetch_external_json(
            &url,
            ExternalResourceKind::ContactShare,
            Some(assessment.approve()),
        )
        .await
        .expect("approved fetch");
        assert_eq!(body, "{\"ok\":true}");
    }

    #[tokio::test]
    async fn content_type_and_streaming_size_limits_are_enforced() {
        let wrong_type_url = serve_once("text/plain", "{}".into());
        let wrong_type_approval =
            assess_external_url(&wrong_type_url, ExternalResourceKind::GroupInvite)
                .await
                .expect("assessment")
                .approve();
        let wrong_type = fetch_external_json(
            &wrong_type_url,
            ExternalResourceKind::GroupInvite,
            Some(wrong_type_approval),
        )
        .await
        .expect_err("non-JSON response must fail");
        assert_eq!(wrong_type.code(), "external_content_type_invalid");

        let oversized_url = serve_once("application/json", "x".repeat(MAX_JSON_BYTES + 1));
        let oversized_approval =
            assess_external_url(&oversized_url, ExternalResourceKind::ContactShare)
                .await
                .expect("assessment")
                .approve();
        let oversized = fetch_external_json(
            &oversized_url,
            ExternalResourceKind::ContactShare,
            Some(oversized_approval),
        )
        .await
        .expect_err("oversized response must fail");
        assert_eq!(oversized.code(), "external_response_too_large");
    }
}
