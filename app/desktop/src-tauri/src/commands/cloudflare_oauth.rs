use std::fs;
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::OnceLock;

use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rand::RngCore;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use crate::commands::cloudflare_rest::{AccountInfo, OAuthTokens, WhoamiResult};

const CF_API_BASE: &str = "https://api.cloudflare.com/client/v4";
const CLIENT_ID: &str = "54d11594-84e4-41aa-b438-e81b8fa78ee7";
const REDIRECT_PORT: u16 = 8976;
const REDIRECT_PATH: &str = "/oauth/callback";
const TOKEN_URL: &str = "https://dash.cloudflare.com/oauth2/token";
const AUTH_URL: &str = "https://dash.cloudflare.com/oauth2/auth";
const TOKEN_SERVICE: &str = "TapChat Cloudflare OAuth";
const TOKEN_ACCOUNT: &str = "default";
const SCOPES: &str = "account:read user:read workers:write workers_kv:write workers_scripts:write workers_tail:read d1:write offline_access";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredCloudflareToken {
    access_token: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    refresh_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    account_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    account_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    email: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    expires_at_ms: Option<u64>,
}

#[derive(Debug, Clone, Deserialize)]
struct CloudflareEnvelope<T> {
    success: bool,
    #[serde(default)]
    result: Option<T>,
    #[serde(default)]
    errors: Vec<CloudflareApiError>,
}

#[derive(Debug, Clone, Deserialize)]
struct CloudflareApiError {
    #[serde(default)]
    message: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
struct UserResult {
    email: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
struct AccountResult {
    id: String,
    name: String,
}

#[derive(Debug, Clone, Deserialize)]
struct TokenExchangeResponse {
    access_token: String,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    expires_in: Option<u64>,
}

const ACCESS_TOKEN_REFRESH_SKEW_MS: u64 = 5 * 60 * 1000;

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn refresh_gate() -> &'static tokio::sync::Mutex<()> {
    static GATE: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
    GATE.get_or_init(|| tokio::sync::Mutex::new(()))
}

fn access_token_needs_refresh(token: &StoredCloudflareToken, now: u64) -> bool {
    token
        .expires_at_ms
        .is_none_or(|expires| expires <= now.saturating_add(ACCESS_TOKEN_REFRESH_SKEW_MS))
}

pub async fn login() -> Result<OAuthTokens> {
    let code_verifier = generate_code_verifier();
    let code_challenge = generate_code_challenge(&code_verifier);
    let redirect_uri = redirect_uri();
    let state = uuid::Uuid::new_v4().to_string();

    let mut auth_url = url::Url::parse(AUTH_URL)?;
    auth_url
        .query_pairs_mut()
        .append_pair("client_id", CLIENT_ID)
        .append_pair("response_type", "code")
        .append_pair("redirect_uri", &redirect_uri)
        .append_pair("scope", SCOPES)
        .append_pair("state", &state)
        .append_pair("code_challenge", &code_challenge)
        .append_pair("code_challenge_method", "S256");

    let listener = TcpListener::bind(("127.0.0.1", REDIRECT_PORT))
        .await
        .with_context(|| format!("bind Cloudflare OAuth callback on 127.0.0.1:{REDIRECT_PORT}"))?;

    open::that(auth_url.as_str())
        .with_context(|| "open Cloudflare authorization URL in the system browser")?;

    let code = tokio::time::timeout(
        std::time::Duration::from_secs(120),
        wait_for_oauth_code(listener, &state),
    )
    .await
    .map_err(|_| anyhow!("OAuth timeout: no response within 120 seconds"))??;

    let token = exchange_code_for_token(&code, &code_verifier, &redirect_uri).await?;
    let whoami = whoami_for_token(&token.access_token).await?;
    let account = whoami
        .accounts
        .first()
        .cloned()
        .ok_or_else(|| anyhow!("Cloudflare account not found"))?;

    store_token(&StoredCloudflareToken {
        access_token: token.access_token.clone(),
        refresh_token: token.refresh_token.clone(),
        account_id: Some(account.account_id.clone()),
        account_name: Some(account.account_name.clone()),
        email: whoami.email.clone(),
        expires_at_ms: token
            .expires_in
            .map(|seconds| now_ms().saturating_add(seconds.saturating_mul(1000))),
    })?;

    Ok(OAuthTokens {
        success: true,
        access_token: Some(token.access_token),
        refresh_token: token.refresh_token,
        expires_in: token.expires_in,
        account_id: Some(account.account_id),
        account_name: Some(account.account_name),
        error: None,
    })
}

pub async fn whoami() -> Result<WhoamiResult> {
    let access_token = valid_access_token(false, None).await?;
    let mut result = match whoami_for_token(&access_token).await {
        Ok(result) => result,
        Err(error) if error.to_string().contains("cloudflare_api_unauthorized") => {
            let access_token = valid_access_token(true, Some(&access_token)).await?;
            whoami_for_token(&access_token).await?
        }
        Err(error) => return Err(error),
    };
    let token = load_token()?;
    if result.active_account_id.is_none() {
        result.active_account_id = token.account_id.clone().or_else(|| {
            result
                .accounts
                .first()
                .map(|account| account.account_id.clone())
        });
    }
    Ok(result)
}

pub async fn load_access_token() -> Result<String> {
    valid_access_token(false, None).await
}

pub async fn force_refresh_access_token(stale_access_token: &str) -> Result<String> {
    valid_access_token(true, Some(stale_access_token)).await
}

async fn valid_access_token(force: bool, stale_access_token: Option<&str>) -> Result<String> {
    let _guard = refresh_gate().lock().await;
    let mut token = load_token()?;
    if force
        && stale_access_token.is_some_and(|stale| stale != token.access_token)
        && !access_token_needs_refresh(&token, now_ms())
    {
        return Ok(token.access_token);
    }
    if !force && !access_token_needs_refresh(&token, now_ms()) {
        return Ok(token.access_token);
    }
    let refresh_token = token
        .refresh_token
        .clone()
        .ok_or_else(|| anyhow!("oauth_login_required: Cloudflare refresh token is missing"))?;
    let refreshed = refresh_access_token(&refresh_token).await?;
    apply_token_refresh(&mut token, refreshed, now_ms());
    store_token(&token)?;
    Ok(token.access_token)
}

fn apply_token_refresh(
    token: &mut StoredCloudflareToken,
    refreshed: TokenExchangeResponse,
    refreshed_at_ms: u64,
) {
    token.access_token = refreshed.access_token;
    if let Some(rotated) = refreshed.refresh_token.filter(|value| !value.is_empty()) {
        token.refresh_token = Some(rotated);
    }
    token.expires_at_ms = refreshed
        .expires_in
        .map(|seconds| refreshed_at_ms.saturating_add(seconds.saturating_mul(1000)));
}

fn load_token() -> Result<StoredCloudflareToken> {
    load_keychain_token().map_err(|keychain_error| {
        anyhow!(
            "Cloudflare OAuth token not found in OS keychain. Use the explicit legacy Wrangler import command if you want to migrate an old plaintext token: {keychain_error}"
        )
    })
}

pub fn import_legacy_wrangler_token() -> Result<()> {
    let token = load_wrangler_token()?;
    store_token(&token)
}

fn load_keychain_token() -> Result<StoredCloudflareToken> {
    let entry = keyring::Entry::new(TOKEN_SERVICE, TOKEN_ACCOUNT)
        .context("create Cloudflare OAuth keychain entry")?;
    let encoded = entry
        .get_password()
        .context("read Cloudflare OAuth token from OS keychain")?;
    serde_json::from_str(&encoded).context("decode Cloudflare OAuth keychain token")
}

fn store_token(token: &StoredCloudflareToken) -> Result<()> {
    let entry = keyring::Entry::new(TOKEN_SERVICE, TOKEN_ACCOUNT)
        .context("create Cloudflare OAuth keychain entry")?;
    entry
        .set_password(&serde_json::to_string(token)?)
        .context("store Cloudflare OAuth token in OS keychain")
}

fn load_wrangler_token() -> Result<StoredCloudflareToken> {
    let content =
        fs::read_to_string(wrangler_config_path()?).context("read legacy Wrangler OAuth token")?;
    let access_token = parse_toml_string(&content, "oauth_token")
        .ok_or_else(|| anyhow!("legacy Wrangler config missing oauth_token"))?;
    Ok(StoredCloudflareToken {
        access_token,
        refresh_token: parse_toml_string(&content, "refresh_token"),
        account_id: parse_toml_string(&content, "account_id"),
        account_name: None,
        email: None,
        expires_at_ms: None,
    })
}

fn wrangler_config_path() -> Result<PathBuf> {
    Ok(dirs::home_dir()
        .ok_or_else(|| anyhow!("cannot determine home directory"))?
        .join(".wrangler")
        .join("config")
        .join("default.toml"))
}

fn parse_toml_string(content: &str, key: &str) -> Option<String> {
    content.lines().find_map(|line| {
        let trimmed = line.trim();
        let prefix = format!("{key} = ");
        let value = trimmed.strip_prefix(&prefix)?;
        Some(value.trim().trim_matches('"').to_string()).filter(|value| !value.is_empty())
    })
}

async fn whoami_for_token(access_token: &str) -> Result<WhoamiResult> {
    let client = Client::builder()
        .build()
        .context("build Cloudflare client")?;
    let user = get_user_info(&client, access_token).await?;
    let accounts = get_account_info(&client, access_token).await?;
    Ok(WhoamiResult {
        authenticated: true,
        email: user.email.clone(),
        accounts,
        active_account_id: None,
        error: None,
    })
}

async fn get_user_info(client: &Client, access_token: &str) -> Result<UserResult> {
    let response = client
        .get(format!("{CF_API_BASE}/user"))
        .bearer_auth(access_token)
        .header("Accept", "application/json")
        .send()
        .await
        .context("request Cloudflare user")?;
    if response.status() == reqwest::StatusCode::UNAUTHORIZED {
        bail!("cloudflare_api_unauthorized");
    }
    let envelope = response
        .json::<CloudflareEnvelope<UserResult>>()
        .await
        .context("decode Cloudflare user response")?;
    unwrap_cloudflare_result(envelope, "Cloudflare user")
}

async fn get_account_info(client: &Client, access_token: &str) -> Result<Vec<AccountInfo>> {
    let response = client
        .get(format!("{CF_API_BASE}/accounts"))
        .bearer_auth(access_token)
        .header("Accept", "application/json")
        .send()
        .await
        .context("request Cloudflare accounts")?;
    if response.status() == reqwest::StatusCode::UNAUTHORIZED {
        bail!("cloudflare_api_unauthorized");
    }
    let envelope = response
        .json::<CloudflareEnvelope<Vec<AccountResult>>>()
        .await
        .context("decode Cloudflare accounts response")?;
    let accounts = unwrap_cloudflare_result(envelope, "Cloudflare accounts")?;
    Ok(accounts
        .into_iter()
        .map(|account| AccountInfo {
            account_id: account.id,
            account_name: account.name,
        })
        .collect())
}

fn unwrap_cloudflare_result<T>(envelope: CloudflareEnvelope<T>, label: &'static str) -> Result<T> {
    if envelope.success {
        return envelope
            .result
            .ok_or_else(|| anyhow!("{label} response missing result"));
    }
    let error = envelope
        .errors
        .iter()
        .filter_map(|error| error.message.as_deref())
        .collect::<Vec<_>>()
        .join("; ");
    bail!("{label} request failed: {error}");
}

async fn exchange_code_for_token(
    code: &str,
    code_verifier: &str,
    redirect_uri: &str,
) -> Result<TokenExchangeResponse> {
    let client = Client::builder().build().context("build OAuth client")?;
    let response = client
        .post(TOKEN_URL)
        .header("Accept", "application/json")
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("client_id", CLIENT_ID),
            ("redirect_uri", redirect_uri),
            ("code_verifier", code_verifier),
        ])
        .send()
        .await
        .context("exchange Cloudflare OAuth code")?;
    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        bail!("Cloudflare token exchange failed with HTTP {status}: {body}");
    }
    response
        .json::<TokenExchangeResponse>()
        .await
        .context("decode Cloudflare token exchange response")
}

async fn refresh_access_token(refresh_token: &str) -> Result<TokenExchangeResponse> {
    let client = Client::builder()
        .build()
        .context("build OAuth refresh client")?;
    let response = client
        .post(TOKEN_URL)
        .header("Accept", "application/json")
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
            ("client_id", CLIENT_ID),
        ])
        .send()
        .await
        .context("refresh Cloudflare OAuth access token")?;
    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        let invalid_grant = serde_json::from_str::<serde_json::Value>(&body)
            .ok()
            .and_then(|value| {
                value
                    .get("error")
                    .and_then(|error| error.as_str())
                    .map(str::to_owned)
            })
            .as_deref()
            == Some("invalid_grant");
        if invalid_grant {
            bail!("oauth_login_required: Cloudflare refresh token was rejected");
        }
        bail!("oauth_refresh_failed: HTTP {status}");
    }
    response
        .json::<TokenExchangeResponse>()
        .await
        .context("decode Cloudflare OAuth refresh response")
}

async fn wait_for_oauth_code(listener: TcpListener, expected_state: &str) -> Result<String> {
    let (mut stream, addr) = listener.accept().await.context("accept OAuth callback")?;
    validate_loopback(addr)?;
    let mut buffer = vec![0u8; 8192];
    let n = stream
        .read(&mut buffer)
        .await
        .context("read OAuth callback request")?;
    let request = String::from_utf8_lossy(&buffer[..n]);
    let request_line = request
        .lines()
        .next()
        .ok_or_else(|| anyhow!("empty OAuth callback request"))?;
    let path = request_line
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| anyhow!("invalid OAuth callback request line"))?;
    let url = url::Url::parse(&format!("http://127.0.0.1:{REDIRECT_PORT}{path}"))
        .context("parse OAuth callback URL")?;
    let code = match oauth_code_from_callback_url(&url, expected_state) {
        Ok(code) => code,
        Err(error) => {
            if url.path() == REDIRECT_PATH {
                write_http_response(&mut stream, 400, "Authorization failed").await?;
            } else {
                write_http_response(&mut stream, 404, "Not found").await?;
            }
            return Err(error);
        }
    };
    write_http_response(
        &mut stream,
        200,
        "TapChat authorization successful. You can close this window.",
    )
    .await?;
    Ok(code)
}

fn oauth_code_from_callback_url(url: &url::Url, expected_state: &str) -> Result<String> {
    if url.path() != REDIRECT_PATH {
        bail!("unexpected OAuth callback path {}", url.path());
    }
    if let Some(error) = url
        .query_pairs()
        .find_map(|(key, value)| (key == "error").then(|| value.into_owned()))
    {
        bail!("Cloudflare OAuth error: {error}");
    }
    let state = url
        .query_pairs()
        .find_map(|(key, value)| (key == "state").then(|| value.into_owned()))
        .ok_or_else(|| anyhow!("OAuth callback missing state"))?;
    if state != expected_state {
        bail!("OAuth callback state mismatch");
    }
    url.query_pairs()
        .find_map(|(key, value)| (key == "code").then(|| value.into_owned()))
        .ok_or_else(|| anyhow!("OAuth callback missing authorization code"))
}

fn validate_loopback(addr: SocketAddr) -> Result<()> {
    if addr.ip().is_loopback() {
        Ok(())
    } else {
        bail!("OAuth callback rejected non-loopback peer {addr}");
    }
}

async fn write_http_response(
    stream: &mut tokio::net::TcpStream,
    status: u16,
    message: &str,
) -> Result<()> {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        _ => "OK",
    };
    let body = format!(
        "<!doctype html><meta charset=\"utf-8\"><title>TapChat</title><body style=\"font-family:system-ui;padding:32px;text-align:center\"><h1>{message}</h1></body>"
    );
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    match stream.write_all(response.as_bytes()).await {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == ErrorKind::BrokenPipe => Ok(()),
        Err(error) => Err(error).context("write OAuth callback response"),
    }
}

fn redirect_uri() -> String {
    format!("http://localhost:{REDIRECT_PORT}{REDIRECT_PATH}")
}

fn generate_code_verifier() -> String {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn generate_code_challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redirect_uri_matches_cloudflare_registered_wrangler_callback() {
        assert_eq!(redirect_uri(), "http://localhost:8976/oauth/callback");
    }

    #[test]
    fn oauth_callback_requires_matching_state() {
        let url =
            url::Url::parse("http://localhost:8976/oauth/callback?code=abc123&state=actual-state")
                .expect("valid callback url");

        let error = oauth_code_from_callback_url(&url, "expected-state")
            .expect_err("state mismatch must fail")
            .to_string();

        assert!(error.contains("state mismatch"));
    }

    #[test]
    fn oauth_callback_extracts_authorization_code() {
        let url = url::Url::parse(
            "http://localhost:8976/oauth/callback?code=abc123&state=expected-state",
        )
        .expect("valid callback url");

        let code = oauth_code_from_callback_url(&url, "expected-state")
            .expect("matching callback should return authorization code");

        assert_eq!(code, "abc123");
    }

    #[test]
    fn legacy_oauth_record_without_expiry_refreshes_on_first_use() {
        let token = StoredCloudflareToken {
            access_token: "access".into(),
            refresh_token: Some("refresh".into()),
            account_id: None,
            account_name: None,
            email: None,
            expires_at_ms: None,
        };
        assert!(access_token_needs_refresh(&token, 1_000));
    }

    #[test]
    fn oauth_refresh_rotates_refresh_token_only_when_returned() {
        let mut token = StoredCloudflareToken {
            access_token: "old-access".into(),
            refresh_token: Some("old-refresh".into()),
            account_id: None,
            account_name: None,
            email: None,
            expires_at_ms: Some(1),
        };
        apply_token_refresh(
            &mut token,
            TokenExchangeResponse {
                access_token: "new-access".into(),
                refresh_token: None,
                expires_in: Some(3_600),
            },
            10_000,
        );
        assert_eq!(token.refresh_token.as_deref(), Some("old-refresh"));
        apply_token_refresh(
            &mut token,
            TokenExchangeResponse {
                access_token: "newer-access".into(),
                refresh_token: Some("rotated-refresh".into()),
                expires_in: Some(3_600),
            },
            20_000,
        );
        assert_eq!(token.refresh_token.as_deref(), Some("rotated-refresh"));
    }
}
