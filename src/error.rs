use std::error::Error;
use std::fmt::{Display, Formatter};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorDomain {
    Core,
    Validation,
    Identity,
    Mls,
    Transport,
    Runtime,
    Storage,
    Security,
    Group,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryAction {
    Retry,
    RetryLater,
    SyncNow,
    RefreshIdentity,
    Reconnect,
    ReconnectRuntime,
    UpgradeApp,
    UpgradeRuntime,
    RestartApp,
    CopyDiagnostics,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppErrorV1 {
    pub version: u16,
    pub code: String,
    pub domain: ErrorDomain,
    pub retryable: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<RecoveryAction>,
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub args: std::collections::BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http_status: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<String>,
}

impl AppErrorV1 {
    pub fn new(code: impl Into<String>, domain: ErrorDomain, retryable: bool) -> Self {
        Self {
            version: 1,
            code: code.into(),
            domain,
            retryable,
            action: None,
            args: std::collections::BTreeMap::new(),
            http_status: None,
            correlation_id: None,
        }
    }

    pub fn with_action(mut self, action: RecoveryAction) -> Self {
        self.action = Some(action);
        self
    }

    pub fn with_http_status(mut self, status: u16) -> Self {
        self.http_status = Some(status);
        self
    }

    pub fn with_correlation_id(mut self, correlation_id: impl Into<String>) -> Self {
        self.correlation_id = Some(correlation_id.into());
        self
    }

    pub fn with_arg(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        let key = key.into();
        if crate::error_codes_generated::is_allowed_error_arg(&self.code, &key) {
            self.args.insert(key, value.into());
        }
        self
    }

    pub fn network_unavailable() -> Self {
        Self::from_registered_code("network_unavailable")
    }

    pub fn from_http_response(status: u16, body: &str) -> Self {
        if let Ok(parsed) = serde_json::from_str::<Self>(body) {
            if parsed.version == 1
                && crate::error_codes_generated::is_registered_app_error(&parsed.code)
            {
                let mut normalized = Self::from_registered_code(&parsed.code);
                normalized.retryable = parsed.retryable;
                normalized.http_status = Some(status);
                normalized.correlation_id = parsed.correlation_id.filter(|value| {
                    !value.is_empty()
                        && value.len() <= 128
                        && value.bytes().all(|byte| {
                            byte.is_ascii_alphanumeric()
                                || matches!(byte, b'-' | b'_' | b'.' | b':')
                        })
                });
                normalized.args = parsed
                    .args
                    .into_iter()
                    .filter(|(key, _)| {
                        crate::error_codes_generated::is_allowed_error_arg(&normalized.code, key)
                    })
                    .collect();
                return normalized;
            }
        }
        let code = match status {
            400 => "invalid_input",
            401 | 403 => "invalid_capability",
            404 => "not_found",
            408 => "request_timeout",
            409 | 412 => "conflict",
            413 => "request_too_large",
            426 => "upgrade_required",
            429 => "rate_limited",
            500..=599 => "temporary_unavailable",
            _ => "temporary_failure",
        };
        Self::from_registered_code(code).with_http_status(status)
    }

    pub fn from_registered_code(code: &str) -> Self {
        let (code, domain, retryable, action) = if let Some((domain, retryable, action)) =
            crate::error_codes_generated::app_error_defaults(code)
        {
            (code, domain, retryable, action)
        } else {
            (
                "unexpected_error",
                ErrorDomain::Core,
                true,
                Some(RecoveryAction::Retry),
            )
        };
        let mut error = Self::new(code, domain, retryable);
        error.action = action;
        error
    }
}

pub type CoreResult<T> = Result<T, CoreError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoreError {
    code: &'static str,
    message: String,
}

impl CoreError {
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    pub fn invalid_state(message: impl Into<String>) -> Self {
        Self::new("invalid_state", message)
    }

    pub fn invalid_input(message: impl Into<String>) -> Self {
        Self::new("invalid_input", message)
    }

    pub fn unsupported(message: impl Into<String>) -> Self {
        Self::new("unsupported", message)
    }

    pub fn temporary_failure(message: impl Into<String>) -> Self {
        Self::new("temporary_failure", message)
    }

    pub fn restore_failed(message: impl Into<String>) -> Self {
        Self::new("restore_failed", message)
    }

    pub fn code(&self) -> &'static str {
        self.code
    }

    pub fn message(&self) -> &str {
        &self.message
    }

    pub fn to_app_error(&self) -> AppErrorV1 {
        let (public_code, domain, retryable, action) = if let Some((domain, retryable, action)) =
            crate::error_codes_generated::app_error_defaults(self.code)
        {
            (self.code, domain, retryable, action)
        } else {
            (
                "unexpected_error",
                ErrorDomain::Core,
                true,
                Some(RecoveryAction::Retry),
            )
        };
        let mut error = AppErrorV1::new(public_code, domain, retryable);
        error.action = action;
        error
    }
}

impl Display for CoreError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl Error for CoreError {}

#[cfg(test)]
mod tests {
    use super::{AppErrorV1, CoreError, ErrorDomain};

    #[test]
    fn constructors_keep_code_and_message() {
        let error = CoreError::invalid_input("missing field");
        assert_eq!(error.code(), "invalid_input");
        assert_eq!(error.message(), "missing field");
    }

    #[test]
    fn structured_http_errors_preserve_only_registered_safe_fields() {
        let error = AppErrorV1::from_http_response(
            422,
            r#"{"version":1,"code":"keypackage_expired","domain":"storage","retryable":false,"args":{"path":"C:\\secret","unknown":"raw"},"correlationId":"request_42"}"#,
        );
        assert_eq!(error.code, "keypackage_expired");
        assert_eq!(error.domain, ErrorDomain::Mls);
        assert!(!error.retryable);
        assert_eq!(error.http_status, Some(422));
        assert_eq!(error.correlation_id.as_deref(), Some("request_42"));
        assert!(error.args.is_empty());
    }

    #[test]
    fn unrecognized_or_malformed_http_errors_do_not_leak_response_details() {
        let error = AppErrorV1::from_http_response(
            500,
            r#"{"version":1,"code":"database_exploded","domain":"storage","retryable":false,"correlationId":"token value must not escape"}"#,
        );
        assert_eq!(error.code, "temporary_unavailable");
        assert_eq!(error.http_status, Some(500));
        assert!(error.correlation_id.is_none());
        assert!(error.args.is_empty());
    }
}
