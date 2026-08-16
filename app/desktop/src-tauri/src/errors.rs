use serde::Serialize;
use std::fmt::{Display, Formatter};
use tapchat_core::{AppErrorV1, CoreError, ErrorDomain, RecoveryAction};

#[derive(Debug, Clone, Serialize)]
#[serde(transparent)]
pub struct DesktopError(pub AppErrorV1);

pub type DesktopResult<T> = Result<T, DesktopError>;

impl DesktopError {
    pub fn new(code: &'static str, domain: ErrorDomain, retryable: bool) -> Self {
        Self(AppErrorV1::new(code, domain, retryable))
    }

    pub fn with_action(mut self, action: RecoveryAction) -> Self {
        self.0.action = Some(action);
        self
    }
}

impl From<AppErrorV1> for DesktopError {
    fn from(value: AppErrorV1) -> Self {
        Self(value)
    }
}

impl From<CoreError> for DesktopError {
    fn from(value: CoreError) -> Self {
        Self(value.to_app_error())
    }
}

impl From<anyhow::Error> for DesktopError {
    fn from(value: anyhow::Error) -> Self {
        if let Some(core) = value.downcast_ref::<CoreError>() {
            return Self(core.to_app_error());
        }
        Self::new("unexpected_error", ErrorDomain::Core, false)
            .with_action(RecoveryAction::CopyDiagnostics)
    }
}

impl From<String> for DesktopError {
    fn from(value: String) -> Self {
        let raw_candidate = value
            .split_once(':')
            .map(|(code, _)| code)
            .unwrap_or(value.as_str())
            .trim();
        let candidate = match raw_candidate {
            "recovery_phrase_auth_failed" => "auth_failed",
            "recovery_phrase_auth_required" => "profile_locked",
            "recovery_phrase_challenge_expired" => "request_timeout",
            "recovery_phrase_confirmation_required" => "invalid_input",
            "recovery_phrase_unavailable" | "recovery_phrase_challenge_failed" => "invalid_state",
            other => other,
        };
        if let Some((domain, retryable, action)) =
            tapchat_core::error_codes_generated::app_error_defaults(candidate)
        {
            let mut error = AppErrorV1::new(candidate, domain, retryable);
            error.action = action;
            return Self(error);
        }
        Self::new("unexpected_error", ErrorDomain::Core, true).with_action(RecoveryAction::Retry)
    }
}

impl From<&str> for DesktopError {
    fn from(value: &str) -> Self {
        Self::from(value.to_owned())
    }
}

impl From<DesktopError> for String {
    fn from(value: DesktopError) -> Self {
        value.0.code
    }
}

impl Display for DesktopError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0.code)
    }
}

impl std::error::Error for DesktopError {}
