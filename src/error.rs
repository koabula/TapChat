use std::error::Error;
use std::fmt::{Display, Formatter};

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

    pub fn code(&self) -> &'static str {
        self.code
    }

    pub fn message(&self) -> &str {
        &self.message
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
    use super::CoreError;

    #[test]
    fn constructors_keep_code_and_message() {
        let error = CoreError::invalid_input("missing field");
        assert_eq!(error.code(), "invalid_input");
        assert_eq!(error.message(), "missing field");
    }
}
