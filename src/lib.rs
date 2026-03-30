pub mod capability;
pub mod conversation;
pub mod error;
pub mod ffi_api;
pub mod identity;
pub mod logging;
pub mod mls_adapter;
pub mod model;
pub mod persistence;
pub mod sync_engine;
pub mod transport_contract;

pub use error::{CoreError, CoreResult};
pub use ffi_api::{
    CoreCommand, CoreEffect, CoreEngine, CoreEvent, CoreOutput, CoreStateUpdate,
};
pub use logging::{LogLevel, Logger, NoopLogger};

#[cfg(test)]
mod tests {
    use crate::error::CoreError;
    use crate::logging::{LogLevel, Logger, NoopLogger};

    #[test]
    fn core_error_has_stable_code() {
        let error = CoreError::unsupported("phase0");
        assert_eq!(error.code(), "unsupported");
    }

    #[test]
    fn noop_logger_accepts_log_calls() {
        let logger = NoopLogger;
        logger.log(LogLevel::Info, "phase0", "core initialized");
    }
}
