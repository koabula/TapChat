#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

pub trait Logger {
    fn log(&self, level: LogLevel, target: &str, message: &str);
}

#[derive(Debug, Default, Clone, Copy)]
pub struct NoopLogger;

impl Logger for NoopLogger {
    fn log(&self, _level: LogLevel, _target: &str, _message: &str) {}
}

#[cfg(test)]
mod tests {
    use super::{LogLevel, Logger, NoopLogger};

    #[test]
    fn noop_logger_is_callable() {
        NoopLogger.log(LogLevel::Debug, "phase0", "test");
    }
}
