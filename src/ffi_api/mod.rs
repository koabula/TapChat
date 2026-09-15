mod attachments;
pub(crate) mod engine;
mod groups;
mod recovery;
mod sync;
/// Crate-visible so that `crate::leakage_corpus` can drive the same two-party
/// harness these tests drive. A corpus that rebuilt the setup for itself would
/// be testing its own transcription, not the engine.
#[cfg(test)]
pub(crate) mod tests;
mod types;

pub use engine::{
    CoreEngine, RealtimeSessionSnapshot, RecoveryContextSnapshot, SyncCheckpointSnapshot,
};
pub use types::*;
