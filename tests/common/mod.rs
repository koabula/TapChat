//! Shared integration-test helpers for the desktop end-to-end suites
//! (`tests/desktop_message_request_e2e.rs`, `tests/desktop_group_e2e.rs`).
//!
//! Rust's `tests/` integration-test convention treats every top-level
//! file in `tests/` as a separate test binary. Placing this module at
//! `tests/common/mod.rs` prevents cargo from trying to build it as
//! its own binary — a subdirectory with a `mod.rs` is treated as a
//! non-test support module (the canonical cargo idiom).
//!
//! Each integration test file includes it with `mod common;` and then
//! `use common::*;` (or selects individual items).

#![allow(dead_code)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{anyhow, bail, Context, Result};
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::Value;
use tapchat_core::model::{DeploymentBundle, DeviceRuntimeAuth};
use tempfile::{Builder, TempDir};

const DESKTOP_E2E_PROFILE_PASSPHRASE: &str = "Correct-Horse-42-Sunrise-Desktop-E2e";

/// Locate the `tapchat` CLI binary that cargo builds before running
/// integration tests.
pub fn binary_path() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_tapchat"))
}

/// The absolute path to the workspace root (the directory that
/// contains the `Cargo.toml` whose `[[bin]]` section compiles the
/// binary under test).
pub fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Build a unique temporary directory under the workspace root. We
/// deliberately keep temp artefacts inside the workspace so the
/// `cleanup_test_temp_script_removes_cli_temp_artifacts` e2e test
/// (which matches on `.tmp-desktop-e2e-*` / `.tmp-cli-e2e-*`
/// prefixes) can sweep them up.
pub fn repo_temp_dir(suffix: &str) -> Result<TempDir> {
    unsafe {
        std::env::set_var("TAPCHAT_PROFILE_PASSPHRASE", DESKTOP_E2E_PROFILE_PASSPHRASE);
    }
    Builder::new()
        .prefix(&format!(".tmp-desktop-e2e-{suffix}-"))
        .tempdir_in(workspace_root())
        .context("create desktop e2e temp dir")
}

/// Run the `tapchat` CLI with `--output json`, assert success, and
/// deserialise stdout as a `serde_json::Value`.
///
/// Every call sets `TAPCHAT_PROFILE_REGISTRY_PATH` to the supplied
/// path so tests can use disposable registries without touching the
/// user's real `device-profiles.json`.
pub fn run_cli_json<I, S>(registry_path: &Path, args: I) -> Result<Value>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut command = Command::new(binary_path());
    command
        .current_dir(workspace_root())
        .arg("--output")
        .arg("json")
        .env("TAPCHAT_PROFILE_REGISTRY_PATH", registry_path)
        .env(
            "TAPCHAT_PROFILE_PASSPHRASE",
            std::env::var("TAPCHAT_PROFILE_PASSPHRASE")
                .unwrap_or_else(|_| DESKTOP_E2E_PROFILE_PASSPHRASE.into()),
        );
    for arg in args {
        command.arg(arg.as_ref());
    }
    let output = command.output().context("run tapchat cli")?;
    if !output.status.success() {
        bail!(
            "tapchat command failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let stdout = String::from_utf8(output.stdout).context("decode cli stdout as utf-8")?;
    serde_json::from_str(&stdout).map_err(|error| {
        anyhow!(
            "failed to parse cli json output: {error}\nstdout:\n{}\nstderr:\n{}",
            stdout,
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

/// Extract a required string field from a JSON object, or return a
/// stable error including the field name so the caller can report it.
pub fn required_str(value: &Value, field: &str) -> Result<String> {
    value
        .get(field)
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .ok_or_else(|| anyhow!("missing string field {field}"))
}

/// Write a plain-text mnemonic file. The CLI's `device recover`
/// subcommand reads these.
pub fn write_mnemonic_file(root: &Path, name: &str, mnemonic: &str) -> Result<PathBuf> {
    let path = root.join(name);
    fs::write(&path, mnemonic).with_context(|| format!("write mnemonic {}", path.display()))?;
    Ok(path)
}

/// Serialise `value` as pretty JSON under `root/name`.
pub fn write_json_file<T: Serialize>(root: &Path, name: &str, value: &T) -> Result<PathBuf> {
    let path = root.join(name);
    fs::write(&path, serde_json::to_vec_pretty(value)?)
        .with_context(|| format!("write json {}", path.display()))?;
    Ok(path)
}

/// Deserialise a JSON file from disk.
pub fn read_json_file<T: DeserializeOwned>(path: &Path) -> Result<T> {
    let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| format!("decode {}", path.display()))
}

/// Extract the `device_runtime_auth` from a [`DeploymentBundle`], or
/// fail with a clear message if it's missing (which would indicate
/// the test runtime's bootstrap step never completed).
pub fn bundle_auth(bundle: &DeploymentBundle) -> Result<&DeviceRuntimeAuth> {
    bundle
        .device_runtime_auth
        .as_ref()
        .ok_or_else(|| anyhow!("deployment bundle missing device runtime auth"))
}

/// Run `tapchat profile export-identity` and return the path to the
/// written identity bundle file. Mirrors the helper inside the CLI
/// e2e test suite, kept in sync field-by-field.
pub fn export_identity_bundle_to_path(
    registry_path: &Path,
    root: &Path,
    profile: &Path,
    name: &str,
) -> Result<PathBuf> {
    let output = root.join(name);
    let exported = run_cli_json(
        registry_path,
        [
            "profile",
            "export-identity",
            "--profile",
            &profile.to_string_lossy(),
            "--out",
            &output.to_string_lossy(),
        ],
    )?;
    assert_eq!(
        required_str(&exported, "written")?,
        output.to_string_lossy()
    );
    Ok(output)
}

/// Build a fresh tokio multi-thread runtime and block on the supplied
/// async closure. Integration tests use this instead of
/// `#[tokio::test]` because several helpers spawn their own runtime
/// briefly and don't want to share a reactor across test cases.
pub fn with_tokio<F, Fut, T>(build: F) -> Result<T>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<T>>,
{
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("build tokio runtime for desktop e2e helper")?
        .block_on(build())
}
