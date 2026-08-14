fn main() {
    println!("cargo:rustc-check-cfg=cfg(mobile)");
    emit_build_metadata();
    emit_windows_stack_reserve();

    let test_support = std::env::var_os("CARGO_FEATURE_TEST_SUPPORT").is_some();
    let gui = std::env::var_os("CARGO_FEATURE_GUI").is_some();
    if test_support && !gui {
        println!("cargo:rerun-if-changed=build.rs");
        return;
    }

    // Ensure plugins configuration is properly embedded.
    tauri_build::build()
}

/// Rust's default 1 MiB Windows PE stack reserve is too small for Tauri's
/// generated IPC dispatcher plus non-trivial async commands. Keep this aligned
/// with the stack budget used by the CLI and desktop integration tests.
fn emit_windows_stack_reserve() {
    const WINDOWS_STACK_RESERVE_BYTES: u64 = 64 * 1024 * 1024;

    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        println!("cargo:rustc-link-arg-bin=tapchat-desktop=/STACK:{WINDOWS_STACK_RESERVE_BYTES}");
    }
}

fn emit_build_metadata() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=tauri.conf.json");
    println!("cargo:rerun-if-env-changed=GITHUB_SHA");
    println!("cargo:rerun-if-env-changed=GITHUB_REF_NAME");

    let git_sha = std::env::var("GITHUB_SHA")
        .ok()
        .and_then(|value| short_sha(&value))
        .or_else(|| git_output(["rev-parse", "--short=12", "HEAD"]))
        .unwrap_or_default();

    let git_tag = std::env::var("GITHUB_REF_NAME")
        .ok()
        .filter(|value| value.starts_with('v'))
        .or_else(|| git_output(["describe", "--tags", "--exact-match", "HEAD"]))
        .unwrap_or_default();

    let updater_endpoint_configured = std::fs::read_to_string("tauri.conf.json")
        .map(|config| config.contains("releases/latest/download/latest.json"))
        .unwrap_or(false);

    println!("cargo:rustc-env=TAPCHAT_GIT_SHA={git_sha}");
    println!("cargo:rustc-env=TAPCHAT_GIT_TAG={git_tag}");
    println!(
        "cargo:rustc-env=TAPCHAT_UPDATER_ENDPOINT_CONFIGURED={}",
        if updater_endpoint_configured {
            "true"
        } else {
            "false"
        }
    );
}

fn short_sha(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }
    Some(trimmed.chars().take(12).collect())
}

fn git_output<const N: usize>(args: [&str; N]) -> Option<String> {
    let output = std::process::Command::new("git").args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let value = String::from_utf8(output.stdout).ok()?.trim().to_string();
    (!value.is_empty()).then_some(value)
}
