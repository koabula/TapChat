use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use anyhow::{Context, Result, bail};

const STRESS_CASE_TIMEOUT: Duration = Duration::from_secs(300);

#[test]
fn cli_e2e_stress_suite() -> Result<()> {
    for test_name in [
        "cli_multi_device_join_and_switch_e2e_work",
        "cli_recovery_restart_e2e_work",
        "cli_long_offline_attachment_and_membership_change_recover_e2e_work",
        "cli_multi_device_restart_rebuild_and_repeated_sync_remain_consistent_e2e_work",
    ] {
        run_ignored_cli_e2e(test_name)?;
    }
    Ok(())
}

fn run_ignored_cli_e2e(test_name: &str) -> Result<()> {
    let exe = cli_e2e_test_binary()?;
    eprintln!("cli_e2e_stress_suite: starting {test_name}");
    let mut child = Command::new(&exe)
        .current_dir(workspace_root())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .args([test_name, "--ignored", "--nocapture"])
        .spawn()
        .with_context(|| format!("spawn ignored cli_e2e test {test_name}"))?;
    let deadline = Instant::now() + STRESS_CASE_TIMEOUT;
    loop {
        if child
            .try_wait()
            .with_context(|| format!("poll ignored cli_e2e test {test_name}"))?
            .is_some()
        {
            break;
        }
        if Instant::now() >= deadline {
            let pid = child.id();
            let _ = stop_pid_and_wait(pid);
            let output = child
                .wait_with_output()
                .with_context(|| format!("collect timed out ignored cli_e2e test {test_name}"))?;
            bail!(
                "ignored cli_e2e test {test_name} timed out after {:?}\nstdout:\n{}\nstderr:\n{}",
                STRESS_CASE_TIMEOUT,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        thread::sleep(Duration::from_millis(250));
    }
    let output = child
        .wait_with_output()
        .with_context(|| format!("collect ignored cli_e2e test {test_name}"))?;
    if !output.status.success() {
        bail!(
            "ignored cli_e2e test {test_name} failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    eprintln!("cli_e2e_stress_suite: finished {test_name}");
    Ok(())
}

fn cli_e2e_test_binary() -> Result<PathBuf> {
    let deps_dir = workspace_root().join("target").join("debug").join("deps");
    let mut candidates: Vec<(PathBuf, SystemTime)> = fs::read_dir(&deps_dir)
        .with_context(|| format!("read {}", deps_dir.display()))?
        .filter_map(|entry| {
            let entry = entry.ok()?;
            let path = entry.path();
            let file_name = path.file_name()?.to_str()?;
            if !file_name.starts_with("cli_e2e-")
                || !file_name.ends_with(".exe")
                || file_name.contains("cli_e2e_stress")
            {
                return None;
            }
            let modified = entry.metadata().ok()?.modified().ok()?;
            Some((path, modified))
        })
        .collect();
    candidates.sort_by_key(|(_, modified)| *modified);
    candidates
        .pop()
        .map(|(path, _)| path)
        .context("resolve cli_e2e test binary in target/debug/deps")
}

fn workspace_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

fn stop_pid_and_wait(pid: u32) -> Result<()> {
    #[cfg(windows)]
    {
        let output = Command::new("taskkill")
            .args(["/PID", &pid.to_string(), "/T", "/F"])
            .output()
            .context("run taskkill for cli e2e stress process")?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            let detail = stderr.trim();
            let combined = if detail.is_empty() {
                stdout.trim().to_string()
            } else {
                detail.to_string()
            };
            let lower = combined.to_ascii_lowercase();
            if !(lower.contains("not found")
                || lower.contains("no running instance")
                || combined.contains("找不到")
                || combined.contains("没有运行的任务"))
            {
                bail!("taskkill failed for pid {pid}: {combined}");
            }
        }
    }
    #[cfg(not(windows))]
    {
        let output = Command::new("kill")
            .args(["-TERM", &pid.to_string()])
            .output()
            .context("run kill for cli e2e stress process")?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            let detail = stderr.trim();
            if !(detail.contains("No such process") || stdout.contains("No such process")) {
                bail!("kill failed for pid {pid}: {}", detail);
            }
        }
    }
    Ok(())
}
