//! Windows guided WSL installer
//!
//! Guides a Windows user through installing WSL when Pick's sandbox finds no
//! backend: enable the two Windows optional features
//! (`Microsoft-Windows-Subsystem-Linux` and `VirtualMachinePlatform`), update
//! the WSL kernel (`wsl --update`), then prompt a reboot.
//!
//! Enabling optional features requires an elevated (Administrator) process, so
//! this module also exposes an elevation check and a UAC-elevating relaunch.
//!
//! ## Implementation note — no `windows`/`winapi` dependency
//!
//! Rather than call `ShellExecuteW` / token APIs (which would pull the
//! `windows` crate in as a *direct* dependency of `pentest-platform` and add
//! linking complexity for code that cannot be run on the Linux dev host), this
//! module mirrors the existing [`super::wsl`] pattern and shells out to
//! `powershell.exe` / `wsl.exe` via [`tokio::process::Command`]. Every
//! OS-specific body is gated with `#[cfg(target_os = "windows")]` /
//! `#[cfg(not(target_os = "windows"))]` so the crate builds cleanly (and the
//! non-Windows arms are exercised by the unit tests) on Linux/macOS.

/// A single step in the guided WSL install flow, for UI progress reporting.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub enum InstallStep {
    /// Enabling the `Microsoft-Windows-Subsystem-Linux` and
    /// `VirtualMachinePlatform` optional features.
    EnableFeatures,
    /// Running `wsl --update` to install/update the WSL2 kernel.
    UpdateKernel,
    /// Features + kernel done; the machine must reboot before WSL works.
    RebootRequired,
    /// The flow finished.
    Done,
}

/// Terminal outcome of [`run_guided_install`].
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub enum InstallOutcome {
    /// Install completed and WSL is ready (no reboot needed).
    Completed,
    /// Features/kernel installed successfully; a reboot is required.
    RebootRequired,
    /// The current process is not elevated; caller should
    /// [`relaunch_elevated`] (or ask the user to relaunch as Administrator).
    NeedsElevation,
    /// A step failed; the string carries a human-readable reason.
    Failed(String),
}

/// Host-side marker file the elevated child writes when it finishes, relative
/// to `%LOCALAPPDATA%`. The non-elevated caller polls for this to learn the
/// outcome of the elevated run.
#[cfg(target_os = "windows")]
const INSTALL_RESULT_MARKER: &str = r"pentest-sandbox\.wsl-install-result";

/// Return `true` if the current process is running elevated (Administrator).
///
/// On Windows this asks PowerShell whether the current identity is in the
/// built-in Administrator role and parses `True`/`False` from stdout. On
/// non-Windows platforms there is no such concept, so this returns `false`.
pub async fn is_elevated() -> bool {
    #[cfg(not(target_os = "windows"))]
    {
        false
    }
    #[cfg(target_os = "windows")]
    {
        use std::process::Stdio;
        use tokio::process::Command;

        let output = Command::new("powershell.exe")
            .args([
                "-NoProfile",
                "-Command",
                "[bool]([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)",
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .output()
            .await;

        match output {
            Ok(o) => String::from_utf8_lossy(&o.stdout)
                .trim()
                .eq_ignore_ascii_case("true"),
            Err(_) => false,
        }
    }
}

/// Run the guided WSL install: enable both optional features, then update the
/// WSL kernel.
///
/// Requires elevation for the feature-enable step. If the process is not
/// elevated this returns [`InstallOutcome::NeedsElevation`] without attempting
/// any changes. On success it returns [`InstallOutcome::RebootRequired`]
/// (enabling `VirtualMachinePlatform` always needs a reboot); any command
/// failure yields [`InstallOutcome::Failed`].
///
/// On non-Windows platforms this is not applicable and returns
/// [`InstallOutcome::Failed`].
pub async fn run_guided_install() -> InstallOutcome {
    #[cfg(not(target_os = "windows"))]
    {
        InstallOutcome::Failed("WSL install is Windows-only".into())
    }
    #[cfg(target_os = "windows")]
    {
        use std::process::Stdio;
        use tokio::process::Command;

        if !is_elevated().await {
            return InstallOutcome::NeedsElevation;
        }

        // Enable an optional feature via PowerShell. The feature name is a fixed
        // internal identifier (never user input), so it is safe to embed in the
        // -Command string. `$ErrorActionPreference='Stop'` turns
        // Enable-WindowsOptionalFeature's NON-TERMINATING errors into a nonzero
        // exit — without it PowerShell can exit 0 on a partial failure and we'd
        // misclassify it as success. Mirrors the elevated script in
        // relaunch_elevated, which sets the same preference.
        async fn enable_feature(feature: &str) -> Result<(), String> {
            let command = format!(
                "$ErrorActionPreference='Stop'; \
                 Enable-WindowsOptionalFeature -Online -FeatureName {feature} -NoRestart"
            );
            let args: Vec<&str> = vec!["-NoProfile", "-Command", &command];
            let status = Command::new("powershell.exe")
                .args(&args)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .await
                .map_err(|e| format!("failed to spawn powershell for {feature}: {e}"))?;
            if status.success() {
                Ok(())
            } else {
                Err(format!(
                    "Enable-WindowsOptionalFeature {feature} failed (exit {status})"
                ))
            }
        }

        if let Err(msg) = enable_feature("Microsoft-Windows-Subsystem-Linux").await {
            return InstallOutcome::Failed(msg);
        }
        if let Err(msg) = enable_feature("VirtualMachinePlatform").await {
            return InstallOutcome::Failed(msg);
        }

        // Update the WSL kernel.
        let update_args: Vec<&str> = vec!["--update"];
        match Command::new("wsl.exe")
            .args(&update_args)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await
        {
            Ok(status) if status.success() => InstallOutcome::RebootRequired,
            Ok(status) => InstallOutcome::Failed(format!("wsl --update failed (exit {status})")),
            Err(e) => InstallOutcome::Failed(format!("failed to spawn wsl --update: {e}")),
        }
    }
}

/// Relaunch this install flow in an elevated child process via a UAC prompt.
///
/// On Windows this spawns `powershell.exe` running `Start-Process powershell
/// -Verb RunAs`, which triggers the UAC consent dialog and launches an
/// Administrator child. That child re-runs the same install steps and writes a
/// result marker at `%LOCALAPPDATA%\pentest-sandbox\.wsl-install-result`, which
/// the (non-elevated) caller polls for the outcome. Returns `Ok(())` if the
/// launcher spawned, `Err` otherwise.
///
/// On non-Windows platforms elevation is not applicable and this returns
/// `Err`.
pub fn relaunch_elevated() -> Result<(), String> {
    #[cfg(not(target_os = "windows"))]
    {
        Err("elevation only on Windows".into())
    }
    #[cfg(target_os = "windows")]
    {
        use std::process::{Command, Stdio};

        // PowerShell run by the elevated child: enable both features, update
        // the kernel, then write the result marker under %LOCALAPPDATA%.
        // Single-quoted here-arguments avoid interpolation surprises.
        let elevated_script = format!(
            "$ErrorActionPreference='Stop'; \
             $dir = Join-Path $env:LOCALAPPDATA 'pentest-sandbox'; \
             New-Item -ItemType Directory -Force -Path $dir | Out-Null; \
             $marker = Join-Path $env:LOCALAPPDATA '{marker}'; \
             try {{ \
               Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux -NoRestart; \
               Enable-WindowsOptionalFeature -Online -FeatureName VirtualMachinePlatform -NoRestart; \
               wsl.exe --update; \
               Set-Content -Path $marker -Value 'RebootRequired' \
             }} catch {{ \
               Set-Content -Path $marker -Value ('Failed: ' + $_.Exception.Message) \
             }}",
            marker = INSTALL_RESULT_MARKER,
        );

        // Outer PowerShell asks Windows to Start-Process the inner PowerShell
        // elevated (`-Verb RunAs` -> UAC prompt). ArgumentList is built as a
        // proper string array in-script rather than concatenated here.
        let start_process = format!(
            "Start-Process powershell -Verb RunAs -ArgumentList @('-NoProfile','-WindowStyle','Hidden','-Command',{script})",
            script = ps_single_quote(&elevated_script),
        );

        Command::new("powershell.exe")
            .args(["-NoProfile", "-Command", &start_process])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map(|_child| ())
            .map_err(|e| format!("failed to launch elevated helper: {e}"))
    }
}

/// Quote a string as a PowerShell single-quoted literal (doubling embedded
/// single quotes), so it can be embedded safely inside another PowerShell
/// command's `-ArgumentList`.
#[cfg(target_os = "windows")]
fn ps_single_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn non_windows_install_is_not_applicable() {
        #[cfg(not(target_os = "windows"))]
        {
            assert!(!is_elevated().await);
            assert!(matches!(
                run_guided_install().await,
                InstallOutcome::Failed(_)
            ));
            assert!(relaunch_elevated().is_err());
        }
    }

    #[test]
    fn outcome_serializes() {
        let o = InstallOutcome::RebootRequired;
        assert!(serde_json::to_string(&o).unwrap().contains("RebootRequired"));
    }
}
