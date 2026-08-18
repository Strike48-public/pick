//! iOS PTY shell — unsupported.
//!
//! iOS application sandboxing forbids spawning subprocesses and allocating
//! PTYs, so the interactive shell (proot/native, as on Android/desktop) has no
//! iOS implementation. This stub exists only to satisfy the shared `shell_ws`
//! call sites at compile time; `spawn` fails immediately with a clear message,
//! and the remaining methods are never reached at runtime.

use pentest_core::config::ShellMode;
use pentest_core::error::{Error, Result};
use std::io::{Read, Write};
use std::path::Path;

fn unsupported() -> Error {
    Error::PlatformNotSupported("interactive shell is not available on iOS".to_string())
}

/// Placeholder interactive PTY shell for iOS. Construction always fails.
pub struct PtyShell {
    _private: (),
}

impl PtyShell {
    pub async fn spawn(
        _cols: u16,
        _rows: u16,
        _progress: Option<tokio::sync::mpsc::Sender<String>>,
        _cwd: Option<&Path>,
        _shell_mode: ShellMode,
    ) -> Result<Self> {
        Err(unsupported())
    }

    pub fn resize(&self, _cols: u16, _rows: u16) -> Result<()> {
        Err(unsupported())
    }

    pub fn try_clone_reader(&self) -> Result<Box<dyn Read + Send>> {
        Err(unsupported())
    }

    pub fn take_writer(&self) -> Result<Box<dyn Write + Send>> {
        Err(unsupported())
    }

    pub fn try_wait(&mut self) -> Result<Option<std::process::ExitStatus>> {
        Ok(None)
    }
}
