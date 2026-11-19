//! Terminal prompts and private file-descriptor input.

use std::fs::File;
use std::io::{BufRead, BufReader, Read, Write};

use ofc_core::proto::ChallengeKind;
use ofc_core::{ErrorCode, ProtoError};
use zeroize::Zeroizing;

use crate::Failure;

/// Maximum accepted secret length from a descriptor.
const MAX_SECRET: u64 = 1024;

/// Reads one newline-terminated value from an inherited descriptor.
fn read_fd(fd: u32) -> Result<String, Failure> {
    let f = File::open(format!("/dev/fd/{fd}")).map_err(|e| {
        Failure(ProtoError::new(
            ErrorCode::InvalidRequest,
            format!("cannot read descriptor {fd}: {e}"),
        ))
    })?;
    let mut line = Zeroizing::new(String::new());
    BufReader::new(f.take(MAX_SECRET))
        .read_line(&mut line)
        .map_err(|e| {
            Failure(ProtoError::new(
                ErrorCode::InvalidRequest,
                format!("cannot read descriptor {fd}: {e}"),
            ))
        })?;
    let v = line.trim_end_matches(['\n', '\r']).to_owned();
    if v.is_empty() {
        return Err(Failure(ProtoError::new(
            ErrorCode::InteractionRequired,
            format!("descriptor {fd} supplied no value"),
        )));
    }
    Ok(v)
}

/// Secrets supplied on descriptors. Each descriptor is read at most once.
#[derive(Debug)]
pub struct SecretSource {
    password_fd: Option<u32>,
    otp_fd: Option<u32>,
}

impl SecretSource {
    /// Validates the descriptor numbers.
    pub fn new(password_fd: Option<u32>, otp_fd: Option<u32>) -> Result<Self, Failure> {
        for fd in [password_fd, otp_fd].into_iter().flatten() {
            if fd <= 2 {
                return Err(Failure(ProtoError::new(
                    ErrorCode::InvalidRequest,
                    "secret descriptors must be 3 or higher",
                )));
            }
        }
        if password_fd.is_some() && password_fd == otp_fd {
            return Err(Failure(ProtoError::new(
                ErrorCode::InvalidRequest,
                "password and OTP need separate descriptors",
            )));
        }
        Ok(Self {
            password_fd,
            otp_fd,
        })
    }

    /// The password, if a descriptor supplies one.
    pub fn password(&mut self) -> Option<Result<String, Failure>> {
        self.password_fd.take().map(read_fd)
    }

    /// The OTP, if a descriptor supplies one.
    pub fn otp(&mut self) -> Option<Result<String, Failure>> {
        self.otp_fd.take().map(read_fd)
    }
}

/// Asks on the controlling terminal. Returns `None` when there is no terminal.
pub fn ask(kind: ChallengeKind, prompt: &str) -> Option<String> {
    let mut tty = File::options()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .ok()?;
    let label = format!("{prompt}: ");
    if kind.is_secret() {
        rpassword::prompt_password(label).ok()
    } else {
        tty.write_all(label.as_bytes()).ok()?;
        let mut line = String::new();
        BufReader::new(tty).read_line(&mut line).ok()?;
        let v = line.trim().to_owned();
        (!v.is_empty()).then_some(v)
    }
}

/// Yes/no on the terminal; `false` without a terminal.
pub fn confirm(question: &str) -> bool {
    let Ok(mut tty) = File::options().read(true).write(true).open("/dev/tty") else {
        return false;
    };
    if write!(tty, "{question} [y/N] ").is_err() {
        return false;
    }
    let mut line = String::new();
    if BufReader::new(tty).read_line(&mut line).is_err() {
        return false;
    }
    matches!(line.trim(), "y" | "Y" | "yes")
}

/// Restores the terminal mode on drop (a prompt interrupted by Ctrl-C leaves echo off).
pub struct TermGuard {
    saved: Option<(File, nix::sys::termios::Termios)>,
}

impl std::fmt::Debug for TermGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TermGuard").finish_non_exhaustive()
    }
}

impl TermGuard {
    /// Saves the current terminal mode, if there is a terminal.
    pub fn save() -> Self {
        let saved = File::options()
            .read(true)
            .write(true)
            .open("/dev/tty")
            .ok()
            .and_then(|f| nix::sys::termios::tcgetattr(&f).ok().map(|t| (f, t)));
        Self { saved }
    }
}

impl Drop for TermGuard {
    fn drop(&mut self) {
        if let Some((f, t)) = &self.saved {
            let _ = nix::sys::termios::tcsetattr(f, nix::sys::termios::SetArg::TCSANOW, t);
        }
    }
}
