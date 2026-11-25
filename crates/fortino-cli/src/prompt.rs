//! Terminal prompts and private file-descriptor input.

use std::fs::File;
use std::io::{BufRead, BufReader, Read, Write};

use fortino_core::proto::ChallengeKind;
use fortino_core::{ErrorCode, ProtoError};
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

/// A terminal prompt the caller can give up on, because the question was answered elsewhere (the
/// desktop app shows the same prompts) or the attempt ended. Resolves to the line typed, or
/// `None` without a terminal.
///
/// The line is read on a blocking thread that waits with select(2): on macOS kqueue and poll
/// refuse terminals, so the async runtime can't wait on one. Dropping the prompt wakes that
/// thread through a socket pair; it stops reading and restores the terminal mode.
pub struct Prompt {
    wake: Option<std::os::unix::net::UnixStream>,
    task: tokio::task::JoinHandle<Option<String>>,
}

impl Prompt {
    /// Writes `prompt` to the terminal and starts reading the answer.
    pub fn start(kind: ChallengeKind, prompt: &str) -> Self {
        let label = format!("{prompt}: ");
        let pair = std::os::unix::net::UnixStream::pair().ok();
        let (wake, woken) = match pair {
            Some((a, b)) => (Some(a), Some(b)),
            None => (None, None),
        };
        let task = tokio::task::spawn_blocking(move || read_answer(kind, &label, woken?));
        Self { wake, task }
    }
}

impl std::future::Future for Prompt {
    type Output = Option<String>;

    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        std::pin::Pin::new(&mut self.task)
            .poll(cx)
            .map(|r| r.ok().flatten())
    }
}

impl Drop for Prompt {
    fn drop(&mut self) {
        if let Some(w) = self.wake.take() {
            let _ = (&w).write_all(b"x");
        }
    }
}

/// Turns echo off for a secret (the newline still echoes) and restores the mode on drop.
struct EchoOff<'a> {
    tty: &'a File,
    saved: Option<nix::sys::termios::Termios>,
}

impl<'a> EchoOff<'a> {
    fn new(tty: &'a File, secret: bool) -> Self {
        use nix::sys::termios::{LocalFlags, SetArg, tcgetattr, tcsetattr};
        let saved = if secret { tcgetattr(tty).ok() } else { None };
        if let Some(t) = &saved {
            let mut quiet = t.clone();
            quiet.local_flags.remove(LocalFlags::ECHO);
            quiet.local_flags.insert(LocalFlags::ECHONL);
            let _ = tcsetattr(tty, SetArg::TCSANOW, &quiet);
        }
        Self { tty, saved }
    }
}

impl Drop for EchoOff<'_> {
    fn drop(&mut self) {
        if let Some(t) = &self.saved {
            let _ = nix::sys::termios::tcsetattr(self.tty, nix::sys::termios::SetArg::TCSANOW, t);
        }
    }
}

/// [`Prompt`]'s blocking half: one line from the terminal, or `None` when woken, without a
/// terminal, or past [`MAX_SECRET`] bytes.
fn read_answer(
    kind: ChallengeKind,
    label: &str,
    woken: std::os::unix::net::UnixStream,
) -> Option<String> {
    use nix::errno::Errno;
    use nix::sys::select::{FdSet, select};
    use std::os::fd::AsFd;
    use std::os::unix::fs::OpenOptionsExt;

    let tty = File::options()
        .read(true)
        .write(true)
        .custom_flags(nix::libc::O_NONBLOCK)
        .open("/dev/tty")
        .ok()?;
    let _mode = EchoOff::new(&tty, kind.is_secret());
    (&tty).write_all(label.as_bytes()).ok()?;
    let mut line = Zeroizing::new(Vec::new());
    let mut buf = Zeroizing::new([0u8; 256]);
    loop {
        let mut ready = FdSet::new();
        ready.insert(tty.as_fd());
        ready.insert(woken.as_fd());
        match select(None, &mut ready, None, None, None) {
            Ok(_) => {}
            Err(Errno::EINTR) => continue,
            Err(_) => return None,
        }
        if ready.contains(woken.as_fd()) {
            return None;
        }
        if !ready.contains(tty.as_fd()) {
            continue;
        }
        match (&tty).read(&mut buf[..]) {
            Ok(0) => return None,
            Ok(n) => {
                line.extend_from_slice(&buf[..n]);
                if let Some(end) = line.iter().position(|b| *b == b'\n') {
                    line.truncate(end);
                    break;
                }
                if line.len() as u64 > MAX_SECRET {
                    return None;
                }
            }
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                ) => {}
            Err(_) => return None,
        }
    }
    let text = std::str::from_utf8(&line).ok()?.trim_end_matches('\r');
    if kind.is_secret() {
        Some(text.to_owned())
    } else {
        let t = text.trim();
        (!t.is_empty()).then(|| t.to_owned())
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
