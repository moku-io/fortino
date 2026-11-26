//! Runtime log level.
//!
//! `main` installs the subscriber with a reloadable filter; `log.setLevel` swaps it. Levels only
//! change verbosity: every writer still goes through the redacting writer, and debug logging
//! records status codes, cookie names and paths only.
//!
//! A level set at runtime is saved in the state directory and restored when the daemon starts,
//! so it survives restarts and updates. `RUST_LOG`, when set, takes precedence over the saved
//! level. Setting `info`, the default, removes the saved file.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use fortino_core::proto::LogLevel;

type Setter = Box<dyn Fn(&str) -> Result<(), String> + Send + Sync>;

static SETTER: OnceLock<Setter> = OnceLock::new();
static CURRENT: Mutex<Option<LogLevel>> = Mutex::new(None);
static SAVED: OnceLock<PathBuf> = OnceLock::new();
/// Serializes saves: they share one temporary file.
static SAVING: Mutex<()> = Mutex::new(());

/// Name of the file in the state directory that holds the saved level.
pub const FILE_NAME: &str = "log-level";

/// Registers the function that replaces the filter. `initial` is `None` when the filter came
/// from `RUST_LOG` and is not a plain level.
pub fn install(setter: Setter, initial: Option<LogLevel>) {
    if SETTER.set(setter).is_ok() {
        if let Ok(mut c) = CURRENT.lock() {
            *c = initial;
        }
    }
}

/// Uses `path` to save the level from now on and, unless `RUST_LOG` chose the filter
/// (`env_set`), applies the level saved there.
pub fn restore(path: PathBuf, env_set: bool) {
    let saved = load(&path);
    let _ = SAVED.set(path);
    if env_set {
        return;
    }
    match saved {
        Ok(Some(level)) => match apply(level) {
            Ok(()) => tracing::info!(level = level.as_str(), "saved log level restored"),
            Err(e) => tracing::warn!(error = %e, "could not restore the saved log level"),
        },
        Ok(None) => {}
        Err(e) => tracing::warn!(error = %e, "ignoring the saved log level"),
    }
}

/// The level last set, if the filter is a plain level.
pub fn current() -> Option<LogLevel> {
    CURRENT.lock().ok().and_then(|c| *c)
}

/// Replaces the filter with `level` for every target and saves it for the next start.
pub fn set(level: LogLevel) -> Result<(), String> {
    apply(level)?;
    tracing::info!(level = level.as_str(), "log level changed");
    if let Some(path) = SAVED.get() {
        let _saving = SAVING
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Err(e) = save(path, level) {
            tracing::warn!(error = %e, "could not save the log level; it lasts until restart");
        }
    }
    Ok(())
}

fn apply(level: LogLevel) -> Result<(), String> {
    let setter = SETTER.get().ok_or("log level is not adjustable")?;
    setter(level.as_str())?;
    if let Ok(mut c) = CURRENT.lock() {
        *c = Some(level);
    }
    Ok(())
}

/// The level saved at `path`; `None` when nothing is saved.
fn load(path: &Path) -> Result<Option<LogLevel>, String> {
    match std::fs::read_to_string(path) {
        Ok(s) => LogLevel::parse(&s)
            .map(Some)
            .ok_or_else(|| format!("{}: not a log level", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("{}: {e}", path.display())),
    }
}

/// Saves `level` at `path`, replacing the file atomically; `info` removes it.
fn save(path: &Path, level: LogLevel) -> std::io::Result<()> {
    if level == LogLevel::Info {
        return match std::fs::remove_file(path) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
            _ => Ok(()),
        };
    }
    let tmp = path.with_extension("tmp");
    let mut f = std::fs::File::create(&tmp)?;
    writeln!(f, "{}", level.as_str())?;
    f.sync_all()?;
    std::fs::rename(&tmp, path)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn saved_level_round_trips_and_info_removes_it() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join(FILE_NAME);
        assert_eq!(load(&p), Ok(None));
        save(&p, LogLevel::Debug).unwrap();
        assert_eq!(load(&p), Ok(Some(LogLevel::Debug)));
        save(&p, LogLevel::Trace).unwrap();
        assert_eq!(load(&p), Ok(Some(LogLevel::Trace)));
        save(&p, LogLevel::Info).unwrap();
        assert!(!p.exists());
        assert_eq!(load(&p), Ok(None));
        save(&p, LogLevel::Info).unwrap(); // nothing saved: still fine
    }

    #[test]
    fn unreadable_saved_level_is_an_error() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join(FILE_NAME);
        std::fs::write(&p, "fortino=debug\n").unwrap();
        assert!(load(&p).is_err());
    }
}
