//! Runtime log level.
//!
//! `main` installs the subscriber with a reloadable filter; `log.setLevel` swaps it. Levels only
//! change verbosity: every writer still goes through the redacting writer, and debug logging
//! records status codes, cookie names and paths only.

use std::sync::{Mutex, OnceLock};

use fortino_core::proto::LogLevel;

type Setter = Box<dyn Fn(&str) -> Result<(), String> + Send + Sync>;

static SETTER: OnceLock<Setter> = OnceLock::new();
static CURRENT: Mutex<Option<LogLevel>> = Mutex::new(None);

/// Registers the function that replaces the filter. `initial` is `None` when the filter came
/// from `RUST_LOG` and is not a plain level.
pub fn install(setter: Setter, initial: Option<LogLevel>) {
    if SETTER.set(setter).is_ok() {
        if let Ok(mut c) = CURRENT.lock() {
            *c = initial;
        }
    }
}

/// The level last set, if the filter is a plain level.
pub fn current() -> Option<LogLevel> {
    CURRENT.lock().ok().and_then(|c| *c)
}

/// Replaces the filter with `level` for every target.
pub fn set(level: LogLevel) -> Result<(), String> {
    let setter = SETTER.get().ok_or("log level is not adjustable")?;
    setter(level.as_str())?;
    if let Ok(mut c) = CURRENT.lock() {
        *c = Some(level);
    }
    tracing::info!(level = level.as_str(), "log level changed");
    Ok(())
}
