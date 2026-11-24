//! Single sign-on in the system browser.
//!
//! The CLI listens on `127.0.0.1:<port>`, opens the gateway's sign-in page and waits. When the
//! browser lands on the local callback, its query string answers the challenge. Where the
//! browser can't reach this computer (another machine, or the port is taken), the user can
//! paste the address the browser ended on instead.

use std::future::Future;
use std::pin::Pin;
use std::process::{Command, Stdio};

use fortino_core::client::Client;
use fortino_core::proto::{Challenge, Event, Status};
use fortino_core::saml_callback::CallbackListener;
use fortino_core::{ErrorCode, ProtoError};
use tokio::sync::mpsc::UnboundedReceiver;
use zeroize::Zeroizing;

use crate::{Failure, prompt};

/// How a single sign-on wait ended.
pub enum Outcome {
    /// The answer for the challenge: the callback's query string.
    Answer(Zeroizing<String>),
    /// The challenge ended or changed meanwhile; this status comes next.
    Status(Box<Status>),
    /// Ctrl-C.
    Cancelled,
    /// Nothing here can receive the sign-in.
    NoInteraction(String),
}

/// Runs one single sign-on for `ch`: listens, opens the browser (unless `open_browser` is
/// false) and waits for the callback, a pasted address, a status change or Ctrl-C.
pub async fn sign_in<F>(
    c: &Client,
    rx: &mut UnboundedReceiver<Event>,
    ch: &Challenge,
    open_browser: bool,
    ctrl_c: &mut Pin<&mut F>,
) -> Result<Outcome, Failure>
where
    F: Future<Output = std::io::Result<()>>,
{
    let Some(login) = ch.saml.as_ref().filter(|l| l.url.starts_with("https://")) else {
        return Ok(Outcome::NoInteraction(
            "the VPN service named no sign-in page".into(),
        ));
    };
    let port = login.callback_port;
    let listener = match CallbackListener::bind(port).await {
        Ok(l) => Some(l),
        Err(e) => {
            eprintln!("Can't receive the sign-in on 127.0.0.1:{port} ({e}).");
            None
        }
    };
    let tty = prompt::interactive();
    if listener.is_none() && !tty {
        return Ok(Outcome::NoInteraction(format!(
            "single sign-on needs 127.0.0.1:{port}, which is in use, or a terminal to paste the \
             browser's final address into"
        )));
    }
    eprintln!("Sign in with your browser:\n  {}", login.url);
    if open_browser && listener.is_some() {
        if !launch_browser(&login.url) {
            eprintln!("Open that address in a browser to continue.");
        }
    } else {
        eprintln!("Open that address in a browser to continue.");
    }

    let accept = async {
        match &listener {
            Some(l) => l.next_login().await.ok(),
            None => None,
        }
    };
    tokio::pin!(accept);
    let paste_task = tty.then(|| {
        let label = if listener.is_some() {
            "If the browser can't reach this computer, paste the address it ends on: "
        } else {
            "After signing in, paste the address the browser ends on: "
        };
        tokio::task::spawn_blocking(move || prompt::pasted_callback(label))
    });
    let paste = async move {
        match paste_task {
            Some(t) => t.await.ok().flatten(),
            None => None,
        }
    };
    tokio::pin!(paste);
    let (mut accept_done, mut paste_done) = (listener.is_none(), !tty);
    loop {
        tokio::select! {
            q = &mut accept, if !accept_done => match q {
                Some(q) => {
                    if tty {
                        eprintln!();
                    }
                    eprintln!("Signed in; finishing the connection…");
                    return Ok(Outcome::Answer(q));
                }
                None => accept_done = true,
            },
            q = &mut paste, if !paste_done => match q {
                Some(q) => {
                    eprintln!("Finishing the connection…");
                    return Ok(Outcome::Answer(q));
                }
                None => paste_done = true,
            },
            ev = rx.recv() => {
                let st = match ev {
                    Some(Event::Status { status }) => *status,
                    Some(Event::ResyncRequired) => c.status().await?,
                    None => {
                        return Err(Failure(ProtoError::new(
                            ErrorCode::ServiceUnavailable,
                            "lost connection to the VPN service",
                        )));
                    }
                };
                if st.challenge.as_ref().is_none_or(|x| x.id != ch.id) {
                    return Ok(Outcome::Status(Box::new(st)));
                }
            }
            _ = ctrl_c.as_mut() => return Ok(Outcome::Cancelled),
        }
        if accept_done && paste_done {
            return Ok(Outcome::NoInteraction(
                "the sign-in could not be received".into(),
            ));
        }
    }
}

/// Opens `url` in the user's default browser.
fn launch_browser(url: &str) -> bool {
    #[cfg(target_os = "macos")]
    let program = "/usr/bin/open";
    #[cfg(not(target_os = "macos"))]
    let program = "xdg-open";
    match Command::new(program)
        .arg(url)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(mut child) => {
            std::thread::spawn(move || {
                let _ = child.wait();
            });
            true
        }
        Err(_) => false,
    }
}
