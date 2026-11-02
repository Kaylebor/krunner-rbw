//! Clipboard via `wl-copy`.
//!
//! Secrets are copied with `--sensitive` (sets `x-kde-passwordManagerHint`,
//! so Klipper keeps them out of history) and `--foreground`, so we keep the
//! process that owns the selection. If it still owns it after `CLEAR_AFTER`
//! we kill it and clear; if something else was copied meanwhile, wl-copy has
//! already exited and we leave the clipboard alone.

use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio::process::{Child, Command};
use tokio::sync::Mutex;

pub const CLEAR_AFTER: Duration = Duration::from_secs(30);

#[derive(Default)]
pub struct Clip {
    generation: u64,
    owner: Option<Child>,
}

pub type SharedClip = Arc<Mutex<Clip>>;

async fn spawn_copy(text: &[u8], sensitive: bool) -> Result<Child, String> {
    let mut cmd = Command::new("wl-copy");
    cmd.arg("--trim-newline");
    if sensitive {
        cmd.args(["--sensitive", "--foreground"]);
    }
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("failed to start wl-copy: {e}"))?;
    let mut stdin = child.stdin.take().expect("piped stdin");
    stdin.write_all(text).await.map_err(|e| e.to_string())?;
    drop(stdin);
    Ok(child)
}

/// Copies non-secret text (e.g. a username).
pub async fn copy_plain(clip: &SharedClip, text: &str) -> Result<(), String> {
    let mut c = clip.lock().await;
    if let Some(mut old) = c.owner.take() {
        let _ = old.kill().await;
    }
    c.generation += 1;
    spawn_copy(text.as_bytes(), false).await?.wait().await.map_err(|e| e.to_string())?;
    Ok(())
}

/// Copies a secret and schedules clearing it.
pub async fn copy_secret(clip: &SharedClip, secret: Vec<u8>) -> Result<(), String> {
    let child = spawn_copy(&secret, true).await;
    drop(secret);
    let child = child?;

    let generation = {
        let mut c = clip.lock().await;
        if let Some(mut old) = c.owner.take() {
            let _ = old.kill().await;
        }
        c.generation += 1;
        c.owner = Some(child);
        c.generation
    };

    let clip = clip.clone();
    tokio::spawn(async move {
        tokio::time::sleep(CLEAR_AFTER).await;
        let mut c = clip.lock().await;
        if c.generation != generation {
            return;
        }
        if let Some(mut owner) = c.owner.take()
            && matches!(owner.try_wait(), Ok(None)) {
                let _ = owner.kill().await;
                let _ = Command::new("wl-copy").arg("--clear").status().await;
            }
    });
    Ok(())
}
