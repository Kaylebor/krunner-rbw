//! Thin async wrapper around the `rbw` CLI.
//!
//! Secrets only pass through here when the user runs an action; matching
//! works off metadata (`list --raw`) and the non-secret parts of `get --raw`.

use std::process::Stdio;
use std::time::Duration;

use serde::de::IgnoredAny;
use serde::Deserialize;
use tokio::process::Command;

const TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Debug, Clone, Deserialize)]
pub struct Status {
    #[serde(default)]
    pub logged_in: bool,
    #[serde(default = "yes")]
    pub locked: bool,
    #[serde(default)]
    pub last_sync: Option<i64>,
}

fn yes() -> bool {
    true
}

impl Default for Status {
    fn default() -> Self {
        Status { logged_in: false, locked: true, last_sync: None }
    }
}

/// One row of `rbw list --raw`.
#[derive(Debug, Clone, Deserialize)]
pub struct ListEntry {
    pub id: String,
    pub name: String,
    pub user: Option<String>,
    pub folder: Option<String>,
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default, deserialize_with = "null_as_empty")]
    pub uris: Vec<String>,
}

fn null_as_empty<'de, D, T>(d: D) -> Result<Vec<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    null_as_default(d)
}

fn null_as_default<'de, D, T>(d: D) -> Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de> + Default,
{
    Ok(Option::<T>::deserialize(d)?.unwrap_or_default())
}

/// The parts of `rbw get --raw` we index. Password, TOTP secret and
/// history are deliberately not captured (`IgnoredAny` keeps only presence).
#[derive(Debug, Deserialize)]
pub struct FullEntry {
    pub notes: Option<String>,
    #[serde(default, deserialize_with = "null_as_default")]
    pub data: Data,
    #[serde(default, deserialize_with = "null_as_empty")]
    pub fields: Vec<Field>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct Data {
    pub username: Option<String>,
    pub totp: Option<IgnoredAny>,
}

#[derive(Debug, Deserialize)]
pub struct Field {
    pub name: Option<String>,
    pub value: Option<String>,
    #[serde(rename = "type")]
    pub kind: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
pub struct Config {
    pub base_url: Option<String>,
    pub ui_url: Option<String>,
}

/// Runs `rbw <args>` and returns stdout, or stderr as the error.
pub async fn run(args: &[&str]) -> Result<Vec<u8>, String> {
    let child = Command::new("rbw")
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| format!("failed to start rbw: {e}"))?;
    let out = tokio::time::timeout(TIMEOUT, child.wait_with_output())
        .await
        .map_err(|_| "rbw timed out".to_string())?
        .map_err(|e| e.to_string())?;
    if out.status.success() {
        Ok(out.stdout)
    } else {
        let err = String::from_utf8_lossy(&out.stderr).trim().to_string();
        Err(if err.is_empty() { format!("rbw exited with {}", out.status) } else { err })
    }
}

/// Like `run`, but for interactive commands (unlock/login) that may wait on
/// pinentry for as long as the user takes.
pub async fn run_interactive(args: &[&str]) -> Result<(), String> {
    let out = Command::new("rbw")
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .await
        .map_err(|e| format!("failed to start rbw: {e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
    }
}

pub async fn status() -> Status {
    match run(&["status", "--json"]).await {
        Ok(out) => serde_json::from_slice(&out).unwrap_or_default(),
        Err(_) => Status::default(),
    }
}

pub async fn list() -> Result<Vec<ListEntry>, String> {
    let out = run(&["list", "--raw"]).await?;
    serde_json::from_slice(&out).map_err(|e| e.to_string())
}

pub async fn get_full(id: &str) -> Result<FullEntry, String> {
    let out = run(&["get", "--raw", id]).await?;
    serde_json::from_slice(&out).map_err(|e| e.to_string())
}

pub async fn config() -> Config {
    match run(&["config", "show"]).await {
        Ok(out) => serde_json::from_slice(&out).unwrap_or_default(),
        Err(_) => Config::default(),
    }
}
