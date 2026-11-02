//! Thin async wrapper around the `rbw` CLI.
//!
//! Secrets only pass through here when the user runs an action; matching
//! works off metadata (`list --raw`) and the non-secret parts of `get --raw`.

use std::collections::HashSet;
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use serde::de::IgnoredAny;
use serde::Deserialize;
use tokio::process::Command;

const TIMEOUT: Duration = Duration::from_secs(15);
/// For user-initiated reads, which may wait on a master-password re-prompt.
pub const INTERACTIVE_TIMEOUT: Duration = Duration::from_secs(180);

#[derive(Debug, Clone, Deserialize)]
pub struct Status {
    #[serde(default)]
    pub agent: bool,
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
        Status { agent: false, logged_in: false, locked: true, last_sync: None }
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
    run_timeout(args, TIMEOUT).await
}

pub async fn run_timeout(args: &[&str], timeout: Duration) -> Result<Vec<u8>, String> {
    let child = Command::new("rbw")
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| format!("failed to start rbw: {e}"))?;
    let out = tokio::time::timeout(timeout, child.wait_with_output())
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

/// IDs of entries with "master password re-prompt" enabled. The agent asks
/// for the master password whenever one of their secrets is decrypted, so the
/// background index must not touch them. The flag is stored unencrypted in
/// rbw's sync database; we read every account's database in the profile's
/// cache dir (IDs are UUIDs, so merging is safe).
pub fn reprompt_ids() -> Result<HashSet<String>, String> {
    #[derive(Deserialize)]
    struct Db {
        entries: Vec<DbEntry>,
    }
    #[derive(Deserialize)]
    struct DbEntry {
        id: String,
        #[serde(default)]
        master_password_reprompt: serde_json::Value,
    }

    let cache = std::env::var_os("XDG_CACHE_HOME")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cache")))
        .ok_or("no cache dir")?;
    let profile = match std::env::var("RBW_PROFILE") {
        Ok(p) if !p.is_empty() => format!("rbw-{p}"),
        _ => "rbw".into(),
    };
    let dir = cache.join(profile);

    let mut ids = HashSet::new();
    let mut found = false;
    for f in std::fs::read_dir(&dir).map_err(|e| format!("{}: {e}", dir.display()))? {
        let path = f.map_err(|e| e.to_string())?.path();
        if path.extension().is_none_or(|e| e != "json") {
            continue;
        }
        let bytes = std::fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        let db: Db = serde_json::from_slice(&bytes).map_err(|e| format!("{}: {e}", path.display()))?;
        found = true;
        ids.extend(db.entries.into_iter().filter_map(|e| {
            let on = match e.master_password_reprompt {
                serde_json::Value::Number(n) => n.as_u64() != Some(0),
                serde_json::Value::Bool(b) => b,
                _ => false,
            };
            on.then_some(e.id)
        }));
    }
    if found { Ok(ids) } else { Err(format!("no rbw database in {}", dir.display())) }
}

pub async fn status() -> Status {
    match run(&["status", "--json"]).await {
        Ok(out) => {
            let mut st: Status = serde_json::from_slice(&out).unwrap_or_default();
            // Without an agent any `list`/`get` would start one and prompt.
            st.locked |= !st.agent;
            st
        }
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
