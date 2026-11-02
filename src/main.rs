//! KRunner D-Bus runner for rbw (and rbw-enhanced).
//!
//! Queries start with the trigger word `bw`. While the vault is locked the
//! only result is an unlock action; once unlocked we search an in-memory
//! index that is filled from `rbw list` immediately and from `rbw get --raw`
//! (notes, non-hidden custom fields) in the background.

mod clipboard;
mod index;
mod rbw;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::process::Command;
use tokio::sync::Mutex;
use tokio::task::JoinSet;
use zbus::zvariant::Value;
use zbus::{interface, Connection};

use clipboard::SharedClip;
use index::Entry;

const SERVICE: &str = "local.krunner_rbw";
const PATH: &str = "/runner";
const TRIGGER: &str = "bw";
const MAX_RESULTS: usize = 15;
const STATUS_TTL: Duration = Duration::from_millis(1500);
const LOCK_POLL: Duration = Duration::from_secs(60);
const INDEX_CONCURRENCY: usize = 4;

const UNLOCK: &str = "rbw:unlock";
const LOGIN: &str = "rbw:login";
const LOCK: &str = "rbw:lock";
const SYNC: &str = "rbw:sync";

const ACT_USER: &str = "user";
const ACT_TOTP: &str = "totp";
const ACT_SITE: &str = "site";
const ACT_VAULT: &str = "vault";

type Props = HashMap<String, Value<'static>>;
type RemoteMatch = (String, String, String, i32, f64, Props);

#[derive(Default)]
struct Vault {
    entries: Vec<Entry>,
    /// `last_sync` the current entries were loaded for.
    loaded_for: Option<Option<i64>>,
    /// Bumped whenever entries are replaced or dropped; stale index passes bail.
    generation: u64,
    indexed: bool,
    status: Option<(Instant, rbw::Status)>,
}

impl Vault {
    fn drop_entries(&mut self) {
        if self.loaded_for.is_some() {
            self.entries.clear();
            self.loaded_for = None;
            self.indexed = false;
            self.generation += 1;
        }
    }
}

#[derive(Clone)]
struct Runner {
    vault: Arc<Mutex<Vault>>,
    clip: SharedClip,
    token: Arc<Mutex<Option<String>>>,
    conn: Arc<Mutex<Option<Connection>>>,
}

impl Runner {
    async fn notify(&self, summary: &str, body: &str) {
        let Some(conn) = self.conn.lock().await.clone() else { return };
        let hints: HashMap<&str, Value> = HashMap::from([("transient", Value::from(true))]);
        let _ = conn
            .call_method(
                Some("org.freedesktop.Notifications"),
                "/org/freedesktop/Notifications",
                Some("org.freedesktop.Notifications"),
                "Notify",
                &("Bitwarden", 0u32, "bitwarden", summary, body, Vec::<&str>::new(), hints, 3000i32),
            )
            .await;
    }

    /// Checks agent state and (re)loads entries if needed. Returns the status.
    async fn refresh(&self, force: bool) -> rbw::Status {
        let mut v = self.vault.lock().await;
        let status = match &v.status {
            Some((at, st)) if !force && at.elapsed() < STATUS_TTL => st.clone(),
            _ => {
                let st = rbw::status().await;
                v.status = Some((Instant::now(), st.clone()));
                st
            }
        };

        if status.locked || !status.logged_in {
            v.drop_entries();
            return status;
        }
        if v.loaded_for == Some(status.last_sync) {
            return status;
        }

        match rbw::list().await {
            Ok(list) => {
                v.entries = list.into_iter().map(Entry::from_list).collect();
                v.loaded_for = Some(status.last_sync);
                v.indexed = false;
                v.generation += 1;
                // Without the re-prompt list we can't tell which `get`s would
                // prompt, so skip the background pass rather than risk it.
                match rbw::reprompt_ids() {
                    Ok(reprompt) => {
                        for e in &mut v.entries {
                            e.reprompt = reprompt.contains(&e.id);
                        }
                        let ids: Vec<String> =
                            v.entries.iter().filter(|e| !e.reprompt).map(|e| e.id.clone()).collect();
                        tokio::spawn(self.clone().index_full(v.generation, ids));
                    }
                    Err(e) => eprintln!("not indexing notes/fields: can't read re-prompt flags: {e}"),
                }
            }
            Err(e) => eprintln!("rbw list failed: {e}"),
        }
        status
    }

    /// Background pass reading notes and custom fields for every entry.
    async fn index_full(self, generation: u64, ids: Vec<String>) {
        let started = Instant::now();
        let mut fulls = Vec::with_capacity(ids.len());
        for chunk in ids.chunks(INDEX_CONCURRENCY) {
            // Never run `rbw get` against a locked vault: it would pop pinentry.
            if self.vault.lock().await.generation != generation || rbw::status().await.locked {
                return;
            }
            let mut set = JoinSet::new();
            for id in chunk {
                let id = id.clone();
                set.spawn(async move {
                    let full = rbw::get_full(&id).await;
                    (id, full)
                });
            }
            while let Some(res) = set.join_next().await {
                match res {
                    Ok((id, Ok(full))) => fulls.push((id, full)),
                    Ok((id, Err(e))) => eprintln!("rbw get {id} failed: {e}"),
                    Err(e) => eprintln!("index task failed: {e}"),
                }
            }
        }

        let mut v = self.vault.lock().await;
        if v.generation != generation {
            return;
        }
        let mut by_id: HashMap<String, _> = fulls.into_iter().collect();
        for e in &mut v.entries {
            if let Some(full) = by_id.remove(&e.id) {
                e.upgrade(full);
            }
        }
        v.indexed = true;
        eprintln!("indexed {} entries in {:.1?}", v.entries.len(), started.elapsed());
    }

    async fn copy_rbw(&self, what: &str, args: &[&str]) {
        match rbw::run_timeout(args, rbw::INTERACTIVE_TIMEOUT).await {
            Ok(out) if out.iter().all(u8::is_ascii_whitespace) => {
                self.notify(&format!("No {what}"), "This entry has none set").await
            }
            Ok(out) => match clipboard::copy_secret(&self.clip, out).await {
                Ok(()) => {
                    let secs = clipboard::CLEAR_AFTER.as_secs();
                    self.notify(&format!("{what} copied"), &format!("Clears in {secs} s")).await
                }
                Err(e) => self.notify("Copy failed", &e).await,
            },
            Err(e) => self.notify(&format!("Could not get {what}"), &e).await,
        }
    }

    async fn open_vault(&self, id: &str) {
        let cfg = rbw::config().await;
        let base = cfg
            .ui_url
            .or(cfg.base_url)
            .unwrap_or_else(|| "https://vault.bitwarden.com".into());
        self.open_url(format!("{}/#/vault?itemId={id}&action=view", base.trim_end_matches('/')))
            .await
    }

    async fn open_url(&self, url: String) {
        let mut cmd = Command::new("xdg-open");
        cmd.arg(url);
        if let Some(token) = self.token.lock().await.take() {
            cmd.env("XDG_ACTIVATION_TOKEN", token);
        }
        if let Err(e) = cmd.status().await {
            self.notify("Could not open browser", &e.to_string()).await;
        }
    }

    async fn vault_command(&self, args: &[&str], done: &str) {
        match rbw::run_interactive(args).await {
            Ok(()) => {
                self.notify(done, "").await;
                self.refresh(true).await;
            }
            Err(e) => self.notify(&format!("rbw {} failed", args[0]), &e).await,
        }
    }

    async fn run_entry(&self, id: &str, action: &str) {
        let entry = {
            let v = self.vault.lock().await;
            v.entries.iter().find(|e| e.id == id).cloned()
        };
        let Some(entry) = entry else {
            self.notify("Entry not found", "The vault changed; search again").await;
            return;
        };
        match action {
            ACT_USER => match entry.user.as_deref() {
                Some(u) => match clipboard::copy_plain(&self.clip, u).await {
                    Ok(()) => self.notify("Username copied", "").await,
                    Err(e) => self.notify("Copy failed", &e).await,
                },
                None => self.notify("No username", "This entry has none set").await,
            },
            ACT_TOTP => self.copy_rbw("One-time code", &["code", id]).await,
            ACT_SITE => match entry.website() {
                Some(url) => self.open_url(url).await,
                None => self.notify("No website", "This entry has no URL a browser can open").await,
            },
            ACT_VAULT => self.open_vault(id).await,
            _ if entry.is_login() => self.copy_rbw("Password", &["get", id]).await,
            _ if entry.kind == "Note" => {
                self.copy_rbw("Note", &["get", "--field", "notes", id]).await
            }
            _ => self.open_vault(id).await,
        }
    }
}

fn props(subtext: String, actions: &[&str]) -> Props {
    let actions: Vec<String> = actions.iter().map(|a| a.to_string()).collect();
    HashMap::from([
        ("subtext".into(), Value::from(subtext)),
        ("category".into(), Value::from("Bitwarden")),
        ("actions".into(), Value::from(actions)),
    ])
}

fn utility(id: &str, text: &str, icon: &str, subtext: &str) -> RemoteMatch {
    (id.into(), text.into(), icon.into(), 100, 1.0, props(subtext.into(), &[]))
}

/// `bw`, `bw foo` → Some(""), Some("foo"); anything else → None.
fn parse_query(query: &str) -> Option<&str> {
    let rest = query.trim_start().strip_prefix(TRIGGER)?;
    if rest.is_empty() {
        Some("")
    } else if rest.starts_with(char::is_whitespace) {
        Some(rest.trim())
    } else {
        None
    }
}

#[interface(name = "org.kde.krunner1")]
impl Runner {
    #[zbus(name = "Config")]
    async fn config(&self) -> HashMap<String, Value<'static>> {
        HashMap::from([
            ("TriggerWords".into(), Value::from(vec![TRIGGER.to_string()])),
            ("MinLetterCount".into(), Value::from(TRIGGER.len() as i32)),
        ])
    }

    #[zbus(name = "Actions")]
    async fn actions(&self) -> Vec<(String, String, String)> {
        [
            (ACT_USER, "Copy username", "user-identity"),
            (ACT_TOTP, "Copy one-time code", "chronometer"),
            (ACT_SITE, "Open website", "internet-web-browser"),
            (ACT_VAULT, "Open in web vault", "bitwarden"),
        ]
        .into_iter()
        .map(|(a, b, c)| (a.into(), b.into(), c.into()))
        .collect()
    }

    #[zbus(name = "Match")]
    async fn find(&self, query: String) -> Vec<RemoteMatch> {
        let Some(term) = parse_query(&query) else { return Vec::new() };
        let status = self.refresh(false).await;

        if !status.logged_in {
            return vec![utility(LOGIN, "Log in to Bitwarden", "user-identity", "rbw login")];
        }
        if status.locked {
            return vec![utility(UNLOCK, "Unlock Bitwarden", "unlock", "Vault is locked")];
        }

        let v = self.vault.lock().await;
        if term.is_empty() {
            let state = if v.indexed { "notes and fields indexed" } else { "indexing notes…" };
            let info = format!("{} entries, {state}", v.entries.len());
            return vec![
                utility(SYNC, "Sync Bitwarden vault", "view-refresh", &info),
                utility(LOCK, "Lock Bitwarden vault", "lock", &info),
            ];
        }

        index::search(&v.entries, term, MAX_RESULTS)
            .into_iter()
            .map(|hit| {
                let e = hit.entry;
                let mut sub: Vec<String> = Vec::new();
                sub.extend(e.user.clone());
                sub.extend(e.folder.clone());
                if e.user.is_none() && e.folder.is_none() {
                    sub.push(e.kind.clone());
                }
                if e.reprompt {
                    sub.push("asks for master password".into());
                }
                if let Some(via) = hit.via {
                    sub.push(format!("matched in {via}"));
                }
                let mut actions = Vec::new();
                if e.is_login() {
                    if e.user.is_some() {
                        actions.push(ACT_USER);
                    }
                    if e.has_totp != Some(false) {
                        actions.push(ACT_TOTP);
                    }
                }
                if e.website().is_some() {
                    actions.push(ACT_SITE);
                }
                actions.push(ACT_VAULT);
                (e.id.clone(), e.name.clone(), "bitwarden".into(), 50, hit.score, props(sub.join(" · "), &actions))
            })
            .collect()
    }

    #[zbus(name = "Run")]
    async fn run(&self, match_id: String, action_id: String) {
        let this = self.clone();
        // Return immediately; KRunner closes while we work.
        tokio::spawn(async move {
            match match_id.as_str() {
                UNLOCK => this.vault_command(&["unlock"], "Vault unlocked").await,
                LOGIN => this.vault_command(&["login"], "Logged in").await,
                SYNC => this.vault_command(&["sync"], "Vault synced").await,
                LOCK => this.vault_command(&["lock"], "Vault locked").await,
                id => this.run_entry(id, &action_id).await,
            }
        });
    }

    #[zbus(name = "SetActivationToken")]
    async fn set_activation_token(&self, token: String) {
        *self.token.lock().await = Some(token);
    }

    #[zbus(name = "Teardown")]
    async fn teardown(&self) {
        // Keep the index (rebuilding takes seconds) but re-check lock state next session.
        self.vault.lock().await.status = None;
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> zbus::Result<()> {
    let runner = Runner {
        vault: Arc::default(),
        clip: Arc::default(),
        token: Arc::default(),
        conn: Arc::default(),
    };
    let conn = zbus::connection::Builder::session()?
        .name(SERVICE)?
        .serve_at(PATH, runner.clone())?
        .build()
        .await?;
    *runner.conn.lock().await = Some(conn);

    // Drop the index soon after the agent auto-locks, even if KRunner is never opened.
    loop {
        tokio::time::sleep(LOCK_POLL).await;
        if runner.vault.lock().await.loaded_for.is_some() {
            runner.refresh(true).await;
        }
    }
}
