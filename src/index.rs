//! In-memory search index over vault metadata.
//!
//! Entries start "light" (from `rbw list`) and are upgraded to "full" once the
//! background pass has read notes and custom fields. Hidden fields are never
//! stored.

use crate::rbw::{FullEntry, ListEntry};

#[derive(Debug, Clone)]
pub struct Entry {
    pub id: String,
    pub name: String,
    pub user: Option<String>,
    pub folder: Option<String>,
    pub kind: String,
    pub uris: Vec<String>,
    /// `None` until the full pass has looked at the entry.
    pub has_totp: Option<bool>,
    // Lowercased haystacks.
    name_l: String,
    user_l: String,
    folder_l: String,
    uris_l: Vec<String>,
    notes_l: String,
    fields_l: Vec<String>,
}

impl Entry {
    pub fn from_list(e: ListEntry) -> Self {
        Entry {
            name_l: e.name.to_lowercase(),
            user_l: e.user.as_deref().unwrap_or_default().to_lowercase(),
            folder_l: e.folder.as_deref().unwrap_or_default().to_lowercase(),
            uris_l: e.uris.iter().map(|u| u.to_lowercase()).collect(),
            notes_l: String::new(),
            fields_l: Vec::new(),
            has_totp: None,
            id: e.id,
            name: e.name,
            user: e.user,
            folder: e.folder,
            kind: e.kind,
            uris: e.uris,
        }
    }

    pub fn upgrade(&mut self, full: FullEntry) {
        if self.user.is_none()
            && let Some(u) = full.data.username.filter(|u| !u.is_empty()) {
                self.user_l = u.to_lowercase();
                self.user = Some(u);
            }
        self.notes_l = full.notes.unwrap_or_default().to_lowercase();
        self.fields_l = full
            .fields
            .into_iter()
            .filter(|f| f.kind.as_deref() != Some("hidden"))
            .map(|f| {
                format!("{}: {}", f.name.unwrap_or_default(), f.value.unwrap_or_default())
                    .to_lowercase()
            })
            .collect();
        self.has_totp = Some(full.data.totp.is_some());
    }

    pub fn is_login(&self) -> bool {
        self.kind == "Login"
    }

    /// First stored URI a browser can open; bare hosts get `https://`.
    pub fn website(&self) -> Option<String> {
        self.uris.iter().find_map(|u| {
            let u = u.trim();
            match u.split_once("://") {
                Some(("http" | "https", _)) => Some(u.to_string()),
                Some(_) => None, // androidapp://, iosapp://, …
                None if !u.is_empty() && !u.contains(char::is_whitespace) => {
                    Some(format!("https://{u}"))
                }
                None => None,
            }
        })
    }
}

pub struct Hit<'a> {
    pub entry: &'a Entry,
    pub score: f64,
    /// Set when some term only matched in notes or custom fields.
    pub via: Option<&'static str>,
}

fn score_name(hay: &str, tok: &str) -> Option<f64> {
    if hay.starts_with(tok) {
        Some(1.0)
    } else if let Some(i) = hay.find(tok) {
        let at_word = !hay[..i].chars().next_back().is_some_and(char::is_alphanumeric);
        Some(if at_word { 0.9 } else { 0.8 })
    } else {
        None
    }
}

fn score_token(e: &Entry, tok: &str) -> Option<(f64, Option<&'static str>)> {
    if let Some(s) = score_name(&e.name_l, tok) {
        return Some((s, None));
    }
    if e.user_l.contains(tok) {
        return Some((0.6, None));
    }
    if e.uris_l.iter().any(|u| u.contains(tok)) {
        return Some((0.55, None));
    }
    if e.folder_l.contains(tok) {
        return Some((0.45, None));
    }
    if e.fields_l.iter().any(|f| f.contains(tok)) {
        return Some((0.35, Some("custom field")));
    }
    if e.notes_l.contains(tok) {
        return Some((0.3, Some("notes")));
    }
    None
}

/// Every whitespace-separated term must match somewhere in the entry.
pub fn search<'a>(entries: &'a [Entry], query: &str, limit: usize) -> Vec<Hit<'a>> {
    let toks: Vec<String> = query.split_whitespace().map(str::to_lowercase).collect();
    if toks.is_empty() {
        return Vec::new();
    }
    let mut hits: Vec<Hit> = entries
        .iter()
        .filter_map(|e| {
            let mut total = 0.0;
            let mut via = None;
            for t in &toks {
                let (s, v) = score_token(e, t)?;
                total += s;
                via = via.or(v);
            }
            Some(Hit { entry: e, score: total / toks.len() as f64, via })
        })
        .collect();
    hits.sort_by(|a, b| {
        b.score
            .total_cmp(&a.score)
            .then_with(|| a.entry.name.len().cmp(&b.entry.name.len()))
    });
    hits.truncate(limit);
    hits
}
