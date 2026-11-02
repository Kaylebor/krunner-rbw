# krunner-rbw

KRunner (Plasma search) plugin for [rbw](https://github.com/doy/rbw) and rbw-enhanced.
It is a D-Bus runner, a separate process speaking `org.kde.krunner1`, so it does not break when Plasma/KF versions change the way compiled runner plugins do.

## Usage

Type `bw <terms>` in KRunner. Every term must match somewhere: name, username, URL, folder, notes, or a non-hidden custom field.

| Key / button        | Action                                   |
| ------------------- | ---------------------------------------- |
| Enter               | Copy password (notes for secure notes; web vault for cards/identities) |
| Copy username       | Copy login                               |
| Copy one-time code  | `rbw code`                               |
| Open website        | Opens the entry's first http(s) URL (bare hosts get `https://`) |
| Open in web vault   | Opens the entry in your Bitwarden web vault |

`bw` on its own offers **Sync** and **Lock**. While the vault is locked, the only result is **Unlock Bitwarden**, which runs `rbw unlock` (pinentry, PIN, or system auth, depending on your rbw config).

Secrets are copied with `wl-copy --sensitive`, so Klipper keeps them out of its history. They are cleared after 30 s unless you've copied something else since.

## How it works

- Match never reads secrets. On unlock (or when `last_sync` changes) the runner loads `rbw list --raw` right away, then reads `rbw get --raw` for every entry in the background (about 13 s for ~1300 entries) to index notes and custom fields. Fields of type `hidden`, passwords, TOTP secrets, and history are not kept.
- The index lives in memory only and is dropped within a minute of the vault locking (it checks `rbw status` every 60 s, and on every query).
- The background pass checks the lock state before each batch, so it never makes `rbw` pop a pinentry prompt.
- Entries with Bitwarden's *master password re-prompt* are skipped by the background pass (the agent would ask for your password every time they are read). They're still searchable by name, login, URL and folder, but not by notes or fields. Copying from one asks for the master password, as Bitwarden intends. The re-prompt flag comes from rbw's local sync database; if that can't be read, the background pass is skipped entirely.

## Install

Requires Rust, `just`, `wl-clipboard`, and Plasma 6 on Wayland.

```bash
just install
```

This installs `~/.local/bin/krunner-rbw`, the plugin file in `~/.local/share/krunner/dbusplugins/`, and a D-Bus activation file, then restarts KRunner. The runner starts on demand. `just uninstall` removes everything.

Logs: `journalctl --user -t krunner-rbw`.

## License

MIT, see [LICENSE](LICENSE).
