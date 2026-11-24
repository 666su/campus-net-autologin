<p align="center">
  <a href="./README.md"><img src="https://img.shields.io/badge/English-0052CC?style=for-the-badge" alt="English"></a>
  <a href="./README.zh-CN.md"><img src="https://img.shields.io/badge/%E4%B8%AD%E6%96%87-495057?style=for-the-badge" alt="中文"></a>
</p>

# 🔌 Campus Network Auto Re-login — SRun / Shrun Portal

Your campus network kicks you offline at 3 a.m. Every automation task that was running dies with it,
and you only find out the next morning.

This tool watches the campus portal and logs you back in within seconds — **fully offline, no browser,
zero third-party dependencies**. It works even while you have no internet at all, because the only thing
it talks to is the portal on your own LAN.

Verified on a real campus account: after the session was killed, connectivity came back in **11.4 seconds**
(`login took 0.12 s`, see [CHANGELOG](CHANGELOG.md)).

| Component | Value |
|---|---|
| Target protocol | SRun (深澜) portal — `SRunFlag: SRun portal server golang version` |
| Offline detection | `GET /cgi-bin/rad_user_info` on the portal (LAN only, no internet needed) |
| Login | `get_challenge` → HMAC-MD5 password → XXTEA + base64 `info` → signed `srun_portal` |
| Runtime | Python 3.8+, **standard library only** (`pip install` nothing) |
| Background | Hidden `pythonw` process + Windows Task Scheduler (logon trigger + 5-minute guard) |
| Other platforms | systemd unit / launchd plist / crontab templates in `deploy/` |

> 👤 **Author: Jason** ｜ 📝 Blog: https://blog.20240606.xyz/ ｜ 🐙 GitHub: https://github.com/666su

```
$ python campus_net.py check
portal http://192.168.1.1: reachable
ac_id: 6
operators: @cmccgx=China Mobile, @dx=China Telecom, @uestc=Campus
session: user 202600000000, domain dx, ip 210.41.x.x, service Telecom
result: online
```

## Why not "refresh the login page every N minutes"

| | Refresh-the-page scripts | This project |
|---|---|---|
| Needs a browser | Yes (breaks on captchas / front-end rewrites) | No, calls the auth API directly |
| Works while offline | No — it can only guess | Yes, the portal is reachable *because* you are unauthenticated |
| Kicks your own phone offline | Yes (blind re-login) | No — see safety rails below |
| Depends on the internet | Yes | **No, offline by design** |
| Runs as a background process | Hard | One command |

## Safety rails (baked in after a real incident)

1. **Portal says "online" → not a single byte is sent.** Login only happens when the portal explicitly
   reports an unauthenticated session.
2. **Never logs out.** `guard.allow_force_logout: false` by default.
3. **Login rate limit** (6 per hour by default). Above that it waits instead of hammering your account.
4. **`pause` switch.** After `python campus_net.py pause` it does not touch the portal at all — safe to use
   the same account on another device.
5. **Exponential backoff** on failures (60 s → 120 s → … → 15 min).

> Campus accounts usually allow **one device online**. Any auto re-login tool kicks your other devices
> whenever it logs in — including this one. That is why it only acts when nobody is online.

## Quick start (Windows)

```powershell
copy config.example.json config.json
python campus_net.py init      # asks for portal address / account / password, probes ac_id & operators
python campus_net.py doctor    # read-only health check: portal, crypto, operator suffix, background state
python campus_net.py install   # background: logon autostart + 5-minute guard
```

Then you can close the window.

```powershell
python campus_net.py status    # daemon + last check
python campus_net.py pause     # freeze it (e.g. you want to use the same account on your phone)
python campus_net.py resume
python campus_net.py uninstall # remove tasks + stop daemon
```

## Configuration (`config.json`)

| Field | Meaning |
|---|---|
| `portal.host` | **Your** portal address, e.g. `192.168.1.1` — the IP in the address bar of the login page |
| `portal.scheme` | `http` (default) or `https` |
| `portal.ac_id` | Leave empty to auto-detect (read from the `/` redirect) |
| `account.username` | Student ID / phone number |
| `account.password` | Password (plain text — see FAQ) |
| `account.operator` | `telecom` / `mobile` / `campus` |
| `account.domain` | Explicit suffix such as `@dx`; overrides `operator` |
| `guard.interval_sec` | Check interval while online (default 30 s) |
| `guard.interval_offline_sec` | Retry interval while offline (default 10 s) |
| `guard.max_logins_per_hour` | Login cap per hour (default 6) |
| `guard.allow_force_logout` | Allow "logout then login" (default `false`) |
| `probe.enabled` | Optional external probing, default `false` (pure offline). Only needed to detect "portal says online but there is no traffic" |

Operator suffixes differ per school; the tool **reads them from the portal page** and `doctor` prints them.
Use `config.example.json` as the template — `config.json` is git-ignored, so credentials never enter the repo.

## Commands

| Command | Purpose |
|---|---|
| `init` | Interactive config wizard |
| `doctor` | Health check (portal, ac_id, operators, crypto self-test, background state) |
| `check` | Print current state, do nothing |
| `fix` | Re-login once if offline — ideal as a pre-step in your own automation scripts |
| `start` / `stop` / `status` | Background daemon control |
| `pause` / `resume` | Freeze / unfreeze (frozen = never touches the portal) |
| `watch` | Run in foreground (debugging) |
| `install` / `uninstall` | Register / remove the scheduled tasks |
| `selftest` | Offline crypto self-test (no network, no config needed) |

Exit codes: `0` online, `2` offline / needs login, `3` configuration problem — handy for `if errorlevel`.

## Deployment

### Windows (recommended, no admin needed)

`python campus_net.py install` creates two tasks:

1. `CampusNetWatcher` — at **logon**, starts the hidden `pythonw` daemon;
2. `CampusNetGuard` — **every 5 minutes**, runs `ensure`, which restarts the daemon if it died.

Both run with `LIMITED` privileges (no UAC prompt). Tasks are registered from **XML** (not a `/TR` command
line), so paths with spaces and quotes are fine; the `LogonTrigger` carries an explicit `UserId` — without it
Windows treats the task as "any user" and requires administrator rights.

Verify it is really running:

```powershell
python campus_net.py status
```

```
CampusNetAutoLogin v1.0.0
  daemon   : running (PID 26148)
  paused   : no
  last check: 2026-11-24 13:34:37
  state    : user 2026xxxxxx, domain dx, ip 210.41.x.x, service Telecom
  logins   : 1 ok / 0 failed
```

### Linux / macOS

```bash
cp config.example.json config.json && python3 campus_net.py init && python3 campus_net.py doctor

mkdir -p ~/.config/systemd/user
sed "s#__REPO__#$PWD#g" deploy/campus-net.service > ~/.config/systemd/user/campus-net.service
systemctl --user daemon-reload && systemctl --user enable --now campus-net

# or just a crontab entry every 2 minutes
*/2 * * * * cd /path/to/repo && python3 campus_net.py fix >/dev/null 2>&1
```

macOS: `deploy/com.campusnet.autologin.plist` via `launchctl load -w`.

## How it works

**Detecting a drop — ask only the LAN portal.** While unauthenticated you have no internet, but the portal
is still reachable (that is how you log in). So:

```
GET /cgi-bin/rad_user_info?callback=cb
  {"error":"ok","online_ip":"...","user_name":"...","domain":"dx"}   → online
  {"error":"not_online_error"}                                      → dropped, log in
  connection refused / timeout                                      → NIC down, retry next tick
```

No internet address is ever contacted, which is why it keeps working with the network down.
The admin dashboard also exposes `keepalive_time`, a timestamp after which an idle session is reclaimed —
one of the usual causes of "it dies every night".

**Logging in:**

1. `get_challenge` → `token` (bound to your IP, valid ~60 s)
2. password hash: `{MD5}` + `HMAC-MD5(key=token, msg=password)`
3. `info`: `{SRBX1}` + custom-alphabet base64(XXTEA(json, token))
4. `chksum`: `sha1(token + username + token + hmd5 + token + ac_id + token + ip + token + n + token + type + token + info)`
5. `srun_portal?action=login&…` — success when `error == "ok"`

The protocol — including the tricky `md5(password, token)` (it is **HMAC-MD5**, not `md5(password + token)`) —
is documented in [`docs/protocol.md`](docs/protocol.md).

**Background:** a file-lock single-instance daemon plus a 5-minute guard task; a cross-process login lock
keeps the two from logging in simultaneously and knocking each other's session out.

## Tests

No network, no real account required:

```bash
python -m unittest discover -s tests -v
```

* `tests/test_crypto.py` — crypto vectors taken from the portal's own JavaScript output
* `tests/test_integration.py` + `tests/mock_portal.py` — a **local mock portal** that really validates
  chksum / HMAC-MD5 / decrypted `info`, covering: dropped → auto re-login, online → no re-login,
  portal unreachable all night, wrong-password backoff, pause switch, login rate limit, task XML arguments
* `tests/test_no_secrets.py` — fails if `config.json` or runtime files ever become tracked

## FAQ

**Why is the password stored in plain text?**
SRun needs the plaintext password as the HMAC message; a hash-only login is not possible. It stays in the
local `config.json` (git-ignored; `install` tightens its ACL). Never commit it.

**Will this kick my own computer offline?**
No. It only logs in when there is no online session at all. Once "online" is detected it does nothing —
there is a dedicated test for that.

**My portal isn't `192.168.1.1`.**
Set `portal.host` to yours; `ac_id` is auto-detected. If the page mentions `SRunFlag` / `srun_portal` it is
this protocol; `Dr.COM` or Ruijie `ePortal` are different systems.

**Can I get banned?**
The tool only automates the "click Login" you would do by hand, rate-limited to ≤6 attempts/hour.
Use it for your own account only — not for credential sharing or multi-device bypass.

**Where are the logs?** `campus_net.log` (rotated, 2 MB × 3). `run/state.json` holds the current state.

## Layout

```
campus_net.py            single-file program (stdlib only)
config.example.json      template (committed)    config.json  your own (git-ignored)
tests/                   offline unit tests + local mock portal
docs/protocol.md         SRun protocol notes
deploy/                  systemd / launchd / crontab / Windows batch
CHANGELOG.md             what changed, including field findings
```

## License

MIT — see [LICENSE](LICENSE). For personal, legitimate network access only;
please respect your school's network usage policy.
