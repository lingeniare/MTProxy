<p align="center">
  <a href="README.md">Русский</a> &nbsp;|&nbsp; <b>English</b>
</p>

<p align="center">
  <img src="cover.webp" alt="MTProxy — Telegram Proxy Bypass" width="100%" />
</p>

<h1 align="center">MTProxy — Automated Deployment for Ubuntu</h1>

<p align="center">
  One-command MTProxy setup on <b>Ubuntu 22.04 / 24.04 LTS</b> with Fake TLS obfuscation,<br/>
  multi-user secrets, watchdog & DPI resistance
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue.svg?style=flat-square" alt="License: MIT"/></a>
  <a href="https://ubuntu.com/"><img src="https://img.shields.io/badge/Platform-Ubuntu%2022.04%20%2F%2024.04-E95420.svg?style=flat-square&logo=ubuntu&logoColor=white" alt="Platform"/></a>
  <a href="CHANGELOG.md"><img src="https://img.shields.io/badge/Version-1.3.1-success.svg?style=flat-square" alt="Version"/></a>
  <img src="https://img.shields.io/badge/FakeTLS-TLS%201.3-7A5CFA.svg?style=flat-square" alt="FakeTLS"/>
  <img src="https://img.shields.io/badge/DPI-resistant-00B37E.svg?style=flat-square" alt="DPI"/>
</p>

<p align="center"><b>Project Sponsors</b></p>

<table>
<tr>
<td align="center" valign="top" width="50%">

<h3>💬 VEGA Chat</h3>

The most versatile AI chat in the world<br/>with free <b>Autopilot</b> — all AI models,<br/>image / video / music & website generation. Personalized for you.

<br/><br/>
<a href="https://vega.chat"><img src="https://img.shields.io/badge/Explore_vega.chat-7A5CFA?style=for-the-badge&logo=sparkles&logoColor=white" alt="Explore vega.chat"/></a>

</td>
<td align="center" valign="top" width="50%">

<h3>🔌 VEGA API</h3>

All <b>OpenRouter</b> endpoints in Russia + catalog of<br/><b>MCP, SKILL, apps</b> and <b>VEGA SKILL API</b><br/>to build your own AI apps without limits.

<br/><br/>
<a href="https://api.vega.chat"><img src="https://img.shields.io/badge/Explore_API-00B37E?style=for-the-badge&logo=rocket&logoColor=white" alt="Explore API"/></a>

</td>
</tr>
</table>

---

<table>
<tr>
<td align="center" valign="top" width="33%">

### � Built from official source

Compiled directly from [Telegram's MTProxy](https://github.com/TelegramMessenger/MTProxy) — no prebuilt binaries, no hidden patches. Fully transparent and auditable.

</td>
<td align="center" valign="top" width="33%">

### 🧩 Safe on a live server

Isolated `mtproxy` user, dedicated port, no interference with existing services. Install alongside your website, bot or VPN without conflicts.

</td>
<td align="center" valign="top" width="33%">

### � Set and forget

Watchdog, automatic config & binary updates, `flock` guards and reboot persistence — runs for years with zero manual maintenance.

</td>
</tr>
</table>

---

## 🚀 Quick Start

```bash
git clone https://github.com/lingeniare/MTProxy.git && cd MTProxy && sudo bash install_mtproxy.sh
```

> That's it. The script prints a ready-to-use `tg://proxy?...` link and a **QR code** — open it on your phone and Telegram connects automatically.

---

## ⚙️ What the Installer Does

| # | Action |
|---|--------|
| 1 | Installs system dependencies (including `cron` if missing) |
| 2 | Configures NTP time sync — clock drift breaks the MTProto handshake |
| 3 | Creates an isolated system user `mtproxy` |
| 4 | Compiles MTProxy from the [official Telegram source](https://github.com/TelegramMessenger/MTProxy) |
| 5 | Downloads and validates Telegram configuration files |
| 6 | Picks a plausible Fake TLS domain from 11 neutral candidates (DNS + TLS 1.3 with valid cert, JA4/ECH-aware) and generates secrets |
| 7 | Auto-detects NAT for cloud VPS environments |
| 8 | Registers a hardened systemd service via wrapper `/etc/mtproxy/run.sh` (secrets never hit the unit) with extended hardening and restart-storm limiting |
| 9 | Sets up a **watchdog**: health check every 2 min with `flock`, auto-restart after 3 consecutive failures |
| 10 | Configures per-IP connection rate limiting via `iptables` |
| 11 | Schedules cron jobs: daily config refresh + weekly binary update (with `flock`, validation, rollback, backup in `$INSTALL_DIR`) |
| 12 | Opens the firewall port and persists rules across reboots |

---

## 🕵️ Why Not `www.google.com`?

Fake TLS impersonates a TLS handshake to a specified domain. If the domain is `google.com` but the server IP doesn't belong to Google, DPI trivially detects the mismatch between **SNI ↔ IP ownership** (JA4/ECH) — followed by active probing and blocking.

Instead, the installer picks from **11 neutral services** (Microsoft, Discord CDN, Cloudflare, Bing, Adobe, Spotify, Dropbox, etc.) and verifies `DNS + TLS 1.3` with a valid chain-of-trust (`curl --tlsv1.3 --fail`, HEAD fallback for CDNs) — JA4/ECH-aware. Supply your own list via `--domain-list`.

> 💡 **Port is also camouflage.** TLS on a non-standard port stands out. Use `--port 443` to blend in with regular HTTPS.

---

## 👥 Multi-User Management

> Each user gets their own secret `(/etc/mtproxy/secrets.d/<name>.secret)`. Revoking one doesn't affect others.

```bash
mtproxy-user.sh add alice     # Create user and get link
mtproxy-user.sh link alice    # Show link again
mtproxy-user.sh list          # List all users
mtproxy-user.sh del alice     # Revoke access
```

---

## 🛡️ Security Architecture

| Mechanism | Implementation |
|-----------|----------------|
| **Privilege isolation** | Dedicated system user `mtproxy` (no login shell, no home) |
| **Secret protection** | `/etc/mtproxy/secrets.d` (`0600`, `root:root`) + wrapper `/etc/mtproxy/run.sh` — secrets injected at runtime |
| **Protocol obfuscation** | Fake TLS with auto-selection from 11 domains (DNS + TLS 1.3 + valid cert, JA4/ECH) |
| **DPI resistance** | `iptables hashlimit` rate-limiting; optional port `443` |
| **Multi-secret** | Per-user secrets (`secrets.d`) with granular revocation |
| **systemd hardening** | `NoNewPrivileges`, `ProtectSystem=strict`, `PrivateTmp`, `LockPersonality`, `RestrictSUIDSGID`, `RemoveIPC`, `SystemCallArchitectures=native`, `TasksMax`/`MemoryMax` |
| **Watchdog** | systemd timer: 2-min checks with `flock`, auto-restart after 3 failures |
| **Time sync** | NTP via `timesyncd` / `chrony` |
| **Persistence** | Firewall rules saved via `netfilter-persistent` |
| **Auto-update** | Config daily, binary weekly (with `flock`, validation + rollback) |
| **NAT** | Auto-detection of `--nat-info` for cloud environments |

---

## 🔧 Options

Defaults are tuned for small groups (up to ~5 users). No flags required for typical use.

| Flag | Description | Default |
|------|-------------|---------|
| `--domain`, `-D` | Domain for Fake TLS SNI | Auto-selected from built-in list (validated) |
| `--domain-list` | Comma-separated custom domain list | _(optional)_ |
| `--port` | Port: `auto`, `443` (HTTPS camouflage), or number | `auto` (random) |
| `--tag`, `-P` | Tag from [@MTProxybot](https://t.me/MTProxybot) | _(optional)_ |
| `--rate-limit` | New connection limit per IP | `5/min` |
| `--rate-burst` | Allowed burst | `10` |
| `--tune-net` | Network tuning: BBR, buffers, backlog | Disabled |
| `--ipv6` | Enable IPv6 (`-6`) and show IPv6 link | Disabled |

**Environment variables:**

| Variable | Description | Default |
|----------|-------------|---------|
| `FORCE_UNSHARE=auto\|1\|0` | PID namespace workaround | `auto` |

---

## 🧩 PID > 65535 Workaround

On systems with large `kernel.pid_max` (e.g. `4194304`), MTProxy may crash:

```text
mtproto-proxy: common/pid.c:42: init_common_PID: Assertion `!(p & 0xffff0000)' failed.
```

The installer wraps the binary in a PID namespace (Ubuntu 24.04 / systemd 255 compatible):

```text
/usr/bin/unshare --pid --fork --mount-proc -- /opt/MTProxy/objs/bin/mtproto-proxy ...
```

<details>
<summary><b>Verify the workaround</b></summary>

1. `systemctl cat MTProxy` — `ExecStart` should be `/etc/mtproxy/run.sh` (prefixed with `unshare` if active).
2. `journalctl -u MTProxy -f` — PIDs appear as `[1]`, `[2]`.
3. `systemctl status MTProxy` — `MainPID` belongs to `unshare`/`run.sh`.

</details>

---

## 🖥️ Administration

```bash
systemctl status MTProxy          # Service status
systemctl restart MTProxy         # Restart
journalctl -u MTProxy -f          # Live logs
journalctl -t mtproxy-watchdog    # Watchdog logs
curl localhost:2398/stats         # Diagnostic stats
```

---

## 🔄 Updating

```bash
cd MTProxy && git pull && sudo bash install_mtproxy.sh
```

Re-running preserves port, secret, and domain. Previous links remain valid.

---

## 🗑️ Uninstall

```bash
sudo bash uninstall_mtproxy.sh
```

Removes service, watchdog, cron jobs, firewall rules, user, and all files.

---

## ⚠️ Limitations

MTProxy only proxies **text and media**. Voice/video calls are **not supported**. For calls use [WireGuard](https://www.wireguard.com/) or [AmneziaWG](https://amnezia.org/) with split tunneling.

---

## 📋 Requirements

- Ubuntu 22.04 LTS / 24.04 LTS
- Root access
- Internet connectivity

---

<p align="center">
  <b>☕ Support the project</b><br/>
  <a href="https://buymeacoffee.com/vegaspace" target="_blank"><img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" alt="Buy Me A Coffee" height="50" width="210"/></a>
</p>

<p align="center">
  <a href="CONTRIBUTING.md">Contributing</a> •
  <a href="SECURITY.md">Security</a> •
  <a href="LICENSE">MIT License</a>
</p>

<p align="center">
  <sub>© 2026 <a href="https://getmyai.io">AI for people and business</a></sub>
</p>
