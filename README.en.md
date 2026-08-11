[Русский](README.md) | **English**

# MTProxy — Automated Deployment for Ubuntu

> One-command MTProxy server setup with Fake TLS obfuscation, multi-user secrets, watchdog, and DPI resistance. Built for Ubuntu 22.04 / 24.04 LTS.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform: Ubuntu 22.04 / 24.04](https://img.shields.io/badge/Platform-Ubuntu%2022.04%20%2F%2024.04-E95420.svg)](https://ubuntu.com/)
[![Version: 1.3.0](https://img.shields.io/badge/Version-1.3.0-success.svg)](CHANGELOG.md)

---

## Quick Start

```bash
git clone https://github.com/lingeniare/MTProxy.git && cd MTProxy && sudo bash install_mtproxy.sh
```

That's it. The script prints a ready-to-use `tg://proxy?...` link at the end — open it on your phone and Telegram connects automatically.

---

## What the Installer Does

1. Installs system dependencies (including `cron` if missing).
2. Configures NTP time sync — clock drift breaks the MTProto handshake.
3. Creates an isolated system user `mtproxy`.
4. Compiles MTProxy from the [official Telegram source](https://github.com/TelegramMessenger/MTProxy).
5. Downloads and validates Telegram configuration files.
6. Picks a plausible Fake TLS domain (verifies DNS + TLS 1.3) and generates secrets.
7. Auto-detects NAT for cloud VPS environments.
8. Registers a hardened systemd service with auto-restart and restart-storm limiting.
9. Sets up a watchdog: health check every 2 minutes, automatic restart on failure.
10. Configures per-IP connection rate limiting via `iptables`.
11. Schedules cron jobs: daily config refresh + weekly binary update (with rollback).
12. Opens the firewall port and persists rules across reboots.

---

## Why Not `www.google.com`?

Fake TLS impersonates a TLS handshake to a specified domain. If the domain is `google.com` but the server IP doesn't belong to Google, DPI trivially detects the mismatch between SNI and IP ownership — followed by active probing and blocking.

Instead, the installer picks from a list of "neutral" services (Microsoft, Discord CDN, Cloudflare, etc.) and verifies the domain actually serves TLS 1.3. You can supply your own list via `--domain-list`.

Another factor: TLS traffic on a non-standard port stands out. Use `--port 443` to blend in with regular HTTPS.

---

## Multi-User Management

Each user gets their own secret (`/etc/mtproxy/secrets.d/<name>.secret`). Revoking one user's access doesn't affect others.

```bash
mtproxy-user.sh add alice     # Create user and get link
mtproxy-user.sh link alice    # Show link again
mtproxy-user.sh list          # List all users
mtproxy-user.sh del alice     # Revoke access
```

---

## Security Architecture

| Mechanism | Implementation |
|----------|----------------|
| Privilege isolation | Dedicated system user `mtproxy` (no login shell, no home) |
| Secret protection | `/etc/mtproxy/secrets.d` with `0600` permissions |
| Protocol obfuscation | Fake TLS with auto-selected plausible domain (TLS 1.3 verified) |
| DPI resistance | `iptables hashlimit` rate-limiting; optional port 443 |
| Multi-secret | Per-user secrets (`secrets.d`) with granular revocation |
| systemd hardening | `NoNewPrivileges`, `ProtectSystem=strict`, `PrivateTmp`, resource limits |
| Watchdog | systemd timer: 2-min checks, auto-restart on failure |
| Time sync | NTP via `timesyncd` / `chrony` |
| Persistence | Firewall rules saved via `netfilter-persistent` |
| Auto-update | Config daily, binary weekly (with validation + rollback) |
| NAT | Auto-detection of `--nat-info` for cloud environments |

---

## Options

Defaults are tuned for small groups (up to ~5 users). No flags required for typical use.

| Flag | Description | Default |
|------|-------------|---------|
| `--domain`, `-D` | Domain for Fake TLS SNI | Auto-selected from built-in list (validated) |
| `--domain-list` | Comma-separated custom domain list for auto-selection | _(optional)_ |
| `--port` | Port: `auto`, `443` (HTTPS camouflage), or a number | `auto` (random) |
| `--tag`, `-P` | Tag from [@MTProxybot](https://t.me/MTProxybot) | _(optional)_ |
| `--rate-limit` | New connection limit per IP | `5/min` |
| `--rate-burst` | Allowed burst | `10` |
| `--tune-net` | Network tuning: BBR, buffers, backlog | Disabled |
| `--ipv6` | Enable IPv6 (`-6`) and show IPv6 link | Disabled |

**Environment variables:**

| Variable | Description | Default |
|----------|-------------|---------|
| `FORCE_UNSHARE=auto\|1\|0` | PID namespace workaround: `auto` enables `unshare` if `pid_max > 65535` or `ns_last_pid > 65535`; `1` always; `0` never | `auto` |

---

## PID > 65535 Workaround

On systems with a large `kernel.pid_max` (e.g. `4194304`), MTProxy may crash on startup:

```text
mtproto-proxy: common/pid.c:42: init_common_PID: Assertion `!(p & 0xffff0000)' failed.
```

**Cause:** `mtproto-proxy` expects a 16-bit PID, but systemd may assign a PID > 65535.

The installer automatically wraps the binary in a PID namespace (compatible with Ubuntu 24.04 / systemd 255):

```text
/usr/bin/unshare --pid --fork --mount-proc -- /opt/MTProxy/objs/bin/mtproto-proxy ...
```

This doesn't change global sysctl or require containerization. The unit also includes `StartLimitIntervalSec=60` and `StartLimitBurst=5` to prevent restart storms.

**Verification:**

1. `systemctl cat MTProxy` — `ExecStart` should contain `unshare` if the workaround is active.
2. `journalctl -u MTProxy -f` — MTProxy PIDs typically appear as `[1]`, `[2]`.
3. `systemctl status MTProxy` — `MainPID` belongs to `unshare`; child `mtproto-proxy` runs in the same cgroup.

---

## Administration

```bash
systemctl status MTProxy          # Service status
systemctl restart MTProxy         # Restart
journalctl -u MTProxy -f          # Live logs
journalctl -t mtproxy-watchdog    # Watchdog logs
curl localhost:2398/stats         # Diagnostic stats
```

---

## Updating

```bash
cd MTProxy && git pull && sudo bash install_mtproxy.sh
```

Re-running preserves the port, secret, and domain from the current configuration. Previously issued links remain valid.

---

## Uninstall

```bash
sudo bash uninstall_mtproxy.sh
```

Removes the service, watchdog, cron jobs, firewall rules, user, and all files.

---

## Limitations

MTProxy only proxies text messages and media files. Voice and video calls are **not supported** through MTProxy. For full call functionality, consider [WireGuard](https://www.wireguard.com/) or [AmneziaWG](https://amnezia.org/) with split tunneling.

---

## Requirements

- Ubuntu 22.04 LTS or 24.04 LTS
- Root access
- Internet connectivity

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Bug reports and pull requests are welcome.

## Security

See [SECURITY.md](SECURITY.md) for the security policy and architecture details.

## License

[MIT](LICENSE) — (c) 2026 [@ingeniare](https://github.com/ingeniare)
