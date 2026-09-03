# Smudged Lens

**Active defense for your machine.** Makes your device look like something it is not to anyone scanning it with NMAP or similar tools.

## What it does

- **Port Spoofing** — Closed ports appear open, serving realistic service banners (Apache, nginx, MySQL, SSH, etc.)
- **OS Fingerprint Spoofing** — Your Linux machine shows up as Windows 11, macOS, or another OS to scanners; includes IPv6 Hop Limit spoofing via ip6tables on dual-stack hosts
- **DNS Wire Protocol** — Port 53 speaks real DNS (UDP + TCP) instead of plaintext banners; returns plausible A/AAAA/TXT/MX records and handles `version.bind` probes
- **Decoy Web Pages** — HTTP ports serve realistic fake pages (Apache default, nginx welcome, IIS, Tomcat); ports 443/8443 speak TLS with a throwaway self-signed certificate
- **Connection Logging** — Every scanner probe is logged with UTC timestamp, source IP, and target port — including probes that get rate-limited
- **Custom Ports** — Add any port with any service banner through the API
- **Rate Limiting** — Auto-blocks scanner IPs that probe too many ports quickly (real users are never affected)

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Run with the web GUI
python3 app.py

# Or run headless (no web GUI)
python3 cli.py serve

# In another terminal, drive it with the CLI
python3 cli.py status
```

Open **http://localhost:5000** for the GUI, or use the CLI for headless operation.

> **Security note:** The web GUI binds to `localhost` by default. To expose it on your network, set `SMUDGED_LENS_HOST=0.0.0.0` **and** read the [Security](#security) section first.

## GUI Features

- **Power button** — one toggle applies the full setup: OS profile, spoofed port count, port + OS deception
- **OS profile chips** — pick the personality your machine should project
- **Port count slider** — choose how many services to fake, with a live chip-by-chip preview of exactly which ports that OS profile exposes (highlighted = will come up when armed)
- **Captured Probes table** — live log of every scanner hit, rate-limited probes flagged in red
- Dark theme, responsive design

## CLI Reference

The CLI drives a **running** Smudged Lens process over its local API when one is reachable. Runtime state (active listeners, connection log, blocked IPs) lives inside that process — views of it need the app running. Commands that only edit configuration fall back to writing the config file directly when no app is running.

```bash
python3 cli.py status                    # Show current state (live if app is up)
python3 cli.py ports on                  # Enable all port spoofing
python3 cli.py ports off                 # Disable all port spoofing
python3 cli.py port 80 on               # Enable a specific port
python3 cli.py port 80 off              # Disable a specific port
python3 cli.py port 9999 add "Redis 7.2"  # Add a custom port
python3 cli.py port 9999 remove         # Remove a port
python3 cli.py os on                    # Enable OS fingerprint spoofing
python3 cli.py os off                   # Disable OS fingerprint spoofing (safe headless)
python3 cli.py os set windows11         # Switch OS profile
python3 cli.py profiles                 # List available OS profiles
python3 cli.py log                      # Show recent connections (live app required)
python3 cli.py log clear                # Clear the log (live app required)
python3 cli.py ratelimiter              # Show rate limiter status (live app required)
python3 cli.py ratelimiter block        # Show blocked IPs
python3 cli.py ratelimiter unblock 1.2.3.4  # Unblock an IP
python3 cli.py ratelimiter config 20 15 600 # Set thresholds
python3 cli.py serve --port 5000        # Run headless until Ctrl+C
```

Environment variables: `SMUDGED_LENS_PORT` (default 5000), `SMUDGED_LENS_API` (full base URL), `SMUDGED_LENS_TOKEN` (shared token, see below).

Configuration is stored at `~/.config/smudged-lens/config.json` — never inside the code tree, so pip installs stay read-only and upgrades don't wipe state. Override the directory with `SMUDGED_LENS_CONFIG_DIR`. Configs from pre-0.1.0 checkouts (a `config.json` beside the code) are migrated automatically on first run.

## Rate Limiter

The rate limiter detects scanner behavior by tracking **unique ports** probed per IP within a time window. Legitimate users hit 1-3 ports. Scanners (nmap -p-) hit dozens.

**Default thresholds:**
- More than 10 unique ports probed within 10 seconds triggers a block
- Blocks last 5 minutes (300 seconds)
- Localhost (127.0.0.1 and ::1) is always exempt

**How it works:**
- Only counts unique ports, not raw connections (hammering port 80 is fine)
- Blocked IPs are **tarpitted**: the TCP handshake completes in the kernel before Smudged Lens ever sees the packet, so blocked ports still show as "open" — but the connection is held open while junk bytes slowly trickle out, wasting the scanner's time, and **no service banner is ever served**
- Probes from blocked IPs are still logged (`blocked=true`, shown in red in the GUI)
- Blocks auto-expire after the configured duration; configurable via GUI or CLI

**Key safety feature:** This only affects connections to our spoofed ports. Real services on the machine (actual Apache, SSH, etc.) are completely unaffected — they run on their own processes.

## OS Profiles

| Profile | OS | TTL | TCP Window | MSS |
|---------|----|-----|------------|-----|
| windows11 | Windows 11 Pro 22H2 | 128 | 65535 | 1460 |
| windows10 | Windows 10 Pro 22H2 | 128 | 65535 | 1460 |
| macos | macOS 14.1 Sonoma | 64 | 65535 | 1460 |
| ubuntu | Ubuntu 22.04 LTS | 64 | 29200 | 1460 |
| centos | CentOS Stream 9 | 64 | 28960 | 1460 |

## How it works

**Port spoofing** opens lightweight TCP listeners on your chosen ports. Each listener handles clients concurrently (capped per port) and answers with a realistic service greeting — an SSH ident string and full auth-failure exchange, a protocol-correct MySQL handshake, real FTP/SMTP command sessions, a PostgreSQL v3 startup exchange, or a full HTTP response served *after* the client sends a request, exactly like a real server. Ports 443/8443 wrap the exchange in TLS using a generated self-signed certificate when openssl is available.

**Decoy pages** serve realistic HTML responses — Apache's default "It works!" page, nginx's welcome page, IIS branding, etc. — so HTTP probes look legitimate. Banners are sanitized to printable single-line ASCII, so they can't inject headers into responses.

**OS fingerprint spoofing** uses iptables to modify outgoing TTL values and TCP MSS options to match the target OS signature. NMAP's OS detection relies heavily on TTL (128=Windows, 64=Linux/macOS) and MSS values as fingerprint data points. Rules are tagged with a comment for safe cleanup — cleanup enumerates our rules precisely via `iptables-save` (with a fallback for stale rules) and removes only ours, never other programs' rules.

**Connection logging** records every connection to a spoofed port with a UTC ISO-8601 timestamp, source IP, source port, target port, and service name. Viewable in the GUI or via CLI against a running app. The log currently lives in memory — restarts clear it.

**Rate limiting** tracks unique ports probed per source IP. When an IP probes more than 10 unique ports within 10 seconds, further connections get tarpitted (held open, no service response) — and each such probe is still logged with `blocked=true`.

## Security

- The web GUI binds to `127.0.0.1` only.
- **Host header allowlist:** requests carrying a Host header other than `localhost` / `127.0.0.1` / `[::1]` are rejected with 403. This defeats DNS-rebinding attacks (a malicious webpage making its domain resolve to 127.0.0.1 while the browser keeps sending the attacker's hostname). Expose extra names with `SMUDGED_LENS_ALLOWED_HOSTS="myhost.example.com,dns2.example"`.
- **Optional shared token:** set `SMUDGED_LENS_TOKEN=<secret>` to require an `X-Auth-Token` header on every API call. The CLI reads the same variable.
- The dev server runs multi-threaded but is not hardened for hostile exposure — keep the GUI off public networks.
- OS spoofing requires root privileges (iptables). Port spoofing works without root on Linux; macOS currently permits low-port binds without root.
- iptables rules are automatically cleaned up on normal exit, SIGTERM/SIGINT, and crashes (`atexit`). `cli.py os off` also removes them headless — useful as an emergency cleanup.
- Rate limiting only affects connections to spoofed ports — your real services are never touched.
- **Known limitations, stated plainly:**
  - The TTL/HL rule applies to *all* outgoing traffic: traceroute/mtr results will reflect the spoofed TTL, and TTL-based CDN routing sees it too.
  - IPv6 spoofing requires ip6tables (Linux only, not available on macOS). Dual-stack macOS hosts still leak their real fingerprint over v6.
  - Blocked IPs still complete TCP handshakes and may be held open (tarpitted) — ports show "open" but serve nothing (see Rate Limiter).
  - RDP (3389) accepts and holds briefly without speaking X.224.
  - **Port conflicts with real services:** On any OS, if a real service is already running on a port Smudged Lens tries to spoof, the bind fails. The app logs the conflicting service name and OS-specific disable command. Common conflicts:
    - **macOS:** CUPS (port 631) — disable via System Settings > Printers & Scanners, or `sudo launchctl bootout system /System/Library/LaunchDaemons/com.apple.cups.plist`
    - **Linux:** SSH (port 22), Apache/nginx (80/443), MySQL (3306), PostgreSQL (5432) — stop with `systemctl stop <service>`
    - **Windows:** RDP (3389), IIS (80/443) — stop with `net stop <service>`
    - The app detects the conflict automatically and skips the port with a clear log message. Other ports start normally.

**Warning:** OS fingerprint spoofing on shared/corporate networks may violate policies. Use responsibly — this tool is for defending machines you own.

## Requirements

- Python 3.8+
- Flask
- Linux with iptables for OS fingerprint spoofing (requires root)
- Port spoofing works on any OS (Linux, macOS, Windows)

## Platform Support

| Feature | Linux | macOS | Windows |
|---------|-------|-------|--------|
| Port spoofing | ✅ | ✅ | ✅ |
| OS fingerprint spoofing (IPv4) | ✅ (requires root) | ❌ | ❌ |
| OS fingerprint spoofing (IPv6) | ✅ (requires root + ip6tables) | ❌ | ❌ |
| DNS wire protocol (UDP + TCP) | ✅ | ✅ | ✅ |
| Web GUI | ✅ | ✅ | ✅ |
| CLI | ✅ | ✅ | ✅ |
| Rate limiting | ✅ | ✅ | ✅ |

On macOS and Windows, the tool gracefully disables OS spoofing with a clear message and still provides full port spoofing, decoy pages, connection logging, and rate limiting.

## Development

```bash
python3 tests.py            # run the test suite (112 tests, no root needed)
```

The suite covers config handling (including corrupt-config recovery and atomic saves), rate limiter logic (block/unblock/expiry, localhost exemption), listener lifecycle (bind conflicts, stop→start races, HTTP request-waiting, HEAD handling, TLS handshakes), wire protocol realism (MySQL greeting + auth-error packets, SSH banner + KEXINIT/USERAUTH_FAILURE, DNS wire format for UDP and TCP, FTP/SMTP/PostgreSQL command sessions), tarpitting, banner sanitization and per-connection variance, IPv6 spoofing guards, web security (Host allowlist, token auth, Server-header hiding), and **fuzz hardening** — the DNS/banner parsers and the socket wire handlers are pounded with thousands of seeded malformed/hostile byte streams in CI to guarantee they never crash on untrusted input.

## License

MIT
