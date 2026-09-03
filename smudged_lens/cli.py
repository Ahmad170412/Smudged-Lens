#!/usr/bin/env python3
"""
Smudged Lens — Command Line Interface

The CLI drives a running Smudged Lens app over its local API when one is
reachable, and falls back to editing config.json (with honest messaging)
when it isn't. Runtime state — active listeners, the connection log,
blocked IPs — lives in the running process, so those views need the app.

Usage:
    python3 cli.py status              Show current spoofing state
    python3 cli.py ports on            Enable all configured port spoofing
    python3 cli.py ports off           Disable all port spoofing
    python3 cli.py port <num> on       Enable a specific port
    python3 cli.py port <num> off      Disable a specific port
    python3 cli.py port <num> add <banner>   Add a custom port
    python3 cli.py port <num> remove   Remove a port
    python3 cli.py os on               Enable OS fingerprint spoofing
    python3 cli.py os off              Disable OS fingerprint spoofing
    python3 cli.py os set <profile>    Switch OS profile
    python3 cli.py log                 Show recent connection log
    python3 cli.py log clear           Clear the connection log
    python3 cli.py profiles            List available OS profiles
    python3 cli.py ratelimiter         Show rate limiter status
    python3 cli.py ratelimiter block   Show blocked IPs
    python3 cli.py ratelimiter unblock <ip>  Unblock an IP
    python3 cli.py ratelimiter config <threshold> <window> <block_duration>
    python3 cli.py serve [--port N] [--host H]
                                       Run headless (no web GUI), Ctrl+C to stop

Environment:
    SMUDGED_LENS_PORT     Port of the running app / API (default: 5000)
    SMUDGED_LENS_TOKEN    Shared token, required if the app was started with one
"""

import json
import os
import sys
import threading
import urllib.error
import urllib.request

from .config import HAS_IPTABLES, IS_LINUX, OS_PROFILES, load_config, save_config
from .spoof_engine import (
    install_exit_handlers,
    os_fingerprinter,
    port_responder,
    restore_state,
)

API_BASE = os.environ.get(
    "SMUDGED_LENS_API",
    f"http://127.0.0.1:{os.environ.get('SMUDGED_LENS_PORT', '5000')}"
)
API_TIMEOUT = 2


# ---------------------------------------------------------------------------
# API plumbing — talk to the live app when it's up
# ---------------------------------------------------------------------------

def _api(method, path, body=None):
    """Call the app's HTTP API. Returns (status_code, parsed_json_or_None)."""
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(API_BASE + path, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    token = os.environ.get("SMUDGED_LENS_TOKEN", "")
    if token:
        req.add_header("X-Auth-Token", token)
    try:
        with urllib.request.urlopen(req, timeout=API_TIMEOUT) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        try:
            payload = json.loads(e.read().decode())
        except (ValueError, OSError, UnicodeDecodeError):
            payload = {}
        return e.code, payload
    except (urllib.error.URLError, OSError):
        return None, None


def _app_status():
    """Return live status dict if the app is reachable, else None."""
    code, data = _api("GET", "/api/status")
    return data if code == 200 and isinstance(data, dict) else None


def _not_running():
    print(f"  Smudged Lens is not reachable at {API_BASE}")
    print("  Start it with: python3 app.py  — or run headless with: python3 cli.py serve")


def _saved_only_hint():
    print("  (app not running — change saved to config.json and will apply on next start)")


def _print_api_result(result, ok_msg=None):
    code, data = result
    if code is None:
        _not_running()
        return False
    if code >= 400:
        print(f"  Error: {data.get('error', code)}")
        return False
    if ok_msg:
        print(f"  {ok_msg}")
    elif data.get("message"):
        print(f"  {data['message']}")
    else:
        print(f"  OK: {data}")
    return True


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_status():
    live = _app_status()
    config = load_config()
    print("\n  Smudged Lens Status")
    print("  " + "=" * 40)
    print(f"  Port Spoofing:  {'ON' if config.get('port_spoofing_enabled') else 'OFF'}")
    if IS_LINUX and HAS_IPTABLES:
        print(f"  OS Spoofing:    {'ON' if config.get('os_spoofing_enabled') else 'OFF'}")
        if config.get("os_spoofing_enabled"):
            prof = OS_PROFILES.get(config.get("os_profile", "windows11"), {})
            print(f"  OS Profile:     {prof.get('name', '?')} "
                  f"(TTL={prof.get('ttl')}, MSS={prof.get('mss', '?')})")
    else:
        print("  OS Spoofing:    N/A (requires Linux + iptables)")
    print(f"  Configured:     {len(config.get('spoofed_ports', {}))} ports")

    if live:
        blocked = live.get("rate_limiter", {}).get("blocked_ips", [])
        print(f"  Active Ports:   {live.get('active_port_count', 0)} "
              f"— {sorted(p for p, c in live.get('spoofed_ports', {}).items() if c.get('active')) or 'none'}")
        print(f"  Probes caught:  {live.get('total_log_hits', 0)}")
        print(f"  Blocked IPs:    {len(blocked)}")
    else:
        print("  Active Ports:   n/a (app not running)")
    print()


def cmd_ports_on():
    if _app_status():
        _print_api_result(_api("POST", "/api/port/all", {"enabled": True}))
        return
    config = load_config()
    config["port_spoofing_enabled"] = True
    save_config(config)
    print("  Port spoofing ON")
    _saved_only_hint()


def cmd_ports_off():
    if _app_status():
        _print_api_result(_api("POST", "/api/port/all", {"enabled": False}))
        return
    config = load_config()
    config["port_spoofing_enabled"] = False
    save_config(config)
    print("  Port spoofing OFF")
    _saved_only_hint()


def cmd_port_on(port_num):
    port = str(port_num)
    if _app_status():
        _print_api_result(_api("POST", "/api/port/toggle", {"port": port, "enabled": True}))
        return
    config = load_config()
    if port not in config["spoofed_ports"]:
        print(f"  Error: Port {port} not configured. Use 'port {port} add <banner>' first.")
        return
    config["spoofed_ports"][port]["enabled"] = True
    save_config(config)
    print(f"  Port {port} enabled — {config['spoofed_ports'][port]['service']}")
    _saved_only_hint()


def cmd_port_off(port_num):
    port = str(port_num)
    if _app_status():
        _print_api_result(_api("POST", "/api/port/toggle", {"port": port, "enabled": False}))
        return
    config = load_config()
    if port not in config["spoofed_ports"]:
        print(f"  Error: Port {port} not configured.")
        return
    config["spoofed_ports"][port]["enabled"] = False
    save_config(config)
    print(f"  Port {port} disabled")
    _saved_only_hint()


def cmd_port_add(port_num, banner):
    port = str(port_num)
    if _app_status():
        _print_api_result(_api("POST", "/api/port/add", {"port": port, "service": banner}))
        return
    config = load_config()
    if port in config["spoofed_ports"]:
        print(f"  Error: Port {port} already exists.")
        return
    config["spoofed_ports"][port] = {"enabled": True, "service": banner}
    save_config(config)
    print(f"  Port {port} added — {banner}")
    _saved_only_hint()


def cmd_port_remove(port_num):
    port = str(port_num)
    if _app_status():
        _print_api_result(_api("POST", "/api/port/remove", {"port": port}))
        return
    config = load_config()
    if port not in config["spoofed_ports"]:
        print(f"  Error: Port {port} not configured.")
        return
    del config["spoofed_ports"][port]
    save_config(config)
    print(f"  Port {port} removed")
    _saved_only_hint()


def cmd_os_on():
    if not IS_LINUX:
        print(f"  OS spoofing is only supported on Linux (current: {__import__('platform').system()})")
        return
    if not HAS_IPTABLES:
        print("  OS spoofing requires iptables — not found on this system")
        return
    # iptables rules are kernel state: applying them without a running daemon
    # would leave them unmanaged (no auto-cleanup on exit).
    if not _app_status():
        print("  Error: enabling OS spoofing needs a running Smudged Lens process")
        print("         to manage and clean up the iptables rules.")
        _not_running()
        return
    _print_api_result(_api("POST", "/api/os/toggle", {"enabled": True}))


def cmd_os_off():
    # Disabling works headless: removing our tagged rules from the kernel is
    # safe with no daemon around — useful as an emergency cleanup.
    _success, msg = os_fingerprinter.disable()
    config = load_config()
    config["os_spoofing_enabled"] = False
    save_config(config)
    print(f"  {msg}")


def cmd_os_set(profile):
    profile = str(profile).lower()
    if profile not in OS_PROFILES:
        print(f"  Error: Unknown profile '{profile}'.")
        cmd_profiles()
        return
    if _app_status():
        _print_api_result(_api("POST", "/api/os/profile", {"profile": profile}))
        return
    config = load_config()
    config["os_profile"] = profile
    save_config(config)
    print(f"  Profile set to {OS_PROFILES[profile]['name']} (will apply when OS spoofing is enabled)")
    _saved_only_hint()


def cmd_profiles():
    print("\n  Available OS Profiles")
    print("  " + "=" * 40)
    for key, prof in OS_PROFILES.items():
        print(f"  {key:<14} {prof['name']:<18} TTL={prof['ttl']}, Window={prof['tcp_window']}")
    print()


def cmd_log():
    live = _app_status()
    if not live:
        _not_running()
        print("  (the connection log lives inside the running app process)")
        return
    _code, data = _api("GET", "/api/log?limit=30")
    entries = (data or {}).get("entries", [])
    if not entries:
        print("  No connections logged yet.")
        return
    print(f"\n  Recent Connections ({len(entries)} shown)")
    print("  " + "=" * 70)
    print(f"  {'TIME':<22} {'SOURCE':<22} {'PORT':<8} {'SERVICE'}")
    print("  " + "-" * 70)
    for e in entries:
        flag = " [BLOCKED]" if e.get("blocked") else ""
        print(f"  {e['time']:<22} {e['source_ip']}:{e['source_port']:<12} :{e['dest_port']:<8} {e['service']}{flag}")
    print()


def cmd_log_clear():
    if _app_status():
        _print_api_result(_api("POST", "/api/log/clear", {}))
    else:
        _not_running()
        print("  (nothing to clear — the log lives inside the running app)")


def cmd_ratelimiter():
    live = _app_status()
    if not live:
        _not_running()
        return
    code, data = _api("GET", "/api/ratelimiter")
    if code != 200 or not data:
        print("  Error fetching rate limiter status")
        return
    print("\n  Rate Limiter Status")
    print("  " + "=" * 40)
    print(f"  Threshold:       {data['unique_ports_threshold']} unique ports")
    print(f"  Window:          {data['window_seconds']} seconds")
    print(f"  Block duration:  {data['block_duration']} seconds")
    print(f"  Tracked IPs:     {data.get('tracked_ips', 0)}")
    print(f"  Blocked IPs:     {len(data.get('blocked_ips', []))}")
    for b in data.get("blocked_ips", []):
        print(f"    {b['ip']:<20} (blocked for {b['remaining']}s)")
    print()


def cmd_ratelimiter_block():
    if not _app_status():
        _not_running()
        return
    _code, data = _api("GET", "/api/ratelimiter")
    blocked = (data or {}).get("blocked_ips", [])
    if not blocked:
        print("  No IPs currently blocked.")
        return
    print(f"\n  Blocked IPs ({len(blocked)})")
    print("  " + "=" * 40)
    for b in blocked:
        print(f"  {b['ip']:<20} Remaining: {b['remaining']}s")
    print()


def cmd_ratelimiter_unblock(ip):
    if not _app_status():
        _not_running()
        print("  (unblocking only makes sense against the running app)")
        return
    _print_api_result(_api("POST", "/api/ratelimiter/unblock", {"ip": ip}))


def cmd_ratelimiter_config(threshold, window, block_duration):
    try:
        threshold, window, block_duration = int(threshold), int(window), int(block_duration)
    except ValueError:
        print("  Error: threshold, window and block_duration must be integers")
        return
    if not _app_status():
        _not_running()
        return
    _print_api_result(_api("POST", "/api/ratelimiter/config",
                           {"threshold": threshold, "window": window,
                            "block_duration": block_duration}))


def cmd_serve(argv):
    """Headless mode: run the engine without the web GUI until interrupted."""
    # --port/--host are accepted for compatibility with app.py but have no
    # effect in headless mode (no HTTP server is started). Parsed only to
    # avoid surprising \"unknown argument\" errors when users reuse env.
    i = 0
    while i < len(argv):
        arg = argv[i]
        if (arg == "--port" or arg == "--host") and i + 1 < len(argv):
            i += 1
        else:
            print(f"  Unknown serve argument: {arg}")
            return
        i += 1

    install_exit_handlers()
    config = load_config()
    restore_state(config)

    running = sorted(port_responder.get_running_ports())
    host = os.environ.get("SMUDGED_LENS_HOST", "127.0.0.1")
    port = int(os.environ.get("SMUDGED_LENS_PORT", "5000"))
    print("\n  🔬 Smudged Lens serving headless (no web GUI)")
    print(f"  Spoofed ports active: {running if running else 'none'}")
    print(f"  Web GUI would be at http://{host}:{port} — run `python3 app.py` instead for it")
    print("  Press Ctrl+C to stop.\n")
    try:
        threading.Event().wait()  # blocks forever; signal handler exits the process
    except KeyboardInterrupt:
        pass
    print("  Shutting down.")


def print_usage():
    print(__doc__)


def main():
    if len(sys.argv) < 2:
        print_usage()
        return

    cmd = sys.argv[1].lower()

    if cmd == "status":
        cmd_status()
    elif cmd == "ports":
        if len(sys.argv) < 3:
            print("  Usage: cli.py ports <on|off>")
            return
        sub = sys.argv[2].lower()
        if sub == "on":
            cmd_ports_on()
        elif sub == "off":
            cmd_ports_off()
        else:
            print(f"  Unknown argument: {sub}")
    elif cmd == "port":
        if len(sys.argv) < 3:
            print("  Usage: cli.py port <num> <on|off|add|remove>")
            return
        port_num = sys.argv[2]
        action = sys.argv[3].lower() if len(sys.argv) > 3 else ""
        if action == "on":
            cmd_port_on(port_num)
        elif action == "off":
            cmd_port_off(port_num)
        elif action == "add":
            banner = " ".join(sys.argv[4:]) if len(sys.argv) > 4 else "Generic Server"
            cmd_port_add(port_num, banner)
        elif action == "remove":
            cmd_port_remove(port_num)
        else:
            print(f"  Unknown action: {action}")
    elif cmd == "os":
        if len(sys.argv) < 3:
            print("  Usage: cli.py os <on|off|set> [profile]")
            return
        sub = sys.argv[2].lower()
        if sub == "on":
            cmd_os_on()
        elif sub == "off":
            cmd_os_off()
        elif sub == "set":
            if len(sys.argv) < 4:
                print("  Usage: cli.py os set <profile>")
                return
            cmd_os_set(sys.argv[3])
        else:
            print(f"  Unknown argument: {sub}")
    elif cmd == "log":
        if len(sys.argv) > 2 and sys.argv[2].lower() == "clear":
            cmd_log_clear()
        else:
            cmd_log()
    elif cmd == "profiles":
        cmd_profiles()
    elif cmd == "ratelimiter":
        if len(sys.argv) < 3:
            cmd_ratelimiter()
        elif sys.argv[2].lower() == "block":
            cmd_ratelimiter_block()
        elif sys.argv[2].lower() == "unblock":
            if len(sys.argv) < 4:
                print("  Usage: cli.py ratelimiter unblock <ip>")
                return
            cmd_ratelimiter_unblock(sys.argv[3])
        elif sys.argv[2].lower() == "config":
            if len(sys.argv) < 6:
                print("  Usage: cli.py ratelimiter config <threshold> <window> <block_duration>")
                return
            cmd_ratelimiter_config(sys.argv[3], sys.argv[4], sys.argv[5])
        else:
            print(f"  Unknown subcommand: {sys.argv[2]}")
    elif cmd == "serve":
        cmd_serve(sys.argv[2:])
    else:
        print(f"  Unknown command: {cmd}")
        print_usage()


if __name__ == "__main__":
    main()
