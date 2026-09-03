import logging
import os
import sys
import threading
import time

from flask import Flask, jsonify, render_template, request

from .config import IS_LINUX, OS_PROFILES, is_root, load_config, save_config
from .spoof_engine import (
    install_exit_handlers,
    os_fingerprinter,
    port_responder,
    rate_limiter,
    restore_state,
    sanitize_banner,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S"
)
logger = logging.getLogger("smudged_lens")

app = Flask(__name__)
config = load_config()
_start_time = time.time()
# config.json mutations come from multiple request threads — serialize them
_config_lock = threading.Lock()

# --- API access control -----------------------------------------------------
#
# The API has no user accounts. Two layers protect it:
#
#   1. Host allowlist — a browser request to http://127.0.0.1:5000 carries the
#      site's real hostname in the Host header. DNS rebinding attacks make an
#      attacker's domain resolve to 127.0.0.1 while the *browser* still sends
#      the attacker's hostname, so rejecting unknown Host headers kills the
#      whole class of attack.
#   2. Optional shared token (SMUDGED_LENS_TOKEN env) — when set, every /api/*
#      call must send a matching X-Auth-Token header.

_ALLOWED_HOSTS = {"localhost", "127.0.0.1", "::1"}
_extra_hosts = os.environ.get("SMUDGED_LENS_ALLOWED_HOSTS", "")
_ALLOWED_HOSTS.update(h.strip().lower() for h in _extra_hosts.split(",") if h.strip())

app.config["SMUDGED_LENS_TOKEN"] = os.environ.get("SMUDGED_LENS_TOKEN", "")


def _hostname_of(host_header):
    """Extract bare hostname from a Host header ('127.0.0.1:5000', '[::1]:5000')."""
    if not host_header:
        return ""
    h = host_header.strip().lower()
    if h.startswith("["):
        return h.split("]", 1)[0].lstrip("[")
    return h.rsplit(":", 1)[0] if ":" in h else h


@app.before_request
def _access_control():
    host = _hostname_of(request.host)
    if host and host not in _ALLOWED_HOSTS:
        logger.warning(f"Rejected request with untrusted Host header: {request.host!r}")
        return jsonify({"error": "Untrusted Host header"}), 403

    token = app.config.get("SMUDGED_LENS_TOKEN", "")
    if token and request.path.startswith("/api/") and request.headers.get("X-Auth-Token") != token:
        return jsonify({"error": "Missing or invalid X-Auth-Token"}), 401
    return None


def _make_masked_handler():
    """A Werkzeug dev-server handler that identifies as IIS, not Werkzeug/Python.

    Flask's ``after_request`` runs *before* the dev server serializes the HTTP
    response, and Werkzeug re-appends ``Server: Werkzeug/… Python/…`` at that
    point — so a Flask hook alone cannot hide the stack. Overriding
    ``version_string`` silences the leak at the only place it can actually be
    fixed for ``app.run``, and yields a single honest ``Server: Microsoft-IIS``
    header.
    """
    from werkzeug.serving import WSGIRequestHandler

    class _MaskedHandler(WSGIRequestHandler):
        def version_string(self):
            return "Microsoft-IIS/10.0"

    return _MaskedHandler


def _json_body():
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else {}


# Ordered, realistic service sets per OS profile. The first N entries are
# used when the user asks for N spoofed ports — no manual port management.
AUTO_PORT_SETS = {
    "windows11": [
        (3389, "Microsoft Terminal Services"),
        (80, "Microsoft-IIS/10.0"),
        (443, "Microsoft-IIS/10.0"),
        (445, "Windows Server 2022"),
        (1433, "Microsoft SQL Server 16.0.1000"),
        (5985, "Microsoft HTTPAPI 2.0"),
        (21, "Microsoft FTP Service"),
        (25, "Microsoft ESMTP MAIL Service"),
        (53, "Microsoft DNS 10.0"),
        (8443, "Microsoft-IIS/10.0"),
        (139, "Windows NetBIOS"),
        (631, "CUPS 2.4.7"),
        (3306, "MySQL 8.0.31"),
    ],
    "windows10": [
        (3389, "Microsoft Terminal Services"),
        (80, "Microsoft-IIS/10.0"),
        (443, "Microsoft-IIS/10.0"),
        (445, "Windows Server 2019"),
        (139, "Windows NetBIOS"),
        (5985, "Microsoft HTTPAPI 2.0"),
        (21, "Microsoft FTP Service"),
        (25, "Microsoft ESMTP MAIL Service"),
        (53, "Microsoft DNS 10.0"),
        (1433, "Microsoft SQL Server 15.0.2000"),
        (8443, "Microsoft-IIS/10.0"),
        (631, "CUPS 2.4.7"),
        (3306, "MySQL 8.0.31"),
    ],
    "macos": [
        (22, "OpenSSH_9.6"),
        (88, "macOS Kerberos"),
        (548, "Apple File Sharing"),
        (631, "CUPS 2.4.7"),
        (5900, "VNC Remote Desktop"),
        (3283, "Apple Remote Desktop"),
        (80, "Server 14.1"),
        (443, "Server 14.1"),
        (3306, "MySQL 8.0.35"),
        (445, "macOS SMB"),
        (21, "ProFTPD 1.3.8"),
        (8443, "Server 14.1"),
    ],
    "ubuntu": [
        (22, "OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"),
        (80, "Apache/2.4.58 (Ubuntu)"),
        (443, "nginx/1.24.0"),
        (3306, "MySQL 8.0.35-0ubuntu0.22.04.1"),
        (8080, "Apache Tomcat/9.0.82"),
        (21, "ProFTPD 1.3.6"),
        (25, "Postfix smtpd"),
        (53, "ISC BIND 9.18.18"),
        (5432, "PostgreSQL 15.5"),
        (8443, "Apache/2.4.58 (Ubuntu)"),
        (139, "Samba 4.17.12"),
        (445, "Samba 4.17.12"),
    ],
    "centos": [
        (22, "OpenSSH_8.7"),
        (80, "nginx/1.20.1"),
        (443, "httpd/2.4.62"),
        (3306, "MariaDB 10.5.22"),
        (8080, "Apache Tomcat/10.0.27"),
        (21, "vsftpd 3.0.5"),
        (25, "Postfix smtpd"),
        (53, "ISC BIND 9.16.23"),
        (5432, "PostgreSQL 13.14"),
        (8443, "httpd/2.4.62"),
        (139, "Samba 4.17.5"),
        (631, "CUPS 2.3"),
        (445, "Samba 4.17.5"),
    ],
}


def apply_setup(enabled, profile, count):
    """Apply the full one-shot configuration: on/off + OS + number of ports."""
    ports = AUTO_PORT_SETS[profile][:count]
    skipped = []

    with _config_lock:
        new_set = [p for p, _ in ports]
        new_banner = dict(ports)
        old_service = {
            str(p): cfg.get("service") for p, cfg in config.get("spoofed_ports", {}).items()
        }

        def _stale(port):
            """A running port needs a restart when it's no longer wanted, or its
            service identity changed (switching OS profile must swap the banner
            — not keep the previous profile's, or overlapping ports leak a mixed
            incoherent fingerprint to scanners)."""
            if not enabled or port not in new_set:
                return True
            return old_service.get(str(port)) != new_banner.get(port)

        running = list(port_responder.get_running_ports())
        already_ok = {p for p in running if not _stale(p)}
        # Stop responders that are no longer wanted or must change identity
        for port in running:
            if _stale(port):
                port_responder.stop_port(port)

        config["spoofed_ports"] = {
            str(p): {"enabled": True, "service": banner} for p, banner in ports
        }
        config["port_spoofing_enabled"] = enabled

        if enabled:
            for p, banner in ports:
                if p in already_ok:
                    continue  # already listening with the correct banner
                started = port_responder.start_port(p, banner)
                if not started:
                    skipped.append(p)
        else:
            port_responder.stop_all()

        # OS fingerprint spoofing
        config["os_profile"] = profile
        if enabled and is_root():
            success, _msg = os_fingerprinter.enable(profile)
            config["os_spoofing_enabled"] = success
        else:
            if config.get("os_spoofing_enabled"):
                os_fingerprinter.disable()
            config["os_spoofing_enabled"] = False

        save_config(config)
    return ports, skipped


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/portsets")
def port_sets():
    """Ordered (port, banner) sets per OS profile — the GUI uses this to preview
    exactly which ports the slider will fake before the user arms defense.
    Kept separate from /api/status because it's static for the process lifetime."""
    return jsonify(AUTO_PORT_SETS)


@app.route("/api/status")
def status():
    running_ports = port_responder.get_running_ports()
    port_status = {}
    for port, cfg in config.get("spoofed_ports", {}).items():
        port_status[port] = {
            "enabled": cfg.get("enabled", False),
            "service": cfg.get("service", ""),
            "active": int(port) in running_ports
        }
    counts = port_responder.conn_log.get_counts()
    total_hits = sum(counts.values())
    return jsonify({
        "port_spoofing_enabled": config.get("port_spoofing_enabled", False),
        "os_spoofing_enabled": config.get("os_spoofing_enabled", False),
        "os_profile": config.get("os_profile", "windows11"),
        "os_profile_info": OS_PROFILES.get(config.get("os_profile", "windows11"), {}),
        "spoofed_ports": port_status,
        "active_port_count": len(running_ports),
        "uptime": int(time.time() - _start_time),
        "is_root": is_root(),
        "os_spoofing_supported": IS_LINUX,
        "total_log_hits": total_hits,
        "rate_limiter": {
            "blocked_ips": rate_limiter.get_blocked_ips(),
            "tracked_ips": rate_limiter.get_tracked_ips(),
            **rate_limiter.get_config()
        }
    })


@app.route("/api/port/toggle", methods=["POST"])
def toggle_port():
    data = _json_body()
    port = str(data.get("port"))
    enabled = bool(data.get("enabled"))

    with _config_lock:
        if port not in config["spoofed_ports"]:
            return jsonify({"error": f"Unknown port: {port}"}), 400

        config["spoofed_ports"][port]["enabled"] = enabled

        # If master switch is on, actually start/stop the port
        if config.get("port_spoofing_enabled"):
            banner = config["spoofed_ports"][port]["service"]
            if enabled:
                started = port_responder.start_port(port, banner)
                if not started:
                    save_config(config)
                    return jsonify({"error": f"Could not bind port {port}"}), 409
            else:
                port_responder.stop_port(port)

        save_config(config)
    return jsonify({"ok": True, "port": port, "enabled": enabled})


@app.route("/api/port/service", methods=["POST"])
def update_service():
    data = _json_body()
    port = str(data.get("port"))
    service = sanitize_banner(data.get("service", ""))
    if not service:
        service = "Generic Server"

    with _config_lock:
        if port not in config["spoofed_ports"]:
            return jsonify({"error": f"Unknown port: {port}"}), 400

        config["spoofed_ports"][port]["service"] = service
        save_config(config)
    return jsonify({"ok": True})


@app.route("/api/port/all", methods=["POST"])
def toggle_all_ports():
    data = _json_body()
    enabled = bool(data.get("enabled", True))

    with _config_lock:
        config["port_spoofing_enabled"] = enabled

        if enabled:
            for port, cfg in config["spoofed_ports"].items():
                if cfg.get("enabled", False):
                    port_responder.start_port(port, cfg["service"])
            msg = "Port spoofing enabled"
        else:
            port_responder.stop_all()
            msg = "Port spoofing disabled"

        save_config(config)
    return jsonify({"ok": True, "message": msg, "enabled": enabled})


@app.route("/api/os/toggle", methods=["POST"])
def toggle_os():
    data = _json_body()
    enabled = bool(data.get("enabled", not config.get("os_spoofing_enabled", False)))

    if enabled:
        success, msg = os_fingerprinter.enable(config.get("os_profile", "windows11"))
    else:
        success, msg = os_fingerprinter.disable()

    with _config_lock:
        config["os_spoofing_enabled"] = success
        save_config(config)
    return jsonify({"ok": success, "message": msg, "enabled": success})


@app.route("/api/os/profile", methods=["POST"])
def set_os_profile():
    data = _json_body()
    profile = data.get("profile")
    if profile not in OS_PROFILES:
        return jsonify({"error": f"Unknown profile: {profile}"}), 400

    msg = f"Profile set to {OS_PROFILES[profile]['name']}"
    success = True
    with _config_lock:
        config["os_profile"] = profile

        # If currently active, re-apply with new profile
        if config.get("os_spoofing_enabled"):
            os_fingerprinter.disable()
            success, msg = os_fingerprinter.enable(profile)
            config["os_spoofing_enabled"] = success

        save_config(config)
    return jsonify({"ok": success, "message": msg, "profile": profile})


# --- Connection Log ---

@app.route("/api/log")
def get_log():
    limit = request.args.get("limit", 50, type=int)
    limit = max(1, min(limit, port_responder.conn_log.MAX_ENTRIES))
    return jsonify({
        "entries": port_responder.conn_log.get_recent(limit),
        "counts": port_responder.conn_log.get_counts(),
        "total": port_responder.conn_log.count()
    })


@app.route("/api/log/clear", methods=["POST"])
def clear_log():
    port_responder.conn_log.clear()
    return jsonify({"ok": True, "message": "Log cleared"})


# --- Custom Port Management ---

@app.route("/api/port/add", methods=["POST"])
def add_port():
    data = _json_body()
    raw_port = str(data.get("port", "")).strip()
    service = sanitize_banner(data.get("service") or "Generic Server")

    if not raw_port.isdigit() or not raw_port.isascii():
        return jsonify({"error": "Invalid port number"}), 400
    port = str(int(raw_port))  # normalize ("0080" → "80")
    if not (1 <= int(port) <= 65535):
        return jsonify({"error": "Invalid port number"}), 400

    with _config_lock:
        if port in config["spoofed_ports"]:
            return jsonify({"error": f"Port {port} already exists"}), 400

        config["spoofed_ports"][port] = {"enabled": True, "service": service}
        bound = True
        if config.get("port_spoofing_enabled"):
            bound = port_responder.start_port(port, service)
        save_config(config)

    if not bound:
        return jsonify({"error": f"Port {port} saved but could not be bound"}), 409
    return jsonify({"ok": True, "port": port, "service": service})


@app.route("/api/port/remove", methods=["POST"])
def remove_port():
    data = _json_body()
    port = str(data.get("port"))

    with _config_lock:
        if port not in config["spoofed_ports"]:
            return jsonify({"error": f"Unknown port: {port}"}), 400

        port_responder.stop_port(port)
        del config["spoofed_ports"][port]
        save_config(config)
    return jsonify({"ok": True, "port": port})


# --- Rate Limiter ---

@app.route("/api/ratelimiter")
def get_ratelimiter():
    return jsonify({
        "blocked_ips": rate_limiter.get_blocked_ips(),
        "tracked_ips": rate_limiter.get_tracked_ips(),
        **rate_limiter.get_config()
    })


@app.route("/api/ratelimiter/config", methods=["POST"])
def set_ratelimiter_config():
    data = _json_body()
    try:
        rate_limiter.set_config(
            threshold=data.get("threshold"),
            window=data.get("window"),
            block_duration=data.get("block_duration")
        )
    except (TypeError, ValueError):
        return jsonify({"error": "Invalid rate limiter configuration"}), 400
    return jsonify({"ok": True, **rate_limiter.get_config()})


@app.route("/api/ratelimiter/unblock", methods=["POST"])
def unblock_ip():
    data = _json_body()
    ip = data.get("ip")
    if not ip or not isinstance(ip, str):
        return jsonify({"error": "Missing ip"}), 400
    rate_limiter.unblock_ip(ip)
    return jsonify({"ok": True, "message": f"Unblocked {ip}"})


@app.route("/api/config")
def get_config_route():
    with _config_lock:
        return jsonify(config)


@app.route("/api/setup", methods=["POST"])
def setup():
    data = _json_body() or {}
    enabled = bool(data.get("enabled", False))
    profile = data.get("profile", config.get("os_profile", "windows11"))
    count = data.get("port_count")

    if profile not in AUTO_PORT_SETS:
        return jsonify({"error": f"Unknown profile: {profile}"}), 400
    try:
        count = int(count) if count is not None else 8
    except (TypeError, ValueError):
        return jsonify({"error": "Invalid port_count"}), 400
    count = max(1, min(count, len(AUTO_PORT_SETS[profile])))

    ports, skipped = apply_setup(enabled, profile, count)
    active = port_responder.get_running_ports()
    return jsonify({
        "ok": True,
        "enabled": enabled,
        "profile": profile,
        "port_count": len(ports),
        "active_ports": sorted(active),
        "skipped_ports": sorted(skipped),
        "os_spoofing": config.get("os_spoofing_enabled", False),
    })


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else int(os.environ.get("SMUDGED_LENS_PORT", "5000"))

    # Bind to localhost by default for security. The API has no user accounts;
    # requests from browsers carry a Host header we validate (anti rebinding),
    # and SMUDGED_LENS_TOKEN adds a shared-secret requirement on top.
    host = os.environ.get("SMUDGED_LENS_HOST", "127.0.0.1")
    install_exit_handlers()
    restore_state(config, auto_port_sets=AUTO_PORT_SETS)
    logger.info(f"🔬 Smudged Lens running on http://{host}:{port}")
    app.run(host=host, port=port, debug=False, threaded=True,
            request_handler=_make_masked_handler())


if __name__ == "__main__":
    main()
