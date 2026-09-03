import copy
import json
import logging
import os
import platform
import shutil

logger = logging.getLogger("smudged_lens")

# Config lives in the user's home, NOT next to the code: a pip-installed
# package can't write into site-packages, and upgrades shouldn't wipe state.
# Override with SMUDGED_LENS_CONFIG_DIR.
CONFIG_DIR = os.environ.get(
    "SMUDGED_LENS_CONFIG_DIR",
    os.path.join(os.path.expanduser("~"), ".config", "smudged-lens"),
)
CONFIG_FILE = os.path.join(CONFIG_DIR, "config.json")


def _migrate_legacy_config():
    """One-time: adopt configs from pre-rebrand locations."""
    if os.path.exists(CONFIG_FILE):
        return
    here = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        os.path.join(here, "config.json"),                   # old: beside the module
        os.path.join(os.path.dirname(here), "config.json"),  # old: flat-layout repo root
        os.path.join(os.path.expanduser("~"), ".config",
                     "blurry-lens", "config.json"),          # old: pre-rebrand name
    ]
    for legacy in candidates:
        try:
            if os.path.isfile(legacy):
                os.makedirs(CONFIG_DIR, exist_ok=True)
                shutil.copy2(legacy, CONFIG_FILE)
                logger.info(f"Migrated legacy config from {legacy} to {CONFIG_FILE}")
                return
        except OSError:
            continue


_migrate_legacy_config()

# --- Platform detection ---
IS_LINUX = platform.system() == "Linux"
IS_MACOS = platform.system() == "Darwin"
HAS_IPTABLES = IS_LINUX and shutil.which("iptables") is not None
HAS_IP6TABLES = IS_LINUX and shutil.which("ip6tables") is not None

def is_root():
    """Check if running with root/admin privileges."""
    if IS_LINUX or platform.system() in ("Darwin", "FreeBSD"):
        return os.geteuid() == 0
    # Windows: assume admin if we can write to a system path
    try:
        with open(os.path.join(os.environ.get("SYSTEMROOT", r"C:\Windows"), "temp", "_smudged_lens_test"), "w") as f:
            f.write("ok")
        os.remove(os.path.join(os.environ.get("SYSTEMROOT", r"C:\Windows"), "temp", "_smudged_lens_test"))
        return True
    except (PermissionError, OSError):
        return False

DEFAULT_CONFIG = {
    "port_spoofing_enabled": False,
    "os_spoofing_enabled": False,
    "os_profile": "windows11",
    "spoofed_ports": {
        "22": {"enabled": True, "service": "OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"},
        "80": {"enabled": True, "service": "Apache/2.4.58 (Ubuntu)"},
        "443": {"enabled": True, "service": "nginx/1.24.0"},
        "3306": {"enabled": True, "service": "MySQL 8.0.35-0ubuntu0.22.04.1"},
        "8080": {"enabled": True, "service": "Apache Tomcat/9.0.82"},
        "8443": {"enabled": False, "service": "Apache/2.4.58 (Ubuntu)"},
        "21": {"enabled": False, "service": "ProFTPD 1.3.6"},
        "25": {"enabled": False, "service": "Postfix smtpd"},
        "53": {"enabled": False, "service": "ISC BIND 9.18.18"},
        "3389": {"enabled": False, "service": "Microsoft Terminal Services"}
    }
}

OS_PROFILES = {
    "windows11": {
        "name": "Windows 11",
        "ttl": 128,
        "tcp_window": 65535,
        "mss": 1460,
        "description": "Windows 11 Pro 22H2"
    },
    "windows10": {
        "name": "Windows 10",
        "ttl": 128,
        "tcp_window": 65535,
        "mss": 1460,
        "description": "Windows 10 Pro 22H2"
    },
    "macos": {
        "name": "macOS Sonoma",
        "ttl": 64,
        "tcp_window": 65535,
        "mss": 1460,
        "description": "macOS 14.1 Sonoma"
    },
    "ubuntu": {
        "name": "Ubuntu Server",
        "ttl": 64,
        "tcp_window": 29200,
        "mss": 1460,
        "description": "Ubuntu 22.04 LTS"
    },
    "centos": {
        "name": "CentOS Stream",
        "ttl": 64,
        "tcp_window": 28960,
        "mss": 1460,
        "description": "CentOS Stream 9"
    }
}


def load_config():
    """Load config.json, merging over defaults.

    Always returns a deep copy — neither DEFAULT_CONFIG nor nested dicts are
    ever shared with callers (a shallow copy here used to let saved values
    permanently pollute the module-level defaults for the process lifetime).
    """
    if not os.path.exists(CONFIG_FILE):
        return copy.deepcopy(DEFAULT_CONFIG)

    try:
        with open(CONFIG_FILE, "r") as f:
            saved = json.load(f)
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        logger.warning(f"config.json is corrupt ({e}); moving it aside and using defaults")
        _quarantine_corrupt_config()
        return copy.deepcopy(DEFAULT_CONFIG)
    except OSError as e:
        logger.warning(f"Could not read config.json ({e}); using defaults")
        return copy.deepcopy(DEFAULT_CONFIG)

    if not isinstance(saved, dict):
        logger.warning("config.json has unexpected structure; using defaults")
        _quarantine_corrupt_config()
        return copy.deepcopy(DEFAULT_CONFIG)

    merged = copy.deepcopy(DEFAULT_CONFIG)
    for key, value in saved.items():
        if key == "spoofed_ports":
            continue
        merged[key] = value

    saved_ports = saved.get("spoofed_ports")
    if isinstance(saved_ports, dict):
        for port, cfg in saved_ports.items():
            if isinstance(cfg, dict):
                if port in merged["spoofed_ports"]:
                    merged["spoofed_ports"][port].update(cfg)
                else:
                    merged["spoofed_ports"][port] = copy.deepcopy(cfg)
    return merged


def _quarantine_corrupt_config():
    """Preserve a corrupt config file for inspection instead of overwriting it."""
    backup = CONFIG_FILE + ".corrupt"
    try:
        os.replace(CONFIG_FILE, backup)
        logger.warning(f"Corrupt config preserved at {backup}")
    except OSError:
        pass


def save_config(config):
    """Persist config atomically: write to a temp file, fsync, then rename.

    A crash mid-write used to leave a truncated config.json behind, which
    bricked every entrypoint on next startup.
    """
    tmp = CONFIG_FILE + ".tmp"
    try:
        os.makedirs(CONFIG_DIR, exist_ok=True)
    except OSError:
        pass
    with open(tmp, "w") as f:
        json.dump(config, f, indent=2)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, CONFIG_FILE)
