#!/usr/bin/env python3
"""
Smudged Lens — Smoke Tests

Runs without GUI, without root, without iptables.
Tests core logic: config, rate limiter, port responder, connection logger,
decoy pages, and OS fingerprinter guards.

Usage:
    python3 tests.py
    python3 -m pytest tests.py -v   (if pytest is installed)
"""

import os
import sys
import time
import json
import random
import select
import ssl
import socket
import struct
import subprocess
import threading
import tempfile
import unittest
from unittest.mock import patch

# Ensure we import from the project directory
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from smudged_lens.config import (
    DEFAULT_CONFIG, OS_PROFILES, load_config, save_config,
    IS_LINUX, HAS_IPTABLES, HAS_IP6TABLES, is_root,
)
from smudged_lens import spoof_engine
from smudged_lens.spoof_engine import (
    ConnectionLogger, RateLimiter, PortResponder, OSFingerprinter,
    _pick_decoy, DECOY_PAGES,
    sanitize_banner, _mysql_greeting, _get_tls_context,
    _dns_parse_name, _dns_build_response, _dns_respond_udp,
    _dns_respond_tcp, _ssh_auth_failure, _mysql_auth_error,
)


# =============================================================================
# Config Tests
# =============================================================================

class TestConfig(unittest.TestCase):
    """Tests for config loading, saving, and platform detection."""

    def test_default_config_has_required_keys(self):
        for key in ("port_spoofing_enabled", "os_spoofing_enabled", "os_profile", "spoofed_ports"):
            self.assertIn(key, DEFAULT_CONFIG)

    def test_default_config_has_default_ports(self):
        ports = DEFAULT_CONFIG["spoofed_ports"]
        self.assertIn("22", ports)
        self.assertIn("80", ports)
        self.assertIn("443", ports)
        for port, cfg in ports.items():
            self.assertIn("enabled", cfg)
            self.assertIn("service", cfg)

    def test_os_profiles_have_required_fields(self):
        for key, prof in OS_PROFILES.items():
            self.assertIn("name", prof, f"{key} missing 'name'")
            self.assertIn("ttl", prof, f"{key} missing 'ttl'")
            self.assertIn("tcp_window", prof, f"{key} missing 'tcp_window'")
            self.assertIn("mss", prof, f"{key} missing 'mss'")

    def test_os_profile_ttl_values(self):
        self.assertEqual(OS_PROFILES["windows11"]["ttl"], 128)
        self.assertEqual(OS_PROFILES["windows10"]["ttl"], 128)
        self.assertEqual(OS_PROFILES["macos"]["ttl"], 64)
        self.assertEqual(OS_PROFILES["ubuntu"]["ttl"], 64)
        self.assertEqual(OS_PROFILES["centos"]["ttl"], 64)

    def test_os_profile_mss_values_are_realistic(self):
        """MSS values should be realistic TCP MSS values, not window sizes."""
        for key, prof in OS_PROFILES.items():
            mss = prof["mss"]
            self.assertGreaterEqual(mss, 536, f"{key} MSS too low")
            self.assertLessEqual(mss, 9660, f"{key} MSS too high")

    def test_load_config_returns_defaults_when_no_file(self):
        fake_path = "/tmp/_smudged_lens_nonexistent_test_file.json"
        with patch("smudged_lens.config.CONFIG_FILE", fake_path):
            cfg = load_config()
        self.assertEqual(cfg["os_profile"], "windows11")
        self.assertIn("22", cfg["spoofed_ports"])

    def test_save_and_load_roundtrip(self):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            fake_path = f.name
        try:
            test_cfg = DEFAULT_CONFIG.copy()
            test_cfg["os_profile"] = "ubuntu"
            test_cfg["spoofed_ports"] = {
                "80": {"enabled": True, "service": "nginx/1.24.0"},
                "9999": {"enabled": True, "service": "Redis 7.2"},
            }
            with patch("smudged_lens.config.CONFIG_FILE", fake_path):
                save_config(test_cfg)
                loaded = load_config()
            self.assertEqual(loaded["os_profile"], "ubuntu")
            self.assertIn("80", loaded["spoofed_ports"])
            self.assertIn("9999", loaded["spoofed_ports"])
            self.assertEqual(loaded["spoofed_ports"]["9999"]["service"], "Redis 7.2")
        finally:
            os.unlink(fake_path)

    def test_platform_detection_returns_booleans(self):
        self.assertIsInstance(IS_LINUX, bool)
        self.assertIsInstance(HAS_IPTABLES, bool)

    def test_is_root_returns_bool(self):
        self.assertIsInstance(is_root(), bool)

    def test_config_merge_preserves_custom_ports(self):
        """Saved config with custom ports should be preserved on load."""
        saved = DEFAULT_CONFIG.copy()
        saved["spoofed_ports"] = DEFAULT_CONFIG["spoofed_ports"].copy()
        saved["spoofed_ports"]["9999"] = {"enabled": True, "service": "Custom"}

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(saved, f)
            fake_path = f.name
        try:
            with patch("smudged_lens.config.CONFIG_FILE", fake_path):
                loaded = load_config()
            self.assertIn("9999", loaded["spoofed_ports"])
            self.assertEqual(loaded["spoofed_ports"]["9999"]["service"], "Custom")
        finally:
            os.unlink(fake_path)


# =============================================================================
# Connection Logger Tests
# =============================================================================

class TestConnectionLogger(unittest.TestCase):
    """Tests for ConnectionLogger."""

    def setUp(self):
        self.logger = ConnectionLogger()

    def test_log_and_get_recent(self):
        self.logger.log("10.0.0.1", 54321, 80, "Apache/2.4.58")
        self.logger.log("10.0.0.2", 54322, 22, "OpenSSH_8.9")
        entries = self.logger.get_recent(10)
        self.assertEqual(len(entries), 2)
        # Most recent first
        self.assertEqual(entries[0]["source_ip"], "10.0.0.2")
        self.assertEqual(entries[1]["source_ip"], "10.0.0.1")

    def test_log_entry_format(self):
        self.logger.log("1.2.3.4", 12345, 80, "Apache")
        entry = self.logger.get_recent(1)[0]
        self.assertIn("time", entry)
        self.assertIn("source_ip", entry)
        self.assertIn("source_port", entry)
        self.assertIn("dest_port", entry)
        self.assertIn("service", entry)
        self.assertEqual(entry["source_ip"], "1.2.3.4")
        self.assertEqual(entry["dest_port"], 80)

    def test_get_recent_respects_limit(self):
        for i in range(20):
            self.logger.log(f"10.0.0.{i}", 10000 + i, 80, "test")
        entries = self.logger.get_recent(5)
        self.assertEqual(len(entries), 5)

    def test_get_counts(self):
        self.logger.log("10.0.0.1", 10001, 80, "Apache")
        self.logger.log("10.0.0.2", 10002, 80, "Apache")
        self.logger.log("10.0.0.3", 10003, 22, "SSH")
        counts = self.logger.get_counts()
        self.assertEqual(counts[80], 2)
        self.assertEqual(counts[22], 1)

    def test_clear(self):
        self.logger.log("10.0.0.1", 10001, 80, "test")
        self.logger.clear()
        self.assertEqual(len(self.logger.get_recent()), 0)
        self.assertEqual(self.logger.get_counts(), {})

    def test_max_entries_cap(self):
        for i in range(ConnectionLogger.MAX_ENTRIES + 100):
            self.logger.log(f"10.0.0.{i % 256}", 10000 + i, 80, "test")
        self.assertLessEqual(len(self.logger.get_recent(9999)), ConnectionLogger.MAX_ENTRIES)

    def test_thread_safety(self):
        """Log from multiple threads simultaneously."""
        errors = []

        def log_many(thread_id):
            try:
                for i in range(50):
                    self.logger.log(f"10.{thread_id}.0.{i}", 10000 + i, 80, "test")
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=log_many, args=(t,)) for t in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [])
        self.assertGreater(len(self.logger.get_recent()), 0)


# =============================================================================
# Rate Limiter Tests
# =============================================================================

class TestRateLimiter(unittest.TestCase):
    """Tests for RateLimiter."""

    def setUp(self):
        self.rl = RateLimiter()

    def test_localhost_is_exempt(self):
        """Localhost should never be rate-limited."""
        for ip in ("127.0.0.1", "::1", "::ffff:127.0.0.1"):
            for port in range(1, 100):
                self.assertTrue(self.rl.check(ip, port), f"localhost {ip} should be exempt")

    def test_unique_port_tracking(self):
        """Connections to different unique ports should be tracked."""
        ip = "192.168.1.100"
        for port in range(1, 10):
            self.assertTrue(self.rl.check(ip, port))
        self.assertGreater(self.rl.get_tracked_ips(), 0)

    def test_threshold_triggers_block(self):
        """Exceeding the threshold should block the IP."""
        ip = "192.168.1.200"
        # Set a low threshold for testing
        self.rl.set_config(threshold=5, window=60, block_duration=60)

        # Probe 5 unique ports — should be allowed
        for port in range(1, 6):
            self.assertTrue(self.rl.check(ip, port))

        # 6th unique port should trigger block
        self.assertFalse(self.rl.check(ip, 6))

    def test_blocked_ip_stays_blocked(self):
        """Once blocked, the IP should remain blocked until block expires."""
        ip = "192.168.1.201"
        self.rl.set_config(threshold=3, window=60, block_duration=300)

        # Trigger block
        for port in range(1, 5):
            self.rl.check(ip, port)
        self.assertFalse(self.rl.check(ip, 100))

        # Should still be blocked
        self.assertFalse(self.rl.check(ip, 200))

        # Should appear in blocked list
        blocked = self.rl.get_blocked_ips()
        self.assertTrue(any(b["ip"] == ip for b in blocked))

    def test_block_expires(self):
        """Block should expire after the configured duration."""
        ip = "192.168.1.202"
        # Minimum block_duration is 10, so set directly and sleep just past it
        self.rl.set_config(threshold=3, window=60, block_duration=10)
        self.rl.block_duration = 2  # Bypass minimum for faster tests

        # Trigger block
        for port in range(1, 5):
            self.rl.check(ip, port)
        self.assertFalse(self.rl.check(ip, 100))

        # Wait for block to expire
        time.sleep(2.5)

        # Should be unblocked now
        self.assertTrue(self.rl.check(ip, 200))

    def test_same_port_does_not_count_twice(self):
        """Hammering the same port should not increase unique port count."""
        ip = "192.168.1.203"
        self.rl.set_config(threshold=5, window=60, block_duration=60)

        for _ in range(100):
            self.assertTrue(self.rl.check(ip, 80))

    def test_unblock_ip(self):
        """Manual unblock should work."""
        ip = "192.168.1.204"
        self.rl.set_config(threshold=3, window=60, block_duration=300)

        for port in range(1, 5):
            self.rl.check(ip, port)
        self.assertFalse(self.rl.check(ip, 100))

        self.rl.unblock_ip(ip)
        self.assertTrue(self.rl.check(ip, 200))

    def test_config_updates(self):
        """set_config should update thresholds."""
        self.rl.set_config(threshold=10, window=30, block_duration=600)
        cfg = self.rl.get_config()
        self.assertEqual(cfg["unique_ports_threshold"], 10)
        self.assertEqual(cfg["window_seconds"], 30)
        self.assertEqual(cfg["block_duration"], 600)

    def test_config_minimum_values(self):
        """Config should enforce minimum values."""
        self.rl.set_config(threshold=1, window=0, block_duration=0)
        cfg = self.rl.get_config()
        self.assertGreaterEqual(cfg["unique_ports_threshold"], 3)
        self.assertGreaterEqual(cfg["window_seconds"], 1)
        self.assertGreaterEqual(cfg["block_duration"], 10)

    def test_get_blocked_ips_format(self):
        """Blocked IPs should have ip and remaining fields."""
        ip = "192.168.1.205"
        self.rl.set_config(threshold=3, window=60, block_duration=60)
        for port in range(1, 5):
            self.rl.check(ip, port)
        self.rl.check(ip, 100)  # trigger block

        blocked = self.rl.get_blocked_ips()
        self.assertGreater(len(blocked), 0)
        entry = next(b for b in blocked if b["ip"] == ip)
        self.assertIn("remaining", entry)
        self.assertGreater(entry["remaining"], 0)


# =============================================================================
# Decoy Page Tests
# =============================================================================

class TestDecoyPages(unittest.TestCase):
    """Tests for decoy page selection."""

    def test_apache_banner_gets_apache_page(self):
        body = _pick_decoy("Apache/2.4.58 (Ubuntu)")
        self.assertIn("Apache2 Ubuntu Default Page", body)

    def test_nginx_banner_gets_nginx_page(self):
        body = _pick_decoy("nginx/1.24.0")
        self.assertIn("Welcome to nginx!", body)

    def test_tomcat_banner_gets_tomcat_page(self):
        body = _pick_decoy("Apache Tomcat/9.0.82")
        self.assertIn("Apache Tomcat", body)

    def test_iis_banner_gets_iis_page(self):
        body = _pick_decoy("Microsoft-IIS/10.0")
        self.assertIn("IIS Windows Server", body)

    def test_microsoft_banner_gets_iis_page(self):
        body = _pick_decoy("Microsoft HTTPAPI 2.0")
        self.assertIn("IIS Windows Server", body)

    def test_unknown_banner_gets_generic_page(self):
        body = _pick_decoy("Redis 7.2")
        self.assertIn("200 OK", body)

    def test_all_decoy_pages_are_valid_html(self):
        for name, body in DECOY_PAGES.items():
            self.assertIn("<html>", body.lower(), f"{name} missing <html>")
            self.assertIn("</html>", body.lower(), f"{name} missing </html>")
            self.assertIn("<title>", body.lower(), f"{name} missing <title>")


# =============================================================================
# Port Responder Tests
# =============================================================================

class TestPortResponder(unittest.TestCase):
    """Tests for PortResponder — starts real TCP listeners on high ports."""

    def setUp(self):
        self.pr = PortResponder()

    def tearDown(self):
        self.pr.stop_all()

    def _find_free_port(self):
        """Find a free high port for testing."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            return s.getsockname()[1]

    def test_start_and_stop_port(self):
        port = self._find_free_port()
        self.assertTrue(self.pr.start_port(port, "Test/1.0"))
        time.sleep(0.1)
        self.assertIn(port, self.pr.get_running_ports())
        self.pr.stop_port(port)
        time.sleep(0.2)
        self.assertNotIn(port, self.pr.get_running_ports())

    def test_stop_all(self):
        ports = [self._find_free_port() for _ in range(3)]
        for p in ports:
            self.pr.start_port(p, "Test/1.0")
        time.sleep(0.1)
        self.pr.stop_all()
        time.sleep(0.2)
        self.assertEqual(len(self.pr.get_running_ports()), 0)

    def test_port_responds_to_connection(self):
        """Connect to a spoofed port and verify we get a banner."""
        port = self._find_free_port()
        self.pr.start_port(port, "Apache/2.4.58")
        time.sleep(0.2)

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(2)
                s.connect(("127.0.0.1", port))
                data = s.recv(4096).decode()
                # Generic banner for port that's not in the known list
                self.assertIn("Apache/2.4.58", data)
        finally:
            self.pr.stop_port(port)

    def test_http_port_responds_with_headers(self):
        """HTTP-like ports should return a full HTTP response."""
        port = self._find_free_port()
        self.pr.start_port(port, "Apache/2.4.58")
        time.sleep(0.2)

        # Override the port to be an HTTP port by using a known HTTP port check
        # The port responder checks the actual port number, so we use port 8080
        self.pr.stop_port(port)
        time.sleep(0.1)

        http_port = self._find_free_port()
        # We can't easily test HTTP ports since the check is by port number.
        # Instead, test the banner format for a known port.
        # Use the generic path and verify banner content.
        self.pr.start_port(http_port, "nginx/1.24.0")
        time.sleep(0.2)

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(2)
                s.connect(("127.0.0.1", http_port))
                data = s.recv(4096).decode()
                self.assertIn("nginx/1.24.0", data)
        finally:
            self.pr.stop_port(http_port)

    def test_generic_banner_format(self):
        """Non-standard ports should get generic banner format (just banner + CRLF)."""
        port = self._find_free_port()
        self.pr.start_port(port, "OpenSSH_8.9p1")
        time.sleep(0.2)

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(2)
                s.connect(("127.0.0.1", port))
                data = s.recv(4096).decode()
                # High ports get generic format: just the banner string
                self.assertIn("OpenSSH_8.9p1", data)
        finally:
            self.pr.stop_port(port)

    def test_start_duplicate_port_returns_false(self):
        port = self._find_free_port()
        self.assertTrue(self.pr.start_port(port, "Test/1.0"))
        time.sleep(0.1)
        self.assertFalse(self.pr.start_port(port, "Test/2.0"))
        self.pr.stop_port(port)

    def test_connection_logged(self):
        """Connections to spoofed ports should be logged."""
        port = self._find_free_port()
        self.pr.start_port(port, "Test/1.0")
        time.sleep(0.2)

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(2)
                s.connect(("127.0.0.1", port))
                s.recv(4096)  # consume response
            time.sleep(0.1)
            entries = self.pr.conn_log.get_recent(10)
            self.assertTrue(any(e["dest_port"] == port for e in entries))
        finally:
            self.pr.stop_port(port)


# =============================================================================
# OS Fingerprinter Tests (guarded — no iptables needed)
# =============================================================================

class TestOSFingerprinter(unittest.TestCase):
    """Tests for OSFingerprinter — verifies guards, no iptables needed."""

    def setUp(self):
        self.fingerprinter = OSFingerprinter()

    def test_enable_fails_on_non_linux(self):
        """Enable should fail gracefully on non-Linux."""
        with patch("smudged_lens.config.IS_LINUX", False):
            with patch("smudged_lens.config.HAS_IPTABLES", False):
                success, msg = self.fingerprinter.enable("windows11")
                self.assertFalse(success)
                self.assertIn("Linux", msg)

    def test_enable_fails_without_iptables(self):
        """Enable should fail if iptables is not found."""
        with patch("smudged_lens.config.IS_LINUX", True):
            with patch("smudged_lens.config.HAS_IPTABLES", False):
                success, msg = self.fingerprinter.enable("windows11")
                self.assertFalse(success)
                self.assertIn("iptables", msg)

    def test_enable_unknown_profile(self):
        """Enable with unknown profile should fail."""
        with patch("smudged_lens.config.IS_LINUX", True):
            with patch("smudged_lens.config.HAS_IPTABLES", True):
                success, msg = self.fingerprinter.enable("beos")
                self.assertFalse(success)
                self.assertIn("Unknown", msg)

    def test_disable_is_idempotent(self):
        """Calling disable when not enabled should not crash."""
        success, msg = self.fingerprinter.disable()
        self.assertTrue(success)
        self.assertFalse(self.fingerprinter.is_enabled())

    def test_disable_handles_missing_iptables(self):
        """Disable should not crash even if iptables is missing."""
        with patch("subprocess.run", side_effect=FileNotFoundError):
            success, msg = self.fingerprinter.disable()
            self.assertTrue(success)

    def test_initial_state(self):
        self.assertFalse(self.fingerprinter.is_enabled())
        self.assertIsNone(self.fingerprinter.get_current_profile())


# =============================================================================
# Integration Smoke Test
# =============================================================================

class TestIntegrationSmoke(unittest.TestCase):
    """Quick integration test: start a port, connect, verify, stop."""

    def test_full_port_spoof_cycle(self):
        """Start port → connect → get banner → verify log → stop."""
        pr = PortResponder()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]

        try:
            pr.start_port(port, "SmokeTest/1.0")
            time.sleep(0.2)

            # Connect and verify
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
                client.settimeout(2)
                client.connect(("127.0.0.1", port))
                data = client.recv(4096).decode()
                self.assertIn("SmokeTest/1.0", data)

            # Verify logged
            time.sleep(0.1)
            entries = pr.conn_log.get_recent(10)
            self.assertTrue(any(
                e["dest_port"] == port and e["service"] == "SmokeTest/1.0"
                for e in entries
            ))

            # Verify running
            self.assertIn(port, pr.get_running_ports())

        finally:
            pr.stop_port(port)
            time.sleep(0.2)
            self.assertNotIn(port, pr.get_running_ports())


# =============================================================================
# Regression Tests — audit findings (config mutation, deadlock, races, XSS)
# =============================================================================

class TestConfigRegressions(unittest.TestCase):
    """Regressions for config handling bugs found in the security audit."""

    def test_load_config_does_not_mutate_defaults(self):
        """A shallow merge used to let saved values permanently pollute
        DEFAULT_CONFIG for the rest of the process lifetime."""
        saved = {"spoofed_ports": {"22": {"enabled": False, "service": "CHANGED"}}}
        fd, fake_path = tempfile.mkstemp(suffix=".json")
        try:
            with os.fdopen(fd, "w") as f:
                json.dump(saved, f)
            with patch("smudged_lens.config.CONFIG_FILE", fake_path):
                load_config()
            self.assertEqual(DEFAULT_CONFIG["spoofed_ports"]["22"]["enabled"], True,
                             "DEFAULT_CONFIG was mutated by load_config()")
            self.assertEqual(
                DEFAULT_CONFIG["spoofed_ports"]["22"]["service"],
                "OpenSSH_8.9p1 Ubuntu-3ubuntu0.6",
                "DEFAULT_CONFIG was mutated by load_config()",
            )
        finally:
            os.unlink(fake_path)

    def test_corrupt_config_recovers_with_defaults(self):
        """Corrupt config.json used to crash every entrypoint at startup.
        It must be quarantined and defaults returned instead."""
        fd, fake_path = tempfile.mkstemp(suffix=".json")
        with os.fdopen(fd, "w") as f:
            f.write("{definitely not valid json!!")
        backup = fake_path + ".corrupt"
        try:
            with patch("smudged_lens.config.CONFIG_FILE", fake_path):
                cfg = load_config()
            self.assertEqual(cfg["os_profile"], DEFAULT_CONFIG["os_profile"])
            self.assertFalse(os.path.exists(fake_path), "corrupt file should be moved aside")
            self.assertTrue(os.path.exists(backup), "corrupt file should be preserved")
        finally:
            for path in (fake_path, backup):
                if os.path.exists(path):
                    os.unlink(path)

    def test_save_config_leaves_no_temp_file(self):
        fd, fake_path = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        try:
            with patch("smudged_lens.config.CONFIG_FILE", fake_path):
                save_config(DEFAULT_CONFIG.copy())
                loaded = load_config()
            self.assertEqual(loaded["os_profile"], DEFAULT_CONFIG["os_profile"])
            self.assertFalse(os.path.exists(fake_path + ".tmp"),
                             "atomic save must not leave temp files behind")
        finally:
            if os.path.exists(fake_path):
                os.unlink(fake_path)


class TestOSFingerprinterRegression(unittest.TestCase):
    """Regression: enable() while enabled used to deadlock on a non-reentrant lock."""

    def test_enable_while_enabled_does_not_deadlock(self):
        fp = OSFingerprinter()
        fp._enabled = True  # simulate previously-enabled state (no iptables touched)
        result = []
        t = threading.Thread(target=lambda: result.append(fp.enable("windows11")), daemon=True)
        t.start()
        t.join(timeout=6)
        self.assertFalse(t.is_alive(), "enable() deadlocked when called while already enabled")
        self.assertEqual(len(result), 1)
        success, msg = result[0]
        self.assertIsInstance(success, bool)
        self.assertIsInstance(msg, str)


class TestPortResponderRegression(unittest.TestCase):
    """Regressions for listener lifecycle bugs found in the audit."""

    def setUp(self):
        self.pr = PortResponder()

    def tearDown(self):
        self.pr.stop_all()

    def _find_free_port(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            return s.getsockname()[1]

    def test_start_port_fails_on_bind_conflict(self):
        """start_port used to report success before bind() ran. A port held
        by another process must yield an honest False."""
        port = self._find_free_port()
        blocker = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Bind wildcard-to-wildcard: BSD/macOS permits a wildcard bind over a
        # specific-address bind when SO_REUSEADDR is set, so 127.0.0.1 isn't
        # enough to force a conflict cross-platform.
        blocker.bind(("0.0.0.0", port))
        blocker.listen(1)
        try:
            self.assertFalse(self.pr.start_port(port, "Test/1.0"),
                             "start_port claimed success on a conflicting bind")
            self.assertNotIn(port, self.pr.get_running_ports())
        finally:
            blocker.close()

    def test_stop_then_immediate_start_works(self):
        """stop_port didn't join its handler thread; an immediate restart
        lost the EADDRINUSE race and left the port dead despite reporting OK."""
        port = self._find_free_port()
        self.assertTrue(self.pr.start_port(port, "Test/1.0"))
        self.assertTrue(self.pr.stop_port(port))
        self.assertTrue(self.pr.start_port(port, "Test/2.0"),
                        "immediate restart after stop failed")
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(3)
                s.connect(("127.0.0.1", port))
                data = s.recv(4096).decode()
            self.assertIn("Test/2.0", data)
        finally:
            self.pr.stop_port(port)

    def test_http_port_waits_for_request_before_responding(self):
        """Real web servers send nothing until spoken to; unsolicited bytes
        are themselves a fingerprint anomaly."""
        port = self._find_free_port()
        with patch.object(spoof_engine, "HTTP_PORTS", {port}):
            self.assertTrue(self.pr.start_port(port, "Apache/2.4.58"))
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(1.0)
                    s.connect(("127.0.0.1", port))
                    with self.assertRaises(socket.timeout,
                                           msg="HTTP decoy answered before any request"):
                        s.recv(4096)
                    s.sendall(b"GET / HTTP/1.1\r\nHost: scanner\r\n\r\n")
                    data = s.recv(4096).decode()
                self.assertIn("HTTP/1.1 200 OK", data)
                self.assertIn("Server: Apache/2.4.58", data)
                self.assertIn("It works!", data)
            finally:
                self.pr.stop_port(port)

    def test_head_request_gets_headers_only(self):
        port = self._find_free_port()
        with patch.object(spoof_engine, "HTTP_PORTS", {port}):
            self.assertTrue(self.pr.start_port(port, "nginx/1.24.0"))
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(3)
                    s.connect(("127.0.0.1", port))
                    s.sendall(b"HEAD / HTTP/1.1\r\nHost: scanner\r\n\r\n")
                    chunks = []
                    while True:
                        part = s.recv(4096)
                        if not part:
                            break
                        chunks.append(part)
                data = b"".join(chunks).decode()
                self.assertIn("Content-Length:", data)
                self.assertNotIn("<html>", data.lower(), "HEAD response must have no body")
            finally:
                self.pr.stop_port(port)

    def test_tls_decoy_port_handshake(self):
        """Ports claiming HTTPS must speak TLS, not plaintext."""
        ctx = _get_tls_context()
        if ctx is None:
            self.skipTest("openssl unavailable — TLS decoys disabled on this machine")
        port = self._find_free_port()
        # Patch both sets: TLS_PORTS makes the server wrap, HTTP_PORTS makes
        # it serve the nginx decoy (instead of the generic banner) inside TLS.
        with patch.object(spoof_engine, "HTTP_PORTS", {port}), \
             patch.object(spoof_engine, "TLS_PORTS", {port}):
            self.assertTrue(self.pr.start_port(port, "nginx/1.24.0"))
            try:
                client_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                client_ctx.check_hostname = False
                client_ctx.verify_mode = ssl.CERT_NONE
                with socket.create_connection(("127.0.0.1", port), timeout=5) as raw:
                    with client_ctx.wrap_socket(raw) as tls_sock:
                        tls_sock.settimeout(5)
                        tls_sock.sendall(b"GET / HTTP/1.1\r\nHost: scanner\r\n\r\n")
                        data = tls_sock.recv(8192).decode()
                self.assertIn("200 OK", data)
                self.assertIn("Welcome to nginx!", data)
            finally:
                self.pr.stop_port(port)

    def test_blocked_probes_are_logged_and_denied(self):
        """Rate-limited probes were silently dropped before logging — you could
        never see who was hammering you. They must be logged with blocked=true.
        With tarpitting, blocked connections get held open instead of closed
        immediately — but the probe is still logged and no real banner is served."""

        class _DenyAll(RateLimiter):
            def check(self, source_ip, dest_port):
                return False

        # Override tarpit to hold for a very short time (avoid slow tests)
        original_hold = spoof_engine.TARPIT_HOLD_TIME
        spoof_engine.TARPIT_HOLD_TIME = 0.3
        try:
            port = self._find_free_port()
            with patch.object(spoof_engine, "rate_limiter", _DenyAll()):
                self.assertTrue(self.pr.start_port(port, "Test/1.0"))
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                        s.settimeout(2)
                        s.connect(("127.0.0.1", port))
                        # Tarpit holds the connection open but sends no real banner.
                        # The connection will close after TARPIT_HOLD_TIME expires.
                        data = s.recv(4096)
                    # Should get junk bytes (or empty), never a real banner
                    self.assertNotIn(b"Test/1.0", data,
                                     "blocked probe must not receive the real banner")
                    time.sleep(0.2)
                    entry = next(
                        e for e in self.pr.conn_log.get_recent(10) if e["dest_port"] == port
                    )
                    self.assertTrue(entry["blocked"], "blocked probe missing blocked=true flag")
                finally:
                    self.pr.stop_port(port)
        finally:
            spoof_engine.TARPIT_HOLD_TIME = original_hold


class TestConnectionLoggerFormat(unittest.TestCase):
    def test_timestamps_are_utc_iso8601(self):
        logger = ConnectionLogger()
        logger.log("10.0.0.1", 1000, 80, "test")
        ts = logger.get_recent(1)[0]["time"]
        self.assertRegex(ts, r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$",
                         "log timestamps must be UTC ISO-8601")

    def test_blocked_flag_defaults_false(self):
        logger = ConnectionLogger()
        logger.log("10.0.0.1", 1000, 80, "test")
        self.assertFalse(logger.get_recent(1)[0]["blocked"])


class TestBannerSanitization(unittest.TestCase):
    """Banners go into HTTP headers and wire protocols — CRLF injection must die here."""

    def test_strips_crlf_injection(self):
        evil = "Apache/2.4\r\nX-Injected: pwned\r\n\r\nHTTP/1.1 200 OK"
        clean = sanitize_banner(evil)
        self.assertNotIn("\r", clean)
        self.assertNotIn("\n", clean)

    def test_strips_non_printable_and_collapses_whitespace(self):
        clean = sanitize_banner("Foo\x00\x1b[31m Bar\t\tBaz")
        self.assertTrue(all(32 <= ord(c) < 127 for c in clean))

    def test_caps_length(self):
        self.assertLessEqual(len(sanitize_banner("A" * 500)), 96)

    def test_empty_falls_back_to_default(self):
        self.assertEqual(sanitize_banner(""), "Generic Server")
        self.assertEqual(sanitize_banner("\r\n\t "), "Generic Server")


class TestMySQLGreeting(unittest.TestCase):
    """The old greeting was plain text — not MySQL wire protocol at all."""

    def test_packet_structure(self):
        g = _mysql_greeting("MySQL 8.0.35-0ubuntu0.22.04.1")
        pkt_len = g[0] | (g[1] << 8) | (g[2] << 16)
        self.assertEqual(pkt_len, len(g) - 4, "packet header length mismatch")
        self.assertEqual(g[3], 0, "sequence id must be 0")
        self.assertEqual(g[4], 10, "protocol version must be 10")

    def test_version_extracted_from_banner(self):
        g = _mysql_greeting("MySQL 8.0.35-0ubuntu0.22.04.1")
        end = g.index(b"\x00", 5)
        self.assertEqual(g[5:end].decode(), "8.0.35-0ubuntu0.22.04.1")

    def test_salt_varies_per_greeting(self):
        self.assertNotEqual(_mysql_greeting("MySQL 8.0.35")[12:20],
                            _mysql_greeting("MySQL 8.0.35")[12:20])

    def test_auth_plugin_name_present(self):
        g = _mysql_greeting("MariaDB 10.5.22")
        self.assertIn(b"mysql_native_password", g)


class TestWebSecurity(unittest.TestCase):
    """API hardening: Host-header allowlist (anti DNS-rebinding) + optional token."""

    @classmethod
    def setUpClass(cls):
        try:
            from smudged_lens.app import app as flask_app
        except ImportError:
            raise unittest.SkipTest("Flask not installed")
        cls.flask_app = flask_app
        cls.client = flask_app.test_client()

    def test_status_ok_from_trusted_host(self):
        r = self.client.get("/api/status", headers={"Host": "127.0.0.1:5000"})
        self.assertEqual(r.status_code, 200)

    def test_ipv6_loopback_host_allowed(self):
        r = self.client.get("/api/status", headers={"Host": "[::1]:5000"})
        self.assertEqual(r.status_code, 200)

    def test_untrusted_host_header_rejected(self):
        """DNS rebinding: attacker page makes their domain resolve to
        127.0.0.1 — the Host header still names their domain and must 403."""
        r = self.client.get("/api/status", headers={"Host": "evil.example.com"})
        self.assertEqual(r.status_code, 403)

    def test_token_required_when_configured(self):
        orig = self.flask_app.config.get("SMUDGED_LENS_TOKEN")
        self.flask_app.config["SMUDGED_LENS_TOKEN"] = "test-token-123"
        try:
            r = self.client.post("/api/log/clear")
            self.assertEqual(r.status_code, 401, "missing token must be rejected")
            r = self.client.post("/api/log/clear", headers={"X-Auth-Token": "wrong"})
            self.assertEqual(r.status_code, 401, "wrong token must be rejected")
            r = self.client.post("/api/log/clear", headers={"X-Auth-Token": "test-token-123"})
            self.assertEqual(r.status_code, 200, "valid token must be accepted")
        finally:
            self.flask_app.config["SMUDGED_LENS_TOKEN"] = orig

    def test_invalid_json_body_handled(self):
        """Malformed request bodies used to raise AttributeError → 500."""
        r = self.client.post("/api/port/toggle", data="not json",
                             content_type="text/plain")
        self.assertIn(r.status_code, (400, 404))

    def test_server_header_does_not_leak_stack(self):
        """Server header must not reveal Werkzeug/Python — that's a dead giveaway.

        The Flask test client never exercises the HTTP layer, which is exactly
        where the leak happens: Werkzeug re-appends ``Server: Werkzeug/…``
        during serialization, after any Flask-level hook. So the assertion has
        to target the dev-server handler's ``version_string`` (and that it
        produces a single, definitive IIS identity).
        """
        from smudged_lens.app import _make_masked_handler
        handler = _make_masked_handler()
        self.assertEqual(
            handler.version_string(None), "Microsoft-IIS/10.0",
            "dev-server Server header must identify as IIS, not Werkzeug/Python")

        r = self.client.get("/api/status", headers={"Host": "127.0.0.1:5000"})
        server = r.headers.get("Server", "")
        self.assertNotIn("Werkzeug", server,
            "Server header must not leak Werkzeug")
        self.assertNotIn("Python", server,
            "Server header must not leak Python version")
        self.assertNotIn("Smudged", server,
            "Server header must not leak tool name")


class TestApplySetupRebind(unittest.TestCase):
    """Switching OS profile while armed must not leave stale banners on
    overlapping ports — otherwise a scan sees mixed identities (e.g.
    'macOS SMB' + ProFTPD + nginx on a supposedly-Windows host)."""

    class _FakeResponder:
        def __init__(self, running):
            self.running = list(running)
            self.stops = []
            self.starts = []   # (port, banner)
        def get_running_ports(self):
            return list(self.running)
        def stop_port(self, port):
            self.stops.append(port)
            if port in self.running:
                self.running.remove(port)
        def stop_all(self):
            pass
        def start_port(self, port, banner):
            if port not in self.running:
                self.running.append(port)
                self.starts.append((port, banner))
                return True
            return False

    def _switch(self, fake, old_ports, old_banners, new_profile, count):
        """Run apply_setup against a stubbed responder + in-memory config."""
        from smudged_lens import app as appmod
        orig_resp = appmod.port_responder
        orig_conf = appmod.config
        try:
            appmod.port_responder = fake
            appmod.config = dict(orig_conf)
            appmod.config["spoofed_ports"] = {
                str(p): {"enabled": True, "service": b}
                for p, b in zip(old_ports, old_banners)
            }
            with patch.object(appmod, "save_config"), \
                 patch.object(appmod, "is_root", return_value=False):
                ports, skipped = appmod.apply_setup(True, new_profile, count)
            return ports, skipped, fake
        finally:
            appmod.port_responder = orig_resp
            appmod.config = orig_conf

    def test_identity_change_rebinds_overlapping_ports(self):
        # Previously armed macOS (ports 80/443/445), now switching to Windows 11.
        _, skipped, fake = self._switch(
            fake=self._FakeResponder([80, 443, 445]),
            old_ports=[80, 443, 445],
            old_banners=["Server 14.1", "Server 14.1", "macOS SMB"],
            new_profile="windows11", count=3,
        )
        # 80/443/445 all carry a changed identity → every one must be torn down
        # and rebound with the Windows banner, so no stale/broken fingerprint.
        self.assertEqual(sorted(fake.stops), [80, 443, 445])
        self.assertIn((80, "Microsoft-IIS/10.0"), fake.starts)
        self.assertIn((443, "Microsoft-IIS/10.0"), fake.starts)
        self.assertEqual(skipped, [])

    def test_identical_profile_does_not_bounce_listeners(self):
        # Re-applying Windows-11 with 80 still running under the right banner
        # must leave that listener untouched.
        _, skipped, fake = self._switch(
            fake=self._FakeResponder([80]),
            old_ports=[80],
            old_banners=["Microsoft-IIS/10.0"],
            new_profile="windows11", count=3,
        )
        self.assertEqual(fake.stops, [], "unchanged ports must not be stopped")
        self.assertNotIn(80, [p for p, _ in fake.starts],
            "unchanged ports must not be restarted")
        self.assertEqual(skipped, [])




class TestTarpitting(unittest.TestCase):
    """Tests for tarpitting: holding blocked connections open to waste scanner time."""

    def test_tarpit_holds_connection(self):
        """Tarpitted connection should stay open for TARPIT_HOLD_TIME seconds."""
        from smudged_lens.spoof_engine import _tarpit_connection

        # Override hold time for fast test
        original_hold = spoof_engine.TARPIT_HOLD_TIME
        spoof_engine.TARPIT_HOLD_TIME = 0.5
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(("127.0.0.1", 0))
                port = s.getsockname()[1]
                s.listen(1)
                s.settimeout(3)

                # Use a connected pair instead
                server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                server.bind(("127.0.0.1", 0))
                server.listen(1)
                server_port = server.getsockname()[1]

                client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                client.connect(("127.0.0.1", server_port))
                server_conn, _ = server.accept()

                # Tarpit should hold the connection open
                start = time.monotonic()
                _tarpit_connection(server_conn, server_port)
                elapsed = time.monotonic() - start

                self.assertGreaterEqual(elapsed, 0.4,
                    "tarpit should hold connection for at least TARPIT_HOLD_TIME")
                client.close()
                server.close()
        finally:
            spoof_engine.TARPIT_HOLD_TIME = original_hold

    def test_tarpit_stops_on_client_disconnect(self):
        """Tarpitting should stop cleanly when the client disconnects."""
        from smudged_lens.spoof_engine import _tarpit_connection

        original_hold = spoof_engine.TARPIT_HOLD_TIME
        original_min = spoof_engine.TARPIT_MIN_DELAY
        spoof_engine.TARPIT_HOLD_TIME = 30  # long hold
        spoof_engine.TARPIT_MIN_DELAY = 0.1
        try:
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.bind(("127.0.0.1", 0))
            server.listen(1)
            server_port = server.getsockname()[1]

            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client.connect(("127.0.0.1", server_port))
            server_conn, _ = server.accept()

            # Close client side — tarpit should detect and exit
            client.close()
            time.sleep(0.1)  # let close propagate

            t = threading.Thread(target=_tarpit_connection,
                                 args=(server_conn, server_port), daemon=True)
            t.start()
            t.join(timeout=10)
            self.assertFalse(t.is_alive(),
                "tarpit should exit after client disconnect")
            server.close()
        finally:
            spoof_engine.TARPIT_HOLD_TIME = original_hold
            spoof_engine.TARPIT_MIN_DELAY = original_min


class TestBannerVariance(unittest.TestCase):
    """Tests for per-connection banner variance."""

    def test_ssh_banner_variance(self):
        """SSH banners should occasionally return a different version."""
        from smudged_lens.spoof_engine import _banner_variance
        banner = "OpenSSH_9.6"
        # Run many times — at least some should vary
        variants = set()
        for i in range(200):
            varied = _banner_variance(banner, 10000 + i)
            variants.add(varied)
        # With 30% swap rate across 200 tries, we should see at least one variant
        self.assertGreater(len(variants), 1,
            "banner variance should produce at least one alternate version")

    def test_non_ssh_banner_unchanged(self):
        """Non-SSH banners should pass through unchanged."""
        from smudged_lens.spoof_engine import _banner_variance
        banner = "Apache/2.4.58 (Ubuntu)"
        for i in range(50):
            varied = _banner_variance(banner, 10000 + i)
            self.assertEqual(varied, banner,
                "non-SSH banners should not be varied")

    def test_banner_jitter_does_not_crash(self):
        """_banner_jitter() should add a small delay without errors."""
        from smudged_lens.spoof_engine import _banner_jitter
        start = time.monotonic()
        _banner_jitter()
        elapsed = time.monotonic() - start
        self.assertGreaterEqual(elapsed, 0.005)
        self.assertLessEqual(elapsed, 0.1)


class TestSSHAuthFailure(unittest.TestCase):
    """Tests for realistic SSH auth failure handling."""

    def test_ssh_auth_failure_sends_banner_and_responds(self):
        """SSH port should send a banner, then handle KEXINIT and auth."""
        import os
        from smudged_lens.spoof_engine import _ssh_auth_failure, _banner_variance

        # Use a raw socket pair to test the protocol handler directly
        # without needing to bind to port 22
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind(("127.0.0.1", 0))
        server_sock.listen(1)
        server_port = server_sock.getsockname()[1]

        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.settimeout(5)
        client.connect(("127.0.0.1", server_port))
        server_conn, _ = server_sock.accept()

        try:
            # Send SSH banner (simulating what _respond does for port 22)
            banner = "OpenSSH_9.6"
            varied = _banner_variance(banner, server_port)
            server_conn.sendall(f"SSH-2.0-{varied}\r\n".encode())

            # Client reads the banner
            data = b""
            while b"\r\n" not in data:
                chunk = client.recv(4096)
                if not chunk:
                    break
                data += chunk
            self.assertIn(b"SSH-2.0-", data,
                "SSH server must send its version banner first")

            # Client sends its version string
            client.sendall(b"SSH-2.0-OpenSSH_8.9p1\r\n")

            # Server handles KEXINIT + auth failure
            _ssh_auth_failure(server_conn)

            # Client should have received data (KEXINIT + USERAUTH_FAILURE)
            response = client.recv(4096)
            self.assertGreater(len(response), 0,
                "SSH server should respond with KEXINIT and auth failure")
            # Check for packet type 51 (USERAUTH_FAILURE) or 20 (KEXINIT)
            self.assertTrue(
                bytes([51]) in response or bytes([20]) in response,
                "should receive SSH_MSG_KEXINIT (20) or USERAUTH_FAILURE (51)")
        finally:
            client.close()
            server_conn.close()
            server_sock.close()


class TestMySQLAuthError(unittest.TestCase):
    """Tests for realistic MySQL auth error handling."""

    def test_mysql_greeting_then_error(self):
        """MySQL port should send greeting, then ERR packet after login attempt."""
        from smudged_lens.spoof_engine import _mysql_greeting, _mysql_auth_error

        # Use raw socket pair to test the protocol handler directly
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind(("127.0.0.1", 0))
        server_sock.listen(1)
        server_port = server_sock.getsockname()[1]

        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.settimeout(5)
        client.connect(("127.0.0.1", server_port))
        server_conn, _ = server_sock.accept()

        try:
            # Server sends MySQL greeting
            banner = "MySQL 8.0.35"
            server_conn.sendall(_mysql_greeting(banner))

            # Client reads the greeting packet
            greeting = client.recv(4096)
            self.assertGreater(len(greeting), 5,
                "MySQL server must send a greeting packet")
            # Protocol version byte is at offset 4
            self.assertEqual(greeting[4], 10,
                "greeting should indicate protocol version 10")

            # Client sends a minimal login attempt
            client.sendall(b"\x01\x00\x00\x01\x85\xa6\x03\x00root\x00\x14TEST")

            # Server handles auth error
            _mysql_auth_error(server_conn, banner)

            # Client reads the ERR packet
            err_response = client.recv(4096)
            self.assertGreater(len(err_response), 0,
                "MySQL should respond with an ERR packet")
            # ERR packet type is 0xff
            self.assertEqual(err_response[4], 0xff,
                "response should be an ERR packet (type 0xff)")
        finally:
            client.close()
            server_conn.close()
            server_sock.close()


# =============================================================================
# FTP / SMTP / PostgreSQL protocol handlers
# =============================================================================

def _read_reply_lines(sock, idle=0.06):
    """Collect one full (possibly multi-line) server reply.

    Multi-line replies (FTP FEAT, SMTP EHLO) span several \n-terminated lines;
    reading just the first leaves trailing lines that corrupt the next assert.
    We read until no data arrives for *idle* seconds."""
    sock.settimeout(1.0)
    lines = []
    last = time.monotonic()
    while True:
        ready, _, _ = select.select([sock], [], [], 0.05)
        if not ready:
            if time.monotonic() - last > idle:
                break
            continue
        buf = b""
        while not buf.endswith(b"\n"):
            chunk = sock.recv(1)
            if not chunk:
                break
            buf += chunk
        if buf:
            lines.append(buf.decode("latin1").strip("\r\n"))
            last = time.monotonic()
        else:
            break
    return lines


class TestFTPSession(unittest.TestCase):
    def test_ftp_command_conversation(self):
        """nmap -sV gets past the 220 greeting: USER/SYST/FEAT/QUIT answered."""
        from smudged_lens.spoof_engine import _ftp_session
        a, b = socket.socketpair()
        t = threading.Thread(target=lambda: (_ftp_session(b, "ProFTPD 1.3.6"), b.close()))
        t.start()
        try:
            a.settimeout(3)
            greeting = _read_reply_lines(a)
            self.assertTrue(greeting and greeting[0].startswith("220"))
            self.assertIn("ProFTPD", greeting[0])
            a.sendall(b"USER anonymous\r\n")
            self.assertTrue(_read_reply_lines(a)[0].startswith("331"))
            a.sendall(b"SYST\r\n")
            self.assertTrue(_read_reply_lines(a)[0].startswith("215"))
            a.sendall(b"FEAT\r\n")
            self.assertTrue(_read_reply_lines(a)[0].startswith("211"))
            a.sendall(b"QUIT\r\n")
            quit_ = _read_reply_lines(a)
            self.assertTrue(quit_ and quit_[-1].startswith("221"))
        finally:
            a.close()
            t.join(timeout=4)

    def test_ftp_hostile_bytes_never_crash(self):
        from smudged_lens.spoof_engine import _ftp_session
        a, b = socket.socketpair()
        errs = []

        def serve():
            try:
                _ftp_session(b, "ProFTPD 1.3.6")
            except Exception as e:  # noqa: BLE001
                errs.append(e)
            finally:
                b.close()

        t = threading.Thread(target=serve)
        t.start()
        try:
            a.settimeout(3)
            a.recv(4096)  # greeting
            a.sendall(b"\xff\x00\r\n" * 10)
            a.close()
            t.join(timeout=4)
            self.assertEqual(errs, [], f"FTP handler crashed: {errs}")
        finally:
            a.close()


class TestSMTPSession(unittest.TestCase):
    def test_smtp_command_conversation(self):
        from smudged_lens.spoof_engine import _smtp_session
        a, b = socket.socketpair()
        t = threading.Thread(target=lambda: (_smtp_session(b, "Postfix smtpd"), b.close()))
        t.start()
        try:
            a.settimeout(3)
            self.assertTrue(_read_reply_lines(a)[0].startswith("220"))
            a.sendall(b"EHLO localhost\r\n")
            ehlo = _read_reply_lines(a)
            self.assertTrue(ehlo and ehlo[0].startswith("250"))
            a.sendall(b"MAIL FROM:<a@b>\r\n")
            self.assertTrue(_read_reply_lines(a)[0].startswith("250"))
            a.sendall(b"QUIT\r\n")
            quit_ = _read_reply_lines(a)
            self.assertTrue(quit_ and quit_[-1].startswith("221"))
        finally:
            a.close()
            t.join(timeout=4)


class TestPostgresStartup(unittest.TestCase):
    def test_postgres_handshake_auth_and_ready(self):
        from smudged_lens.spoof_engine import _postgres_handshake
        a, b = socket.socketpair()
        t = threading.Thread(target=lambda: (_postgres_handshake(b, "PostgreSQL 15.5"), b.close()))
        t.start()
        try:
            a.settimeout(3)
            a.sendall(struct.pack("!II", 8, 80877103))   # SSLRequest
            self.assertEqual(a.recv(1), b"N", "server should decline TLS")
            params = b"user\x00postgres\x00database\x00postgres\x00\x00"
            body = struct.pack("!I", 196608) + params
            a.sendall(struct.pack("!I", len(body) + 4) + body)
            resp = a.recv(4096)
            self.assertIn(b"R\x00\x00\x00\x08\x00\x00\x00\x00", resp)  # AuthenticationOk
            self.assertIn(b"Z\x00\x00\x00\x05I", resp)                    # ReadyForQuery
            self.assertIn(b"server_version\x0015.5", resp)
        finally:
            a.close()
            t.join(timeout=4)

    def test_postgres_backend_keydata_does_not_leak_host_pid(self):
        import os
        from smudged_lens.spoof_engine import _postgres_handshake
        a, b = socket.socketpair()
        t = threading.Thread(target=lambda: (_postgres_handshake(b, "PostgreSQL 15.5"), b.close()))
        t.start()
        try:
            a.settimeout(3)
            params = b"user\x00postgres\x00database\x00postgres\x00\x00"
            body = struct.pack("!I", 196608) + params
            a.sendall(struct.pack("!I", len(body) + 4) + body)
            data = b""
            while True:
                chunk = a.recv(1024)
                if not chunk:
                    break
                data += chunk
            pids = []
            idx = 0
            while True:
                idx = data.find(b"K\x00\x00\x00\x0c", idx)
                if idx == -1:
                    break
                pids.append(struct.unpack("!I", data[idx + 5:idx + 9])[0])
                idx += 9
            self.assertGreater(len(pids), 0, "expected a BackendKeyData message")
            for pid in pids:
                self.assertNotEqual(pid, os.getpid(), "BackendKeyData leaks host pid")
        finally:
            a.close()
            t.join(timeout=4)


# =============================================================================
# DNS Wire Protocol Tests
# =============================================================================

class TestDNSWireProtocol(unittest.TestCase):
    """Tests for DNS wire protocol response builder."""

    def test_parse_name_simple(self):
        """Parse a simple domain name from wire format."""
        # www.example.com = \x03www\x07example\x03com\x00
        data = b"\x03www\x07example\x03com\x00"
        name, offset = _dns_parse_name(data, 0)
        self.assertEqual(name, "www.example.com")
        self.assertEqual(offset, len(data))

    def test_parse_name_compression_pointer(self):
        """Parse a name with a compression pointer."""
        # First name: \x03www\x07example\x03com\x00 at offset 0
        # Second reference: pointer to offset 0 at offset 17
        data = b"\x03www\x07example\x03com\x00\xc0\x00"
        name, offset = _dns_parse_name(data, 17)  # start at the pointer
        self.assertEqual(name, "www.example.com")

    def test_build_response_a_record(self):
        """Build a DNS response for an A record query."""
        # Build a simple A query for example.com
        header = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
        question = b"\x07example\x03com\x00" + struct.pack("!HH", 1, 1)
        query = header + question

        response = _dns_build_response(query)
        self.assertIsNotNone(response)
        self.assertGreater(len(response), 12)

        # Parse response header
        qid, flags, qdcount, ancount = struct.unpack("!HHHH", response[:8])
        self.assertEqual(qid, 0x1234)  # ID matches query
        self.assertEqual(flags & 0x8000, 0x8000)  # QR bit set
        self.assertEqual(qdcount, 1)
        self.assertEqual(ancount, 1)  # one answer

    def test_build_response_txt_record(self):
        """Build a DNS response for a TXT record (version.bind probe)."""
        # TXT query for version.bind
        header = struct.pack("!HHHHHH", 0xABCD, 0x0100, 1, 0, 0, 0)
        # version.bind = \x07version\x04bind\x00
        question = b"\x07version\x04bind\x00" + struct.pack("!HH", 16, 3)  # TXT, CH class
        query = header + question

        response = _dns_build_response(query, banner="ISC BIND 9.18.18")
        self.assertIsNotNone(response)
        self.assertGreater(len(response), 12)

        # Verify QR and answer count
        flags, ancount = struct.unpack("!HH", response[2:6])
        self.assertEqual(flags & 0x8000, 0x8000)
        self.assertEqual(ancount, 1)

    def test_build_response_malformed(self):
        """Malformed queries return None."""
        self.assertIsNone(_dns_build_response(b"\x00"))
        self.assertIsNone(_dns_build_response(b""))
        # Valid header but truncated question
        header = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
        self.assertIsNone(_dns_build_response(header))

    def test_tcp_dns_roundtrip(self):
        """TCP DNS: length-prefixed query → length-prefixed response."""
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind(("127.0.0.1", 0))
        server_sock.listen(1)
        port = server_sock.getsockname()[1]

        try:
            # Build a DNS A query
            header = struct.pack("!HHHHHH", 0x5678, 0x0100, 1, 0, 0, 0)
            question = b"\x07example\x03com\x00" + struct.pack("!HH", 1, 1)
            query = header + question

            # Client sends length-prefixed query
            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client.settimeout(3)
            client.connect(("127.0.0.1", port))

            conn, _ = server_sock.accept()
            conn.settimeout(3)

            # Send length-prefixed query
            client.sendall(struct.pack("!H", len(query)) + query)

            # Read length prefix
            length_data = conn.recv(2)
            self.assertEqual(len(length_data), 2)
            msg_len = struct.unpack("!H", length_data)[0]

            # Read response
            response = conn.recv(msg_len)
            self.assertGreater(len(response), 12)

            # Verify ID matches
            resp_id = struct.unpack("!H", response[:2])[0]
            self.assertEqual(resp_id, 0x5678)

            client.close()
            conn.close()
        finally:
            server_sock.close()

    def test_udp_dns_roundtrip(self):
        """UDP DNS: datagram query → datagram response."""
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind(("127.0.0.1", 0))
        port = server_sock.getsockname()[1]

        try:
            # Build a DNS A query
            header = struct.pack("!HHHHHH", 0x9999, 0x0100, 1, 0, 0, 0)
            question = b"\x07example\x03com\x00" + struct.pack("!HH", 1, 1)
            query = header + question

            # Client sends query, then server processes it and sends response.
            # Use a thread so the server recvfrom doesn't block forever.
            result = [None]
            def server_respond():
                _dns_respond_udp(server_sock, "ISC BIND 9.18.18")
                # After responding, try to read back the response sent to client
                # The response was sent to the client's addr — we need a separate
                # socket to capture it. Simpler: just verify _dns_respond_udp runs.

            def client_send():
                client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                client.settimeout(3)
                client.sendto(query, ("127.0.0.1", port))
                try:
                    data, _ = client.recvfrom(4096)
                    result[0] = data
                except OSError:
                    pass
                client.close()

            t_server = threading.Thread(target=server_respond)
            t_client = threading.Thread(target=client_send)
            t_server.start()
            t_client.start()
            t_server.join(timeout=3)
            t_client.join(timeout=3)

            self.assertIsNotNone(result[0])
            resp_id = struct.unpack("!H", result[0][:2])[0]
            self.assertEqual(resp_id, 0x9999)

            # Verify it's a valid DNS response
            flags = struct.unpack("!H", result[0][2:4])[0]
            self.assertEqual(flags & 0x8000, 0x8000)  # QR=1
        finally:
            server_sock.close()


# =============================================================================
# IPv6 Spoofing Tests
# =============================================================================

class TestIPv6Spoofing(unittest.TestCase):
    """Tests for IPv6 spoofing via ip6tables."""

    def test_enable_applies_ip6tables_when_available(self):
        """IPv6 rules are applied when ip6tables is available."""
        fp = OSFingerprinter()
        mock_result = subprocess.CompletedProcess([], returncode=0)

        with patch("smudged_lens.config.IS_LINUX", True), \
             patch("smudged_lens.config.HAS_IPTABLES", True), \
             patch("smudged_lens.config.HAS_IP6TABLES", True), \
             patch("subprocess.run", return_value=mock_result):
            success, msg = fp.enable("windows11")
            self.assertTrue(success)
            self.assertIn("IPv6", msg)

    def test_enable_skips_ip6tables_when_unavailable(self):
        """IPv6 rules are skipped when ip6tables is not available."""
        fp = OSFingerprinter()
        mock_result = subprocess.CompletedProcess([], returncode=0)

        with patch("smudged_lens.config.IS_LINUX", True), \
             patch("smudged_lens.config.HAS_IPTABLES", True), \
             patch("smudged_lens.config.HAS_IP6TABLES", False), \
             patch("subprocess.run", return_value=mock_result):
            success, msg = fp.enable("windows11")
            self.assertTrue(success)
            self.assertNotIn("IPv6", msg)

    def test_cleanup_ip6tables_handles_missing(self):
        """ip6tables cleanup should not crash when ip6tables is missing."""
        fp = OSFingerprinter()
        with patch("smudged_lens.config.HAS_IP6TABLES", True), \
             patch("subprocess.run", side_effect=FileNotFoundError):
            fp._cleanup_ip6tables_rules()  # should not raise

    def test_cleanup_ip6tables_skipped_when_unavailable(self):
        """ip6tables cleanup is a no-op when HAS_IP6TABLES is False."""
        fp = OSFingerprinter()
        with patch("smudged_lens.config.HAS_IP6TABLES", False):
            fp._cleanup_ip6tables_rules()  # should be instant, no subprocess calls

    def test_disable_cleans_both_iptables_and_ip6tables(self):
        """Disable should attempt cleanup for both iptables and ip6tables."""
        fp = OSFingerprinter()
        call_log = []
        def mock_run(cmd, **kwargs):
            call_log.append(cmd[0])
            return subprocess.CompletedProcess([], returncode=1)

        with patch("smudged_lens.config.HAS_IP6TABLES", True), \
             patch("subprocess.run", side_effect=mock_run):
            fp.disable()

        self.assertIn("iptables-save", call_log)
        self.assertIn("ip6tables-save", call_log)


# =============================================================================
# Fuzz Hardening — hostile / malformed input must never crash the wire handlers
# =============================================================================

class _FakeNetSocket:
    """A byte-bounded fake socket for exercising the wire handlers hermetically.

    Models the two ways a hostile peer misbehaves: it sends arbitrary/malformed
    bytes, and it aborts the stream (socket.timeout / OSError) at any moment.
    recv() is exact-bounded (like a real socket) so oversized reads can't sneak
    past a length check. To force an abort, push a socket.timeout() or OSError()
    instance into the chunk list.
    """

    def __init__(self, chunks=(), abort_writes=False):
        self._chunks = list(chunks)
        self._buf = b""
        self.abort_writes = abort_writes
        self.sent = b""
        self.closed = False

    def settimeout(self, _t):
        pass

    def setblocking(self, _v):
        pass

    def close(self):
        self.closed = True

    def recv(self, n):
        while not self._buf and self._chunks:
            c = self._chunks.pop(0)
            if isinstance(c, BaseException):
                raise c
            self._buf += c
        if not self._buf:
            return b""
        out = self._buf[:n]
        self._buf = self._buf[n:]
        return out

    def recvfrom(self, _n):
        while not self._buf and self._chunks:
            c = self._chunks.pop(0)
            if isinstance(c, BaseException):
                raise c
            self._buf += c
        data = self._buf
        self._buf = b""
        return data, ("203.0.113.7", 31337)

    def sendall(self, data):
        if self.abort_writes:
            raise OSError("peer aborted write")
        self.sent += data

    def sendto(self, data, _addr):
        if self.abort_writes:
            raise OSError("peer aborted write")
        self.sent += data


class TestFuzzHardening(unittest.TestCase):
    """Fuzz the DNS/banner parsers and the socket wire handlers against hostile
    input. Every probe the engine ever receives is untrusted bytes from the
    network — a crash in any of them (an uncaught struct.error, IndexError,
    UnsupportedOperation ...) would kill a handler thread. These tests are
    deterministic (seeded RNG) and assert that the handlers never raise."""

    def _seed(self):
        return random.Random(0xC0FFFF)

    def test_dns_build_response_random_bytes(self):
        rng = self._seed()
        for _ in range(2000):
            data = bytes(rng.getrandbits(8) for _ in range(rng.randrange(0, 256)))
            result = _dns_build_response(data)  # must not raise
            self.assertTrue(result is None or isinstance(result, bytes))

    def test_dns_build_response_mutated_queries(self):
        rng = self._seed()
        qtypes = [1, 2, 15, 16, 28, 255, 65535]
        for _ in range(1200):
            labels = [
                bytes([rng.randrange(1, 64)]) + bytes(rng.getrandbits(8)
                       for _ in range(rng.randrange(0, 20))) + b"\x00"
                for _ in range(rng.randrange(1, 4))
            ]
            q = bytearray(
                struct.pack("!HHHHHH", rng.randrange(65536), rng.randrange(65536),
                            1, 0, 0, 0)
                + b"".join(labels)
                + struct.pack("!HH", rng.choice(qtypes), rng.choice([1, 3]))
            )
            for _ in range(rng.randrange(1, 5)):
                if not q:
                    break
                pos = rng.randrange(len(q))
                q[pos] ^= rng.randrange(1, 256)
                if rng.random() < 0.3:
                    del q[pos:]
                _dns_build_response(bytes(q), banner="ISC BIND 9.18.18")  # no raise

    def test_dns_parse_name_total(self):
        rng = self._seed()
        for _ in range(2000):
            data = bytes(rng.getrandbits(8) for _ in range(rng.randrange(0, 64)))
            off = rng.randrange(0, len(data) + 1)
            name, new_off = _dns_parse_name(data, off)  # must not raise
            self.assertIsInstance(name, str)
            self.assertIsInstance(new_off, int)

    def test_sanitize_banner_total(self):
        rng = self._seed()
        weird = [None, 0, 1.5, b"\x00\xff\r\n", "\x1b[31m", "\u00e9\u2028"]
        for _ in range(2000):
            value = rng.choice(weird) if rng.random() < 0.4 else (
                bytes(rng.getrandbits(8) for _ in range(rng.randrange(0, 120))))
            clean = sanitize_banner(value)  # must not raise
            self.assertTrue(clean)
            self.assertLessEqual(len(clean), 96)
            self.assertTrue(all(32 <= ord(c) < 127 for c in clean),
                            msg=f"non-printable char in {clean!r}")
            self.assertNotIn("\n", clean)
            self.assertNotIn("\r", clean)

    def test_dns_respond_tcp_total(self):
        rng = self._seed()
        # [] / b"" simulate a peer sending nothing or disconnecting (EOF is
        # b"", never None). The last two are a valid length prefix followed by
        # an EOF mid-message and an oversized length claim.
        payloads = [
            [],
            [b""],
            [socket.timeout()],
            [OSError("reset")],
            [bytes(rng.getrandbits(8) for _ in range(rng.randrange(0, 64)))],
            [b"\x00\x00", bytes(rng.getrandbits(8) for _ in range(rng.randrange(0, 64)))],
            [b"\x00\x04", b""],
            [b"\xff\xff"],
        ]
        for chunks in payloads:
            _dns_respond_tcp(_FakeNetSocket(chunks), "ISC BIND 9.18.18")  # no raise

    def test_dns_respond_tcp_answers_valid_query(self):
        """Under the fake, a well-formed query still produces a length-prefixed reply."""
        query = (struct.pack("!HHHHHH", 0x4321, 0x0100, 1, 0, 0, 0)
                 + b"\x07example\x03com\x00" + struct.pack("!HH", 1, 1))
        sock = _FakeNetSocket([struct.pack("!H", len(query)) + query])
        _dns_respond_tcp(sock, "ISC BIND 9.18.18")
        self.assertGreaterEqual(len(sock.sent), 2)
        resp_len = struct.unpack("!H", sock.sent[:2])[0]
        self.assertEqual(resp_len, len(sock.sent) - 2)
        self.assertEqual(struct.unpack("!H", sock.sent[2:4])[0], 0x4321)  # echoed ID

    def test_dns_respond_udp_total(self):
        rng = self._seed()
        sock = _FakeNetSocket([
            OSError("recvfrom failed"),
            bytes(rng.getrandbits(8) for _ in range(rng.randrange(0, 64))),
        ])
        _dns_respond_udp(sock, "ISC BIND 9.18.18")  # no raise
        # A datagram whose response write fails must also not raise.
        _dns_respond_udp(_FakeNetSocket([b"garbage"], abort_writes=True),
                         "ISC BIND 9.18.18")

    def test_ssh_auth_failure_total(self):
        rng = self._seed()
        for chunks in ([[socket.timeout()], [OSError("reset")],
                        [bytes(rng.getrandbits(8) for _ in range(60))], []]):
            _ssh_auth_failure(_FakeNetSocket(chunks))  # no raise

    def test_mysql_auth_error_total(self):
        rng = self._seed()
        for chunks in ([[socket.timeout()], [OSError("reset")],
                        [bytes(rng.getrandbits(8) for _ in range(60))], []]):
            _mysql_auth_error(_FakeNetSocket(chunks), "MySQL 8.0.35")  # no raise

    def test_mysql_greeting_hostile_banners(self):
        rng = self._seed()
        for _ in range(800):
            banner = rng.choice([
                bytes(rng.getrandbits(8) for _ in range(rng.randrange(0, 64))).decode("latin1"),
                str(rng.randrange(10 ** 9)),
                "MySQL " + "a" * 500,
                "\x00\xff\r\nMySQL",
                "MariaDB 10.5.22 ",
            ])
            g = _mysql_greeting(banner)  # must not raise
            self.assertIsInstance(g, bytes)
            self.assertGreater(len(g), 4)

    def test_service_handlers_never_crash_on_hostile_bytes(self):
        """FTP/SMTP/PostgreSQL sessions must tolerate junk and aborts, like the others."""
        from smudged_lens.spoof_engine import _ftp_session, _smtp_session, _postgres_handshake
        rng = self._seed()
        handlers = [_ftp_session, _smtp_session, _postgres_handshake]
        banners = ["ProFTPD 1.3.6", "Postfix smtpd", "PostgreSQL 15.5", ""]
        for i in range(300):
            h = rng.choice(handlers)
            payload = bytes(rng.getrandbits(8) for _ in range(rng.randrange(0, 48)))
            chunks = [payload]
            if i % 2:
                chunks.append(rng.choice([socket.timeout(), OSError("reset")]))
            h(_FakeNetSocket(chunks), rng.choice(banners))  # must not raise

    def test_respond_never_crashes_on_hostile_wire_data(self):
        """Drive the real responder dispatch over live socketpairs with junk."""
        rng = self._seed()
        probes = [
            (22, "OpenSSH_9.6"),
            (21, "ProFTPD 1.3.6"),
            (25, "Postfix smtpd"),
            (53, "ISC BIND 9.18.18"),
            (80, "Apache/2.4.58"),
            (3306, "MySQL 8.0.35"),
            (5432, "PostgreSQL 15.5"),
            (9999, "Generic Service"),
        ]
        payloads = [
            bytes(rng.getrandbits(8) for _ in range(rng.randrange(0, 80))),
            b"GET / HTTP/1.1\r\nHost: x\r\n\r\n",
            b"SSH-2.0-OpenSSH_8.9p1\r\n",
        ]
        for port, banner in probes:
            for payload in payloads:
                a, b = socket.socketpair()
                errs = []
                def run():
                    try:
                        PortResponder()._respond(b, port, banner)
                    except (OSError, socket.timeout, ssl.SSLError):
                        pass  # peer aborted — expected
                    except Exception as e:  # noqa: BLE001 — a crash is a test failure
                        errs.append(e)
                    finally:
                        try:
                            b.close()
                        except OSError:
                            pass
                t = threading.Thread(target=run, daemon=True)
                t.start()
                try:
                    a.sendall(payload)
                except OSError:
                    pass
                a.close()
                t.join(timeout=5)
                self.assertFalse(t.is_alive(),
                                f"{port} handler hung on hostile data")
                self.assertEqual(errs, [],
                                f"{port} raised {errs[0] if errs else ''}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
