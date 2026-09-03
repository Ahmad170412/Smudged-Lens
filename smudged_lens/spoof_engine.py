import atexit
import datetime
import logging
import os
import random
import re
import secrets
import shutil
import signal
import socket
import ssl
import struct
import subprocess
import threading
import time
from collections import deque

from . import config as _config  # accessed via module so test patches take effect

logger = logging.getLogger("smudged_lens")

# Per-session random tag for iptables/ip6tables rules — allows cleanup
# of only our rules without revealing the tool name in cleartext.
_IPTABLES_PREFIX = "nf-"
_IPTABLES_COMMENT = _IPTABLES_PREFIX + secrets.token_hex(4)

# Ports that get HTTP-style decoy responses / TLS wrapping
HTTP_PORTS = {80, 631, 8080, 8443, 443, 8000, 8888, 9090}
TLS_PORTS = {443, 8443}

# DNS port — needs proper wire-protocol handling, not plaintext banners
DNS_PORT = 53

# Dummy IP returned for spoofed DNS A records (RFC 5737 TEST-NET-3)
_DNS_DUMMY_IP = "192.0.2.1"
_DNS_DUMMY_IPV6 = "2001:db8::1"

# Max simultaneous client handlers per spoofed port (excess connections are dropped)
MAX_CONNECTIONS_PER_PORT = 16

# Tarpitting — hold blocked connections open to waste scanner time
TARPIT_MIN_DELAY = 1.0      # minimum seconds between sent bytes
TARPIT_MAX_DELAY = 8.0      # maximum seconds between sent bytes
TARPIT_HOLD_TIME = 30.0     # total seconds to hold the connection
TARPIT_JUNK_SIZE = (1, 8)   # random byte count per write (min, max)

# Banner variance — per-connection subtle differences to break fingerprinting
SSH_Software_Variants = [
    "OpenSSH_9.6",
    "OpenSSH_9.5p1",
    "OpenSSH_9.3p2",
    "OpenSSH_8.9p1",
    "OpenSSH_8.4p1",
]


def sanitize_banner(value, default="Generic Server"):
    """Clamp a service banner to printable, single-line ASCII.

    Banners end up in HTTP ``Server:`` headers and wire protocols — a value
    containing CRLF would let an API/CLI user inject arbitrary response
    headers into the decoy output.
    """
    cleaned = "".join(ch if 32 <= ord(ch) < 127 else " " for ch in str(value))
    cleaned = " ".join(cleaned.split())[:96]
    return cleaned or default


# ---------------------------------------------------------------------------
# DNS wire protocol — speak real DNS instead of plaintext banners
# ---------------------------------------------------------------------------

def _dns_parse_name(data, offset):
    """Parse a DNS name from wire format.

    Returns (name_string, new_offset). Handles compression pointers (RFC 1035
    section 4.1.4) with a depth limit to prevent infinite loops.
    """
    parts = []
    jump_count = 0
    while offset < len(data):
        length = data[offset]
        if length == 0:
            offset += 1
            break
        # Compression pointer: top two bits set → 14-bit offset
        if (length & 0xC0) == 0xC0:
            if offset + 1 >= len(data):
                break
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            offset += 2
            jump_count += 1
            if jump_count > 64:
                break  # prevent infinite loops from malformed packets
            offset = pointer
            continue
        offset += 1
        if offset + length > len(data):
            break
        parts.append(data[offset:offset + length].decode("ascii", errors="replace"))
        offset += length
    return ".".join(parts), offset


def _dns_build_response(query_data, banner="ISC BIND 9.18.18"):
    """Build a valid DNS response packet for the given query.

    Returns the raw response bytes, or None if the query is malformed.
    A real DNS server would resolve properly — we return plausible dummy
    records that satisfy nmap's version detection without revealing we're
    a spoof.
    """
    if len(query_data) < 12:
        return None

    # Parse header
    (qid, _flags, qdcount, ancount, _nscount, arcount) = struct.unpack(
        "!HHHHHH", query_data[:12],
    )

    # Parse the question section
    offset = 12
    _qname, offset = _dns_parse_name(query_data, offset)
    if offset + 4 > len(query_data):
        return None
    qtype, _qclass = struct.unpack("!HH", query_data[offset:offset + 4])

    # Build response header: QR=1, AA=1, RA=1, RCODE=0
    resp_flags = 0x8180  # standard response, authorative, recursion available
    # Build answer records
    answers = []

    if qtype == 1:  # A record
        ip_bytes = socket.inet_aton(_DNS_DUMMY_IP)
        answers.append(
            struct.pack("!H", 0xC00C)  # pointer to question name
            + struct.pack("!HHI", 1, 1, 300)  # type A, class IN, TTL 300
            + struct.pack("!H", 4)  # RDLENGTH
            + ip_bytes
        )
    elif qtype == 28:  # AAAA record
        ip6_bytes = socket.inet_pton(socket.AF_INET6, _DNS_DUMMY_IPV6)
        answers.append(
            struct.pack("!H", 0xC00C)
            + struct.pack("!HHI", 28, 1, 300)  # type AAAA, class IN, TTL 300
            + struct.pack("!H", 16)  # RDLENGTH
            + ip6_bytes
        )
    elif qtype == 16:  # TXT record
        # nmap probes "version.bind" and "version.server" via CH class TXT.
        # Return a plausible BIND version string.
        txt = banner.encode("ascii")[:255]
        txt_record = struct.pack("B", len(txt)) + txt
        answers.append(
            struct.pack("!H", 0xC00C)
            + struct.pack("!HHI", 16, 1, 300)  # type TXT, class IN, TTL 300
            + struct.pack("!H", len(txt_record))
            + txt_record
        )
    elif qtype == 15:  # MX record
        # Return a plausible mail exchange
        mx_exchange = b"\x04mail\x06example\x03com\x00"
        answers.append(
            struct.pack("!H", 0xC00C)
            + struct.pack("!HHI", 15, 1, 300)  # type MX, class IN, TTL 300
            + struct.pack("!H", 2 + len(mx_exchange))  # RDLENGTH
            + struct.pack("!H", 10)  # preference
            + mx_exchange
        )
    elif qtype == 2:  # NS record
        ns_name = b"\x04ns1\x06example\x03com\x00"
        answers.append(
            struct.pack("!H", 0xC00C)
            + struct.pack("!HHI", 2, 1, 300)  # type NS, class IN, TTL 300
            + struct.pack("!H", len(ns_name))
            + ns_name
        )
    # Other query types: return empty response (NOERROR with 0 answers)

    ancount = len(answers)
    header = struct.pack("!HHHHHH", qid, resp_flags, qdcount, ancount, 0, arcount)
    question = query_data[12:offset + 4]
    return header + question + b"".join(answers)


def _dns_respond_tcp(client, banner):
    """Handle a TCP DNS connection (RFC 1035 section 4.2.2).

    TCP DNS messages are prefixed with a 2-byte length field.
    """
    # Read the 2-byte length prefix
    length_data = _recv_exact(client, 2)
    if length_data is None:
        return
    msg_len = struct.unpack("!H", length_data)[0]
    if msg_len > 4096:
        return  # oversized — drop silently

    query_data = _recv_exact(client, msg_len)
    if query_data is None:
        return

    response = _dns_build_response(query_data, banner)
    if response is None:
        return

    # Send length-prefixed response
    client.sendall(struct.pack("!H", len(response)) + response)


def _dns_respond_udp(server_sock, banner):
    """Handle a single UDP DNS query.

    Called from the UDP listener thread when a datagram arrives on port 53.
    """
    try:
        data, addr = server_sock.recvfrom(4096)
    except OSError:
        return
    response = _dns_build_response(data, banner)
    if response is None:
        return
    try:
        server_sock.sendto(response, addr)
    except OSError:
        pass


def _recv_exact(sock, n):
    """Read exactly *n* bytes from *sock*, or return None on short read."""
    buf = b""
    while len(buf) < n:
        try:
            chunk = sock.recv(n - len(buf))
        except (socket.timeout, OSError):
            return None
        if not chunk:
            return None
        buf += chunk
    return buf


def _recv_line(sock, maxlen=512):
    """Read one \n-terminated line from *sock*, returned without CR/LF.

    Byte-by-byte read keeps pipelined commands safe and bounds memory. Returns
    b"" on disconnect/timeout/junk with no line terminator, or a line capped at
    *maxlen* bytes."""
    buf = b""
    while len(buf) < maxlen:
        try:
            ch = sock.recv(1)
        except (socket.timeout, OSError):
            break
        if not ch:
            break
        buf += ch
        if buf.endswith(b"\n"):
            break
    return buf.rstrip(b"\r\n")


# ---------------------------------------------------------------------------
# Tarpitting — waste scanner time by holding blocked connections open
# ---------------------------------------------------------------------------

def _tarpit_connection(client, dest_port):
    """Hold a blocked connection open, trickling junk bytes slowly.

    The scanner's TCP handshake completed (kernel-level), so the port still
    appears "open" to nmap. But every second wasted here is a second the
    scanner isn't scanning your real services. Connections are held for
    TARPIT_HOLD_TIME seconds with randomized delays between writes.

    Uses small sleep increments so we detect client disconnects promptly
    instead of sleeping through the entire delay.

    Returns after the hold period or on client disconnect.
    """
    hold_end = time.monotonic() + TARPIT_HOLD_TIME
    rng = random.Random()
    try:
        while time.monotonic() < hold_end:
            delay = rng.uniform(TARPIT_MIN_DELAY, TARPIT_MAX_DELAY)
            remaining = hold_end - time.monotonic()
            sleep_until = time.monotonic() + min(delay, max(remaining, 0.05))

            # Sleep in small chunks so we notice disconnects quickly
            while time.monotonic() < sleep_until:
                time.sleep(0.1)
                # Check if client is still connected by attempting a zero-byte peek
                try:
                    client.setblocking(False)
                    peek = client.recv(1, socket.MSG_PEEK)
                    if peek == b"":
                        return  # client disconnected cleanly
                except BlockingIOError:
                    pass  # no data yet — still connected
                except OSError:
                    return  # socket error — client gone
                finally:
                    try:
                        client.setblocking(True)
                    except OSError:
                        pass

            if time.monotonic() >= hold_end:
                break

            # Send a small chunk of plausible-looking junk
            size = rng.randint(*TARPIT_JUNK_SIZE)
            try:
                client.sendall(os.urandom(size))
            except OSError:
                return  # client disconnected — stop wasting our threads
    finally:
        try:
            client.close()
        except OSError:
            pass


# ---------------------------------------------------------------------------
# Banner variance — per-connection differences to break scanner fingerprinting
# ---------------------------------------------------------------------------

def _banner_variance(banner, source_port):
    """Return a slightly varied version of a banner string.

    Real services produce subtly different banners across connections
    (build timestamps, patch levels, connection-specific IDs). A perfect
    byte-identical response across every connection is itself a fingerprint.
    """
    rng = random.Random(source_port ^ (hash(banner) & 0xFFFFFFFF))

    # For SSH banners, occasionally swap in a plausible older version
    if "OpenSSH" in banner and rng.random() < 0.3:
        return rng.choice(SSH_Software_Variants)

    return banner


def _banner_jitter():
    """Small random delay to simulate natural server response timing."""
    time.sleep(random.uniform(0.01, 0.05))


# ---------------------------------------------------------------------------
# Port conflict detection — identify real services blocking our binds
# ---------------------------------------------------------------------------

# Known services that commonly run on each OS and would conflict with our
# spoofed ports. Each entry: port → (service_name, {os: disable_command}).
# A missing OS key means "we know this service exists but can't auto-disable it".
KNOWN_SERVICES = {
    22: ("SSH", {
        "linux":  "sudo systemctl stop ssh && sudo systemctl disable ssh",
        "macos":  "sudo systemsetup -setremotelogin off",
        "windows": "net stop TermService",
    }),
    80: ("HTTP server (Apache/nginx/IIS)", {
        "linux":  "sudo systemctl stop apache2 nginx httpd",
        "macos":  "sudo apachectl stop",
        "windows": "net stop W3SVC",
    }),
    443: ("HTTPS server (Apache/nginx/IIS)", {
        "linux":  "sudo systemctl stop apache2 nginx httpd",
        "macos":  "sudo apachectl stop",
        "windows": "net stop W3SVC",
    }),
    53: ("DNS server (BIND)", {
        "linux":  "sudo systemctl stop named bind9",
    }),
    3306: ("MySQL/MariaDB", {
        "linux":  "sudo systemctl stop mysql mariadb",
        "macos":  "brew services stop mysql",
    }),
    5432: ("PostgreSQL", {
        "linux":  "sudo systemctl stop postgresql",
        "macos":  "brew services stop postgresql",
    }),
    631: ("CUPS ( printing service )", {
        "macos":  "sudo launchctl bootout system /System/Library/LaunchDaemons/com.apple.cups.plist",
        "linux":  "sudo systemctl stop cups cups-browsed",
    }),
    3389: ("RDP (Remote Desktop)", {
        "windows": "reg add \"HKLM\\System\\CurrentControlSet\\Control\\Terminal Server\" /v fDenyTSConnections /t REG_DWORD /d 1 /f && net stop TermService",
    }),
}


def _port_in_use(port):
    """Check if a port is already bound by another process.

    Returns (in_use: bool, service_hint: str or None) where service_hint
    is a human-readable note about what's likely on that port and how to
    disable it on the current OS.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.0)
        result = s.connect_ex(("127.0.0.1", port))
        s.close()
        if result == 0:
            # Port is accepting connections — something is already on it
            hint = None
            if port in KNOWN_SERVICES:
                svc_name, disable_cmds = KNOWN_SERVICES[port]
                # Pick the disable command for the current OS
                os_key = ("macos" if _config.IS_MACOS
                          else "linux" if _config.IS_LINUX
                          else "windows")
                cmd = disable_cmds.get(os_key)
                if cmd:
                    hint = f"Real {svc_name} is running. Disable it: {cmd}"
                else:
                    hint = f"Real {svc_name} is running on this port"
            return True, hint
    except OSError:
        pass
    return False, None


# ---------------------------------------------------------------------------
# Fake auth failures — force scanners to interact, not just grab banners
# ---------------------------------------------------------------------------

def _ssh_auth_failure(client):
    """After sending the SSH banner, handle the client's KEXINIT and respond
    with a proper USERAUTH_FAILURE. This forces nmap's version detection
    through a full SSH handshake instead of just grabbing the banner string.

    SSH protocol flow (server side):
      1. Server sends banner (done before calling this)
      2. Server sends SSH_MSG_KEXINIT (20)
      3. Client sends SSH_MSG_KEXINIT (20)
      4. Client sends SSH_MSG_USERAUTH_REQUEST (50)
      5. Server responds with SSH_MSG_USERAUTH_FAILURE (51)
    """
    # Read client's version string (e.g. "SSH-2.0-OpenSSH_8.9")
    try:
        client.settimeout(3.0)
        client.recv(256)
    except (socket.timeout, OSError):
        return

    # Send SSH_MSG_KEXINIT — 16 bytes cookie + name-lists
    # Packet type 20, sequence 1
    kex_cookie = os.urandom(16)
    # Empty kex-algorithms, server-host-key-algorithms, etc (minimal valid)
    name_list = b""
    padding = b"\x00" * 8
    kex_payload = bytes([20]) + kex_cookie + (
        name_list + b"\x00" +   # kex_algorithms
        name_list + b"\x00" +   # server_host_key_algorithms
        name_list + b"\x00" +   # encryption_algorithms_client_to_server
        name_list + b"\x00" +   # encryption_algorithms_server_to_client
        name_list + b"\x00" +   # mac_algorithms_client_to_server
        name_list + b"\x00" +   # mac_algorithms_server_to_client
        name_list + b"\x00" +   # compression_algorithms_client_to_server
        name_list + b"\x00" +   # compression_algorithms_server_to_client
        name_list + b"\x00" +   # languages_client_to_server
        name_list + b"\x00" +   # languages_server_to_client
        b"\x00"                 # first_kex_packet_follows
    ) + b"\x00\x00\x00\x00" + padding  # reserved + padding

    # SSH packet: 4-byte length header (not including self) + padding
    pkt_len = len(kex_payload) + 1  # +1 for padding length byte
    padding_needed = (8 - (pkt_len % 8)) % 8
    if padding_needed < 4:
        padding_needed += 8
    total_len = pkt_len + padding_needed
    padding_len = padding_needed

    # Rewrite payload with correct padding length
    kex_payload = kex_payload[:-1]  # remove old padding_len
    header = struct.pack(">I", total_len + 4) + bytes([padding_len])
    full_pkt = header + kex_payload + os.urandom(padding_needed)

    try:
        client.sendall(full_pkt)
    except OSError:
        return

    # Wait for client's KEXINIT + USERAUTH_REQUEST
    try:
        client.settimeout(5.0)
        data = b""
        while len(data) < 256:
            chunk = client.recv(256)
            if not chunk:
                break
            data += chunk
            # Look for USERAUTH_REQUEST (type 50) in the stream
            if b"\x32" in data or len(data) > 200:
                break
    except (socket.timeout, OSError):
        return

    # Send SSH_MSG_USERAUTH_FAILURE (type 51)
    # bool partial_success (0) + name-list auth_methods
    auth_methods = b"publickey,password\0"
    fail_payload = bytes([51]) + b"\x00" + auth_methods
    fail_pkt_len = len(fail_payload) + 1
    fail_padding = (8 - (fail_pkt_len % 8)) % 8
    if fail_padding < 4:
        fail_padding += 8
    fail_total = fail_pkt_len + fail_padding
    fail_header = struct.pack(">I", fail_total + 4) + bytes([fail_padding])
    try:
        client.sendall(fail_header + fail_payload + os.urandom(fail_padding))
    except OSError:
        pass


def _mysql_auth_error(client, version):
    """After sending the MySQL greeting, read the client's login attempt
    and respond with a proper ERR packet (type 0xff). This forces nmap
    through the full MySQL handshake instead of just fingerprinting the
    greeting packet.

    MySQL protocol flow (after greeting):
      1. Server sends greeting (done before calling this)
      2. Client sends COM_QUIT or login packet
      3. Server responds with ERR packet
    """
    try:
        client.settimeout(5.0)
        client.recv(512)  # read client's login attempt
    except (socket.timeout, OSError):
        return

    # Build MySQL ERR packet (type 0xff)
    # Error code 1045 = "Access denied"
    # SQL state "28000"
    err_msg = b"Access denied for user\x00"
    err_payload = bytes([0xff]) + struct.pack("<H", 1045) + b"#" + b"28000" + err_msg
    err_header = struct.pack("<I", len(err_payload))[:3] + b"\x02"  # seq=2
    try:
        client.sendall(err_header + err_payload)
    except OSError:
        pass


# ---------------------------------------------------------------------------
# FTP / SMTP / PostgreSQL — speak enough real protocol so version scans name them
# ---------------------------------------------------------------------------

def _ftp_session(client, banner):
    """Answer nmap/curl FTP version probes with a plausible command loop.

    A bare 220 greeting is enough to suggest "ftp" but nmap marks the version
    as unconfirmed; answering USER/PASS/SYST/FEAT lets it classify it properly.
    """
    try:
        client.settimeout(6.0)
        client.sendall(f"220 {banner} ready.\r\n".encode())
    except OSError:
        return

    while True:
        line = _recv_line(client)
        if not line:
            return
        line = line.decode("ascii", errors="replace")
        parts = line.split(None, 1)
        verb = parts[0].upper()
        arg = parts[1].strip() if len(parts) > 1 else ""
        try:
            if verb in ("USER", "ACCT"):
                client.sendall(b"331 Password required.\r\n")
            elif verb == "PASS":
                client.sendall(b"230 Logged in.\r\n")
            elif verb == "SYST":
                client.sendall(b"215 UNIX Type: L8\r\n")
            elif verb == "FEAT":
                client.sendall(b"211-Features:\r\n EPRT\r\n EPSV\r\n MDTM\r\n PASV\r\n REST STREAM\r\n SIZE\r\n TVFS\r\n UTF8\r\n211 End\r\n")
            elif verb == "TYPE":
                client.sendall(f"200 Switching to {arg.upper()} mode.\r\n".encode())
            elif verb in ("PWD", "XPWD"):
                client.sendall(b'257 "/" is the current directory.\r\n')
            elif verb == "CWD":
                client.sendall(b"250 Directory successfully changed.\r\n")
            elif verb == "NOOP":
                client.sendall(b"200 NOOP ok.\r\n")
            elif verb == "HELP":
                client.sendall(b"214-The following commands are recognized.\r\n SIZE SYST TYPE PASV EPSV PWD CWD\r\n214 Help OK.\r\n")
            elif verb == "QUIT":
                client.sendall(b"221 Goodbye.\r\n")
                return
            else:
                client.sendall(b"502 Command not implemented.\r\n")
        except OSError:
            return


def _smtp_session(client, banner):
    """Answer SMTP EHLO/MAIL probes so nmap classifies the port, not just greets it."""
    try:
        client.settimeout(6.0)
        client.sendall(f"220 {banner} ESMTP\r\n".encode())
    except OSError:
        return

    while True:
        line = _recv_line(client).decode("ascii", errors="replace")
        if not line:
            return
        verb = line.split(None, 1)[0].upper() if line.split(None, 1) else line
        try:
            if verb == "EHLO":
                client.sendall(b"250-localhost\r\n250-AUTH LOGIN PLAIN\r\n250 PIPELINING\r\n")
            elif verb == "HELO":
                client.sendall(b"250 localhost\r\n")
            elif verb == "NOOP":
                client.sendall(b"250 OK\r\n")
            elif verb == "VRFY":
                client.sendall(b"252 Cannot VRFY user, but will accept message and attempt delivery\r\n")
            elif verb == "EXPN":
                client.sendall(b"550 No such mailing list\r\n")
            elif verb in ("MAIL", "RCPT"):
                client.sendall(b"250 2.1.0 OK\r\n")
            elif verb == "DATA":
                client.sendall(b"354 Start mail input; end with <CRLF>.<CRLF>\r\n")
            elif verb == "RSET":
                client.sendall(b"250 Reset OK\r\n")
            elif verb == "HELP":
                client.sendall(b"250 HELP\r\n")
            elif verb == "QUIT":
                client.sendall(b"221 Bye\r\n")
                return
            else:
                client.sendall(b"502 Command not recognized\r\n")
        except OSError:
            return


def _postgres_handshake(client, banner):
    """Speak enough of the PostgreSQL v3 startup to satisfy a version scan.

    A real server replies to the client's StartupMessage with AuthenticationOk /
    ParameterStatus / BackendKeyData / ReadyForQuery; we serve exactly that so
    nmap classifies the port as PostgreSQL instead of a bare banner. We decline
    TLS with 'N' (standard when the server doesn't offer it) and answer over
    plaintext. Backend pid/secret are random — never the host PID."""
    try:
        client.settimeout(5.0)
        length = _recv_exact(client, 4)
        if length is None:
            return
        msg_len = struct.unpack("!I", length)[0]
        if msg_len < 8 or msg_len > 4096:
            return
        code = _recv_exact(client, 4)
        if code is None:
            return
        if struct.unpack("!I", code)[0] == 80877103:
            # SSLRequest — decline TLS, then read the StartupMessage length.
            try:
                client.sendall(b"N")
            except OSError:
                return
            length = _recv_exact(client, 4)
            if length is None:
                return
            msg_len = struct.unpack("!I", length)[0]
            if msg_len < 4 or msg_len > 4096:
                return
            _recv_exact(client, msg_len - 4)  # drain StartupMessage params
        # else: code was the StartupMessage version (3.0). Remaining params stay
        # inbound but we don't need to drain them before answering — the client
        # is waiting for our response, not for us to acknowledge its params.
    except (OSError, struct.error):
        return

    m = re.search(r"(\d+\.\d+(?:\.\d+)?)", banner)
    version = m.group(1) if m else "15.5"

    def _msg(typ, payload):
        return typ + struct.pack("!I", len(payload) + 4) + payload

    resp = b""
    resp += _msg(b"R", struct.pack("!I", 0))                                  # AuthenticationOk
    resp += _msg(b"S", b"user\x00postgres\x00")                               # ParameterStatus user
    resp += _msg(b"S", b"database\x00postgres\x00")                           # database
    resp += _msg(b"S", b"server_version\x00" + version.encode() + b"\x00")
    resp += _msg(b"K", struct.pack("!II", secrets.randbits(32), secrets.randbits(32)))  # BackendKeyData
    resp += _msg(b"Z", b"I")                                                  # ReadyForQuery
    try:
        client.sendall(resp)
    except OSError:
        pass


# ---------------------------------------------------------------------------
# Decoy HTTP pages — realistic fake pages served by HTTP port responders
# ---------------------------------------------------------------------------

DECOY_PAGES = {
    "apache": (
        '<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">\n'
        "<html>\n<head>\n<title>Apache2 Ubuntu Default Page: It works</title>\n"
        "</head>\n<body>\n<h1>It works!</h1>\n"
        "<p>This is the default welcome page used by the Apache2 Ubuntu installation.</p>\n"
        "<p>It is based on the masssite content by the Apache Software Foundation.</p>\n"
        "</body>\n</html>\n"
    ),
    "nginx": (
        "<!DOCTYPE html>\n<html>\n<head>\n<title>Welcome to nginx!</title>\n"
        "<style>body{width:60em;margin:0 auto;font-family:Tahoma,Verdana,sans-serif;}\n"
        "h1{font-size:1.5em;color:#444;}</style>\n</head>\n<body>\n"
        "<h1>Welcome to nginx!</h1>\n"
        "<p>If you see this page, the nginx web server is successfully installed and working.</p>\n"
        "<p>For online documentation and support, refer to nginx.org.</p>\n"
        "</body>\n</html>\n"
    ),
    "tomcat": (
        "<!DOCTYPE html>\n<html>\n<head>\n<title>Apache Tomcat</title>\n"
        "</head>\n<body>\n"
        "<h2>If you see this page, the Tomcat web server is running.</h2>\n"
        "<p>Tomcat is an open source servlet container developed by the Apache Software Foundation.</p>\n"
        "</body>\n</html>\n"
    ),
    "iis": (
        '<!DOCTYPE html>\n<html>\n<head><title>IIS Windows Server</title></head>\n'
        '<body>\n<div style="text-align:center;margin-top:100px;">\n'
        '<h1 style="color:#0078D7;">Microsoft-IIS/10.0</h1>\n'
        "<p>The web server is running.</p>\n"
        "</div>\n</body>\n</html>\n"
    ),
    "generic": (
        "<!DOCTYPE html>\n<html>\n<head><title>Server</title></head>\n"
        "<body><h1>200 OK</h1><p>The server is operational.</p></body>\n</html>\n"
    ),
}


def _pick_decoy(banner):
    """Pick the best decoy page based on the service banner string."""
    b = banner.lower()
    if "apache" in b and "tomcat" not in b:
        return DECOY_PAGES["apache"]
    if "nginx" in b:
        return DECOY_PAGES["nginx"]
    if "tomcat" in b:
        return DECOY_PAGES["tomcat"]
    if "microsoft" in b or "iis" in b:
        return DECOY_PAGES["iis"]
    return DECOY_PAGES["generic"]


def _mysql_greeting(banner):
    """Build a minimal but protocol-correct MySQL server greeting packet.

    A plain-text line is not MySQL wire protocol — any version scan would
    immediately flag it as garbage. This speaks just enough of the protocol
    (protocol 10 handshake) to survive `nmap -sV`.
    """
    m = re.search(r"(\d+\.\d+\.\d+[^\s]*)", banner)
    version = m.group(1) if m else "8.0.35"
    salt = secrets.token_bytes(20)

    payload = bytes([0x0A]) + version.encode("ascii", "replace")[:32] + b"\x00"
    # thread/id: random, NOT os.getpid() — exposing the real PID lets a scanner
    # read a host-process beacon out of the greeting. Random also looks more
    # like a real MySQL connection id than a low system pid.
    payload += struct.pack("<I", secrets.randbits(32) & 0xFFFFFFFF)
    payload += salt[:8] + b"\x00"                            # auth-plugin-data-part-1
    caps = 0x00000001 | 0x00000200 | 0x00002000 | 0x00008000 | 0x00080000
    # LONG_PASSWORD | PROTOCOL_41 | TRANSACTIONS | SECURE_CONNECTION | PLUGIN_AUTH
    payload += struct.pack("<HBIHB", caps & 0xFFFF, 0x21, 0x0002, caps >> 16, 21)
    payload += b"\x00" * 10                                  # reserved
    payload += salt[8:20] + b"\x00"                          # auth-plugin-data-part-2
    payload += b"mysql_native_password\x00"

    header = struct.pack("<I", len(payload))[:3] + b"\x00"   # 3-byte length + seq 0
    return header + payload


# --- TLS for decoy ports ----------------------------------------------------

_tls_lock = threading.Lock()
_tls_context = None
_tls_unavailable = False


def _get_tls_context():
    """Lazily build an in-memory SSLContext with a throwaway self-signed cert.

    Real services on 443/8443 speak TLS — serving plaintext there is itself a
    fingerprint tell. Returns None if openssl isn't available (callers fall
    back to plaintext rather than leaving the port dead).
    """
    global _tls_context, _tls_unavailable
    if _tls_context is not None or _tls_unavailable:
        return _tls_context
    with _tls_lock:
        if _tls_context is not None or _tls_unavailable:
            return _tls_context
        try:
            import tempfile
            openssl = shutil.which("openssl")
            if not openssl:
                raise RuntimeError("openssl not found")
            with tempfile.TemporaryDirectory() as td:
                key_path = os.path.join(td, "key.pem")
                cert_path = os.path.join(td, "cert.pem")
                subprocess.run(
                    [openssl, "req", "-x509", "-newkey", "rsa:2048",
                     "-keyout", key_path, "-out", cert_path,
                     "-days", "3650", "-nodes", "-subj", "/CN=www.example.com"],
                    capture_output=True, timeout=60, check=True,
                )
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                ctx.load_cert_chain(cert_path, key_path)
            _tls_context = ctx
            logger.info("Generated self-signed certificate for TLS decoy ports (443/8443)")
        except Exception as e:  # noqa: BLE001 — any failure means "no TLS", never crash
            _tls_unavailable = True
            logger.warning(f"TLS decoys disabled ({e}); ports 443/8443 will serve plaintext")
        return _tls_context


# ---------------------------------------------------------------------------
# Connection Logger — records every probe hitting a spoofed port
# ---------------------------------------------------------------------------

class ConnectionLogger:
    """Stores recent connection events (capped at MAX_ENTRIES)."""

    MAX_ENTRIES = 500

    def __init__(self):
        self._entries = deque(maxlen=self.MAX_ENTRIES)
        self._lock = threading.Lock()
        self._counts = {}  # port -> count

    def log(self, source_ip, source_port, dest_port, service, blocked=False):
        entry = {
            "time": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "source_ip": source_ip,
            "source_port": source_port,
            "dest_port": dest_port,
            "service": service,
            "blocked": blocked,
        }
        with self._lock:
            self._entries.appendleft(entry)
            self._counts[dest_port] = self._counts.get(dest_port, 0) + 1

    def get_recent(self, limit=50):
        with self._lock:
            return list(self._entries)[:limit]

    def get_counts(self):
        with self._lock:
            return dict(self._counts)

    def count(self):
        with self._lock:
            return len(self._entries)

    def clear(self):
        with self._lock:
            self._entries.clear()
            self._counts.clear()


# ---------------------------------------------------------------------------
# Rate Limiter — blocks scanner IPs that probe too many unique ports
# ---------------------------------------------------------------------------

class RateLimiter:
    """
    Detects scanner behavior by tracking unique ports probed per IP.
    A legitimate user hits 1-3 ports. A scanner (nmap -p-) hits dozens.
    If an IP probes more than UNIQUE_PORTS_THRESHOLD unique ports within
    WINDOW_SECONDS, it gets temporarily blocked for BLOCK_DURATION seconds.

    Key design choices:
    - Only counts UNIQUE ports, not raw connections (a user hammering port 80 is fine)
    - Localhost is exempt (people test their nmap on themselves)
    - Blocks are temporary and self-expire
    - Only affects our spoofed ports, not real services on the machine
    - Blocked clients are accepted then immediately closed: the kernel has
      already completed the handshake before accept(), so the port still
      shows "open" — but no service banner is ever served. Probes from
      blocked IPs ARE logged (with blocked=true).
    """

    # Defaults — overridable via set_config()
    UNIQUE_PORTS_THRESHOLD = 10   # unique ports within window to trigger block
    WINDOW_SECONDS = 10           # time window to track
    BLOCK_DURATION = 300          # seconds to block (5 min)
    CLEANUP_INTERVAL = 60         # how often to purge expired entries

    def __init__(self):
        self._ip_ports = {}     # ip -> {port: timestamp, ...}
        self._blocked = {}      # ip -> unblock_time
        self._lock = threading.Lock()
        self._last_cleanup = time.time()
        # Configurable thresholds
        self.unique_ports_threshold = self.UNIQUE_PORTS_THRESHOLD
        self.window_seconds = self.WINDOW_SECONDS
        self.block_duration = self.BLOCK_DURATION

    def check(self, source_ip, dest_port):
        """
        Returns True if the connection is allowed, False if rate-limited.
        Only called from spoofed port handlers.
        """
        # Always allow localhost — users test their own setup
        if source_ip in ('127.0.0.1', '::1', '::ffff:127.0.0.1'):
            return True

        now = time.time()

        with self._lock:
            # Periodic cleanup of expired entries
            if now - self._last_cleanup > self.CLEANUP_INTERVAL:
                self._cleanup(now)
                self._last_cleanup = now

            # Check if currently blocked
            if source_ip in self._blocked:
                if now < self._blocked[source_ip]:
                    return False  # Still blocked
                else:
                    # Block expired — unblock and reset their port tracking
                    del self._blocked[source_ip]
                    self._ip_ports.pop(source_ip, None)
                    logger.info(f"Unblocked {source_ip} (block expired)")
                    return True

            # Track unique ports probed by this IP within the window
            if source_ip not in self._ip_ports:
                self._ip_ports[source_ip] = {}

            ports = self._ip_ports[source_ip]

            # Only count if this port hasn't been seen recently
            if dest_port not in ports or (now - ports[dest_port]) > self.window_seconds:
                ports[dest_port] = now

                # Prune old entries outside the window
                ports = {p: t for p, t in ports.items() if now - t < self.window_seconds}
                self._ip_ports[source_ip] = ports

                # Check threshold
                if len(ports) > self.unique_ports_threshold:
                    self._blocked[source_ip] = now + self.block_duration
                    logger.warning(
                        f"Rate-limited {source_ip}: {len(ports)} unique ports "
                        f"in {self.window_seconds}s — blocked for {self.block_duration}s"
                    )
                    return False

            return True

    def get_blocked_ips(self):
        """Return list of currently blocked IPs with remaining time."""
        now = time.time()
        with self._lock:
            blocked = []
            for ip, until in list(self._blocked.items()):
                if now < until:
                    blocked.append({"ip": ip, "remaining": int(until - now)})
                else:
                    del self._blocked[ip]
            return blocked

    def get_tracked_ips(self):
        """Return count of IPs being tracked."""
        with self._lock:
            return len(self._ip_ports)

    def unblock_ip(self, ip):
        """Manually unblock an IP."""
        with self._lock:
            self._blocked.pop(ip, None)
            self._ip_ports.pop(ip, None)

    def set_config(self, threshold=None, window=None, block_duration=None):
        """Update rate-limiting thresholds."""
        with self._lock:
            if threshold is not None:
                self.unique_ports_threshold = max(3, threshold)
            if window is not None:
                self.window_seconds = max(1, window)
            if block_duration is not None:
                self.block_duration = max(10, block_duration)

    def get_config(self):
        return {
            "unique_ports_threshold": self.unique_ports_threshold,
            "window_seconds": self.window_seconds,
            "block_duration": self.block_duration,
        }

    def _cleanup(self, now):
        """Remove expired tracking data."""
        # Clean expired port tracking
        for ip in list(self._ip_ports.keys()):
            ports = self._ip_ports[ip]
            ports = {p: t for p, t in ports.items() if now - t < self.window_seconds}
            if ports:
                self._ip_ports[ip] = ports
            else:
                del self._ip_ports[ip]
        # Clean expired blocks
        for ip in list(self._blocked.keys()):
            if now >= self._blocked[ip]:
                del self._blocked[ip]


# Singleton rate limiter
rate_limiter = RateLimiter()


# ---------------------------------------------------------------------------
# PortResponder — threaded TCP listener per spoofed port
#
# Lifecycle notes:
#   start_port() waits for the handler thread's bind() result before
#   reporting success, so callers never see a phantom "running" port.
#   stop_port() closes the listener socket and joins the thread, making
#   an immediate stop→start cycle safe.
# ---------------------------------------------------------------------------

class PortResponder:
    """Listens on spoofed ports and responds with fake service banners."""

    BIND_TIMEOUT = 3.0     # how long start_port waits for the bind result
    JOIN_TIMEOUT = 3.0     # how long stop_port waits for a handler to exit

    def __init__(self):
        self._threads = {}
        self._running = {}       # port -> bool (True only after successful bind)
        self._servers = {}       # port -> listener socket (closed to force exit)
        self._udp_sockets = {}   # port -> UDP socket (for DNS)
        self._bind_event = {}    # port -> Event set once bind outcome is known
        self._bind_success = {}  # port -> bool
        self._conn_slots = {}    # port -> Semaphore capping concurrent handlers
        self._lock = threading.RLock()
        self.conn_log = ConnectionLogger()

    def start_port(self, port, banner, wait=True):
        """Start a spoofed listener. Returns True only if it bound (or wait=False)."""
        port = int(port)
        banner = sanitize_banner(banner)
        with self._lock:
            if self._running.get(port, False):
                return False
            self._running[port] = False
            self._bind_success[port] = False
            self._bind_event[port] = binding_done = threading.Event()

        t = threading.Thread(
            target=self._listener_loop, args=(port, banner, binding_done),
            daemon=True, name=f"spoof-{port}",
        )
        t.start()
        with self._lock:
            self._threads[port] = t

        if wait:
            binding_done.wait(timeout=self.BIND_TIMEOUT)
            return self._bind_success.get(port, False)
        return True

    def _listener_loop(self, port, banner, binding_done):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        udp_sock = None
        try:
            try:
                server.bind(("0.0.0.0", port))
                server.listen(MAX_CONNECTIONS_PER_PORT)
            except OSError as e:
                in_use, hint = _port_in_use(port)
                if in_use and hint:
                    logger.error(f"Port {port} is occupied by a real service — "
                                 f"skipping spoof. {hint}")
                else:
                    logger.error(f"Failed to bind port {port}: {e}")
                with self._lock:
                    self._running[port] = False
                    self._bind_success[port] = False
                binding_done.set()
                server.close()
                return

            # DNS needs a UDP listener too — that's the primary transport.
            if port == DNS_PORT:
                try:
                    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    udp_sock.bind(("0.0.0.0", DNS_PORT))
                    with self._lock:
                        self._udp_sockets[port] = udp_sock
                    threading.Thread(
                        target=self._udp_dns_loop,
                        args=(udp_sock, banner, port),
                        daemon=True, name=f"spoof-{port}-udp",
                    ).start()
                except OSError as e:
                    logger.warning(f"UDP DNS listener failed on port {DNS_PORT}: {e} — "
                                   "TCP-only DNS spoofing active")

            server.settimeout(0.5)
            slots = threading.Semaphore(MAX_CONNECTIONS_PER_PORT)
            with self._lock:
                self._servers[port] = server
                self._running[port] = True
                self._bind_success[port] = True
                self._conn_slots[port] = slots
            binding_done.set()
            logger.info(f"Port spoof active: {port} → {banner}")

            while self._running.get(port, False):
                try:
                    client, addr = server.accept()
                except socket.timeout:
                    continue
                except OSError:
                    break  # socket closed — we're stopping

                source_ip, source_port = addr[0], addr[1]
                blocked = not rate_limiter.check(source_ip, port)
                # Log every probe, including denied ones (blocked=true)
                self.conn_log.log(source_ip, source_port, port, banner, blocked=blocked)

                if blocked:
                    # Tarpit: hold the connection open, trickling junk bytes.
                    # The scanner's TCP handshake already completed, so the port
                    # appears "open" — but every second wasted here is a second
                    # it isn't scanning your real services.
                    threading.Thread(
                        target=_tarpit_connection, args=(client, port),
                        daemon=True, name=f"tarpit-{port}",
                    ).start()
                    continue

                # Hand off to a per-client thread so one slow scanner can't
                # head-of-line-block other probes against the same port.
                if not slots.acquire(blocking=False):
                    try:
                        client.close()
                    except OSError:
                        pass
                    continue
                threading.Thread(
                    target=self._serve_client, args=(client, port, banner, slots),
                    daemon=True, name=f"spoof-{port}-client",
                ).start()
        finally:
            try:
                server.close()
            except OSError:
                pass
            with self._lock:
                if self._servers.get(port) is server:
                    self._servers.pop(port, None)
                    self._conn_slots.pop(port, None)

    def _udp_dns_loop(self, udp_sock, banner, port):
        """Handle UDP DNS queries in a dedicated loop."""
        while self._running.get(port, False):
            try:
                _dns_respond_udp(udp_sock, banner)
            except OSError:
                break
        try:
            udp_sock.close()
        except OSError:
            pass

    def _serve_client(self, client, port, banner, slots):
        try:
            client.settimeout(5.0)
            if port in TLS_PORTS:
                ctx = _get_tls_context()
                if ctx is not None:
                    # TLS handshake happens here; plain-HTTP probes fail and
                    # get closed, exactly like a real HTTPS endpoint.
                    client = ctx.wrap_socket(client, server_side=True)
            self._respond(client, port, banner)
        except (OSError, ssl.SSLError, socket.timeout):
            # Client went away / sent garbage / aborted handshake — normal
            pass
        finally:
            try:
                client.close()
            except OSError:
                pass
            slots.release()

    def _respond(self, client, port, banner):
        """Send a realistic service response based on port type.

        Banner strings are sanitized at start_port(), so they're safe to
        embed in headers here. Each connection gets a slightly varied banner
        and timing to break byte-identical fingerprinting patterns.
        """
        # Small timing jitter simulates natural server variance
        _banner_jitter()

        if port in HTTP_PORTS:
            request = self._read_http_request(client)
            if not request:
                # Real web servers send nothing until the client asks.
                return
            self._send_http_response(client, banner, head_only=request.startswith(b"HEAD"))
        elif port == 22:
            # SSH servers greet first — sending immediately is correct here.
            varied = _banner_variance(banner, client.getpeername()[1])
            client.sendall(f"SSH-2.0-{varied}\r\n".encode())
            # Force scanner through a full handshake — respond to their
            # KEXINIT and answer auth attempts with USERAUTH_FAILURE.
            _ssh_auth_failure(client)
        elif port == 21:
            _ftp_session(client, banner)
        elif port == 25:
            _smtp_session(client, banner)
        elif port == 5432:
            _postgres_handshake(client, banner)
        elif port == 3306:
            client.sendall(_mysql_greeting(banner))
            # Read the client's login attempt and respond with a proper
            # ERR packet so nmap can't just fingerprint the greeting alone.
            _mysql_auth_error(client, banner)
        elif port == 3389:
            # RDP: client sends an X.224 connection request first. We don't
            # speak full RDP — read briefly like a busy terminal server, then
            # let the connection close.
            try:
                client.settimeout(1.0)
                client.recv(4096)
            except (socket.timeout, OSError):
                pass
        elif port == DNS_PORT:
            # TCP DNS: length-prefixed messages (RFC 1035 section 4.2.2).
            # Speak real wire protocol instead of a plaintext banner.
            _dns_respond_tcp(client, banner)
        else:
            client.sendall(f"{banner}\r\n".encode())

    @staticmethod
    def _read_http_request(client):
        """Read until end of headers (or timeout/size cap). Empty → client said nothing."""
        data = b""
        while b"\r\n\r\n" not in data and len(data) < 8192:
            try:
                chunk = client.recv(4096)
            except (socket.timeout, OSError):
                break
            if not chunk:
                break
            data += chunk
        return data

    @staticmethod
    def _send_http_response(client, banner, head_only=False):
        body = _pick_decoy(banner).encode("utf-8")
        headers = (
            f"HTTP/1.1 200 OK\r\n"
            f"Server: {banner}\r\n"
            f"Content-Type: text/html; charset=UTF-8\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        ).encode("ascii")
        client.sendall(headers if head_only else headers + body)

    def stop_port(self, port):
        """Stop a spoofed listener and wait for its thread to exit."""
        port = int(port)
        with self._lock:
            self._running[port] = False
            server = self._servers.pop(port, None)
            udp_sock = self._udp_sockets.pop(port, None)
            thread = self._threads.pop(port, None)
            self._bind_event.pop(port, None)
            self._bind_success.pop(port, None)
            self._conn_slots.pop(port, None)
        if server is not None:
            try:
                server.close()  # unblocks accept() immediately
            except OSError:
                pass
        if udp_sock is not None:
            try:
                udp_sock.close()
            except OSError:
                pass
        if thread is not None and thread.is_alive():
            thread.join(timeout=self.JOIN_TIMEOUT)
        return True

    def stop_all(self):
        with self._lock:
            ports = list(self._running.keys())
        for port in ports:
            self.stop_port(port)

    def is_running(self, port):
        port = int(port)
        with self._lock:
            return self._running.get(port, False)

    def get_running_ports(self):
        with self._lock:
            return sorted(p for p, r in self._running.items() if r)


# ---------------------------------------------------------------------------
# OSFingerprinter — iptables / ip6tables TTL / MSS / HL manipulation
#
# Uses iptables mangle table to rewrite outgoing packet headers so that
# remote scanners (NMAP etc.) see a different OS fingerprint.
#
# Three techniques:
#   1. TTL spoofing — rewrites the IPv4 TTL field to match the target OS.
#      NMAP's OS detection relies heavily on TTL (128=Windows, 64=Linux/macOS).
#   2. MSS spoofing — rewrites the TCP MSS option in SYN-ACK packets to
#      match the target OS's typical MSS value. NMAP checks this as one of
#      its fingerprint data points.
#   3. IPv6 Hop Limit spoofing — rewrites the IPv6 Hop Limit field via
#      ip6tables HL module. Dual-stack hosts leak their real fingerprint
#      over v6 without this.
#
# NOTE: iptables cannot directly modify the TCP window size header field.
# The advertised window size is set by the kernel's TCP stack and is not
# mangleable via iptables. TTL/MSS + HL together cover the most heavily
# weighted OS fingerprint fields across both IP versions.
#
# CAVEATS (documented in README too):
#   - Rules apply to ALL outgoing traffic, so traceroute/mtr results and
#     TTL-based CDN routing will reflect the spoofed TTL.
#   - IPv6 spoofing requires ip6tables (Linux only, not available on macOS).
# ---------------------------------------------------------------------------

class OSFingerprinter:
    """Manipulates OS fingerprinting via iptables/ip6tables TTL, HL, and MSS spoofing."""

    def __init__(self):
        self._enabled = False
        self._current_profile = None
        # RLock: enable() calls disable() while holding the lock — a plain
        # Lock deadlocked here whenever OS spoofing was enabled twice.
        self._lock = threading.RLock()

    def enable(self, profile):
        """Enable OS fingerprint spoofing with given profile."""
        with self._lock:
            if self._enabled:
                self.disable()

            if not _config.IS_LINUX:
                msg = f"OS spoofing is only supported on Linux (current: {__import__('platform').system()})"
                logger.warning(msg)
                return False, msg
            if not _config.HAS_IPTABLES:
                msg = "OS spoofing requires iptables — not found on this system"
                logger.warning(msg)
                return False, msg

            prof = _config.OS_PROFILES.get(profile)
            if not prof:
                return False, f"Unknown profile: {profile}"

            try:
                # Rule 1: Set outgoing TTL to match target OS
                self._run_iptables([
                    "-t", "mangle", "-A", "POSTROUTING",
                    "-j", "TTL", "--ttl-set", str(prof["ttl"]),
                    "-m", "comment", "--comment", _IPTABLES_COMMENT,
                ])

                # Rule 2: Rewrite TCP MSS option in SYN-ACK packets
                # to match the target OS's typical MSS value.
                # NMAP's OS fingerprint database includes MSS as a data point.
                mss = prof.get("mss", 1460)
                self._run_iptables([
                    "-t", "mangle", "-A", "POSTROUTING",
                    "-p", "tcp", "--tcp-flags", "SYN,ACK", "SYN,ACK",
                    "-j", "TCPMSS", "--mss", str(mss),
                    "-m", "comment", "--comment", _IPTABLES_COMMENT,
                ])

                # IPv6 rules — close the dual-stack leak if ip6tables is available
                if _config.HAS_IP6TABLES:
                    # Rule 3: Set outgoing Hop Limit to match target OS
                    self._run_ip6tables([
                        "-t", "mangle", "-A", "POSTROUTING",
                        "-j", "HL", "--hl-set", str(prof["ttl"]),
                        "-m", "comment", "--comment", _IPTABLES_COMMENT,
                    ])
                    # Rule 4: Rewrite TCP MSS in SYN-ACK (ip6tables TCPMSS)
                    self._run_ip6tables([
                        "-t", "mangle", "-A", "POSTROUTING",
                        "-p", "tcp", "--tcp-flags", "SYN,ACK", "SYN,ACK",
                        "-j", "TCPMSS", "--mss", str(mss),
                        "-m", "comment", "--comment", _IPTABLES_COMMENT,
                    ])

                self._enabled = True
                self._current_profile = profile
                ipv6_note = " + IPv6 HL" if _config.HAS_IP6TABLES else ""
                logger.info(f"OS fingerprint spoofing enabled: {prof['name']}{ipv6_note}")
                return True, f"OS spoofing as {prof['name']}{ipv6_note}"
            except Exception as e:  # noqa: BLE001 — iptables may fail in many ways; must clean up partial state
                # If partially applied, clean up what we can
                self._cleanup_iptables_rules()
                self._cleanup_ip6tables_rules()
                self._enabled = False
                self._current_profile = None
                logger.error(f"Failed to enable OS spoofing: {e}")
                return False, str(e)

    def disable(self):
        """Disable OS fingerprint spoofing by removing only our rules."""
        with self._lock:
            self._cleanup_iptables_rules()
            self._cleanup_ip6tables_rules()
            self._enabled = False
            self._current_profile = None
            logger.info("OS fingerprint spoofing disabled")
            return True, "OS spoofing disabled"

    def _cleanup_iptables_rules(self):
        """Remove only the iptables rules tagged with our comment.

        Unlike flushing the POSTROUTING chain (which would destroy rules from
        VPNs, Docker, etc.), this removes exactly the rules we created.
        Preferred path enumerates them precisely via iptables-save; the
        fallback covers stale rules from older sessions / missing iptables-save.
        """
        if not self._cleanup_by_rule_listing():
            self._cleanup_by_known_values()

    def _cleanup_by_rule_listing(self):
        """Delete every mangle rule carrying our comment, discovered live."""
        try:
            result = subprocess.run(
                ["iptables-save", "-t", "mangle"],
                capture_output=True, text=True, timeout=10, check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            return False
        if result.returncode != 0:
            return False

        found_any = False
        for line in result.stdout.splitlines():
            line = line.strip()
            # Match rules tagged with our prefix (nf-<hex>) or the legacy
            # hardcoded name from older versions.
            if line.startswith("-A ") and (
                _IPTABLES_PREFIX in line or "smudged-lens-spoof" in line
            ):
                spec = line[len("-A "):].split()
                self._run_iptables(["-t", "mangle", "-D"] + spec, check=False)
                found_any = True
        return found_any

    def _cleanup_by_known_values(self):
        """Fallback: delete rules matching historically used values.

        Used when iptables-save is unavailable. Tries both the current
        session tag and the legacy hardcoded tag from older versions.
        """
        legacy_comment = "smudged-lens-spoof"
        for comment in (_IPTABLES_COMMENT, legacy_comment):
            for ttl_val in ("128", "64"):
                self._run_iptables([
                    "-t", "mangle", "-D", "POSTROUTING",
                    "-j", "TTL", "--ttl-set", ttl_val,
                    "-m", "comment", "--comment", comment,
                ], check=False)

            for _ in range(10):
                result = self._run_iptables([
                    "-t", "mangle", "-D", "POSTROUTING",
                    "-p", "tcp", "--tcp-flags", "SYN,ACK", "SYN,ACK",
                    "-j", "TCPMSS", "--mss", "1460",
                    "-m", "comment", "--comment", comment,
                ], check=False)
                if result.returncode != 0:
                    break

    # -- IPv6 (ip6tables) ---------------------------------------------------

    def _run_ip6tables(self, args, check=True):
        cmd = ["ip6tables"] + args
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10, check=False)
        except FileNotFoundError:
            if check:
                raise RuntimeError("ip6tables not found on this system")
            class _DummyResult:
                returncode = 1
                stderr = "ip6tables not found"
            return _DummyResult()
        if check and result.returncode != 0:
            raise RuntimeError(f"ip6tables failed: {result.stderr.strip()}")
        return result

    def _cleanup_ip6tables_rules(self):
        """Remove ip6tables rules tagged with our comment."""
        if not _config.HAS_IP6TABLES:
            return
        if not self._cleanup_ip6tables_by_rule_listing():
            self._cleanup_ip6tables_by_known_values()

    def _cleanup_ip6tables_by_rule_listing(self):
        """Delete every mangle rule carrying our comment, discovered live."""
        try:
            result = subprocess.run(
                ["ip6tables-save", "-t", "mangle"],
                capture_output=True, text=True, timeout=10, check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            return False
        if result.returncode != 0:
            return False

        found_any = False
        for line in result.stdout.splitlines():
            line = line.strip()
            if line.startswith("-A ") and (
                _IPTABLES_PREFIX in line or "smudged-lens-spoof" in line
            ):
                spec = line[len("-A "):].split()
                self._run_ip6tables(["-t", "mangle", "-D"] + spec, check=False)
                found_any = True
        return found_any

    def _cleanup_ip6tables_by_known_values(self):
        """Fallback: delete ip6tables rules matching historically used values."""
        legacy_comment = "smudged-lens-spoof"
        for comment in (_IPTABLES_COMMENT, legacy_comment):
            for hl_val in ("128", "64"):
                self._run_ip6tables([
                    "-t", "mangle", "-D", "POSTROUTING",
                    "-j", "HL", "--hl-set", hl_val,
                    "-m", "comment", "--comment", comment,
                ], check=False)

            for _ in range(10):
                result = self._run_ip6tables([
                    "-t", "mangle", "-D", "POSTROUTING",
                    "-p", "tcp", "--tcp-flags", "SYN,ACK", "SYN,ACK",
                    "-j", "TCPMSS", "--mss", "1460",
                    "-m", "comment", "--comment", comment,
                ], check=False)
                if result.returncode != 0:
                    break

    def is_enabled(self):
        return self._enabled

    def get_current_profile(self):
        return self._current_profile

    def _run_iptables(self, args, check=True):
        cmd = ["iptables"] + args
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10, check=False)
        except FileNotFoundError:
            if check:
                raise RuntimeError("iptables not found on this system")
            # When check=False (cleanup), silently ignore missing iptables
            class _DummyResult:
                returncode = 1
                stderr = "iptables not found"
            return _DummyResult()
        if check and result.returncode != 0:
            raise RuntimeError(f"iptables failed: {result.stderr.strip()}")
        return result


# ---------------------------------------------------------------------------
# Singleton instances
# ---------------------------------------------------------------------------

port_responder = PortResponder()
os_fingerprinter = OSFingerprinter()


# ---------------------------------------------------------------------------
# State restore + exit cleanup
# ---------------------------------------------------------------------------

def restore_state(config, auto_port_sets=None):
    """Re-apply persisted spoofing state (used by app.py and `cli.py serve`).

    When *auto_port_sets* is provided (the AUTO_PORT_SETS dict from app.py),
    only ports that belong to the current profile are restored. This prevents
    stale ports from a previous profile (e.g. SSH from centos) leaking through
    after switching to a profile that doesn't include them (e.g. windows11).
    """
    started = []
    if config.get("port_spoofing_enabled"):
        # Build the set of valid ports for the current profile
        valid_ports = None
        if auto_port_sets:
            profile = config.get("os_profile", "windows11")
            valid_ports = {str(p) for p, _ in auto_port_sets.get(profile, [])}

        for port, cfg in config.get("spoofed_ports", {}).items():
            if not cfg.get("enabled", False):
                continue
            # Skip ports that don't belong to the current profile
            if valid_ports is not None and port not in valid_ports:
                continue
            if port_responder.start_port(port, cfg.get("service", "")):
                started.append(int(port))
            else:
                logger.warning(f"Could not restore spoofed port {port}")
        if started:
            logger.info(f"Restored port spoofing state: {sorted(started)}")

    if config.get("os_spoofing_enabled") and _config.IS_LINUX and _config.HAS_IPTABLES and _config.is_root():
        success, msg = os_fingerprinter.enable(config.get("os_profile", "windows11"))
        if success:
            logger.info("Restored OS fingerprint spoofing")
        else:
            logger.warning(f"Failed to restore OS spoofing: {msg}")


def _cleanup_on_exit(signum=None, frame=None):
    """Remove iptables rules we added. Safe to call multiple times."""
    if os_fingerprinter.is_enabled():
        logger.info("Cleaning up iptables rules on exit...")
        os_fingerprinter.disable()


atexit.register(_cleanup_on_exit)


def install_exit_handlers():
    """Install SIGINT/SIGTERM handlers that clean up, then terminate properly.

    Deliberately NOT called at import time — importing this module must have
    no side effects. The old import-time handlers also swallowed Ctrl+C
    entirely: they returned without exiting, so nothing ever stopped.
    """
    def _handle(signum, frame):
        _cleanup_on_exit()
        signal.signal(signum, signal.SIG_DFL)
        os.kill(os.getpid(), signum)  # re-raise for correct exit code

    signal.signal(signal.SIGINT, _handle)
    signal.signal(signal.SIGTERM, _handle)
