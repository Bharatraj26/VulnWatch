"""
VulnWatch Scanner — Target Validation & SSRF Prevention
=======================================================
Restricts scanning strictly to localhost, loopback addresses, and explicitly
configured authorized targets. Prevents SSRF attacks, DNS rebinding, alternative
IP obfuscations, restricted port access, and redirect bypasses.
"""

from __future__ import annotations

import http.client
import ipaddress
import socket
import urllib.parse
import urllib.request
from typing import ClassVar

# Ports commonly restricted to prevent SSRF and protocol smuggling/confusion attacks
PROHIBITED_PORTS = frozenset({
    1,     # tcpmux
    7,     # echo
    9,     # discard
    11,    # systat
    13,    # daytime
    15,    # netstat
    17,    # qotd
    19,    # chargen
    20,    # ftp data
    21,    # ftp control
    22,    # ssh
    23,    # telnet
    25,    # smtp
    37,    # time
    42,    # name
    43,    # nicname
    53,    # domain (dns)
    77,    # rje
    79,    # finger
    87,    # link
    95,    # supdup
    101,   # hostname
    102,   # iso-tsap
    103,   # gppitnp
    104,   # acr-nema
    109,   # pop2
    110,   # pop3
    111,   # sunrpc
    113,   # auth
    115,   # sftp
    117,   # uucp-path
    119,   # nntp
    123,   # ntp
    135,   # epmap / msrpc
    139,   # netbios-ssn
    143,   # imap
    179,   # bgp
    389,   # ldap
    445,   # microsoft-ds (smb)
    465,   # smtps
    512,   # print / rexec
    513,   # login / rlogin
    514,   # shell / syslog
    515,   # printer
    526,   # tempo
    530,   # courier
    531,   # chat
    532,   # netnews
    540,   # uucp
    556,   # remotefs
    563,   # nntps
    587,   # submission
    601,   # syslog
    636,   # ldaps
    993,   # imaps
    995,   # pop3s
    2049,  # nfs
    3389,  # rdp
    3659,  # apple-sasl
    4045,  # lockd
    6000,  # x11
    6665, 6666, 6667, 6668, 6669,  # irc
})


class TargetValidationError(ValueError):
    """Raised when a scan target violates authorization or security policies."""


def is_obfuscated_ip(hostname: str) -> tuple[bool, str]:
    """
    Detect non-canonical or obfuscated IP address representations:
    integer/dword (2130706433), hex (0x7f000001), octal (0177.0.0.1),
    leading zeros (127.00.0.1), shortened IPs (127.1), or octet overflow.
    """
    clean_host = hostname.strip().lower()

    # Hex prefix anywhere in host
    if "0x" in clean_host:
        return True, "Hexadecimal IP representation is not permitted."

    # Pure integer / dword representation
    if clean_host.isdigit():
        return True, "Integer/DWORD IP representation is not permitted."

    parts = clean_host.split(".")
    # If all parts are numeric
    if all(p.isdigit() for p in parts) and len(parts) > 0:
        if len(parts) in (1, 2, 3):
            return True, "Shortened non-canonical IP notation is not permitted."
        if len(parts) == 4:
            for p in parts:
                if len(p) > 1 and p.startswith("0"):
                    return True, "Octal notation or leading zeros in IP octets are not permitted."
                try:
                    val = int(p)
                    if val < 0 or val > 255:
                        return True, "IP octet value out of range (0-255)."
                except ValueError:
                    return True, "Invalid IP octet value."

    return False, ""


def is_authorized_ip(ip_str: str, allowed_targets: list[str] | None = None) -> bool:
    """
    Check if an IP address belongs to loopback or an explicitly authorized targets allowlist.
    Strictly rejects link-local (cloud metadata 169.254.169.254), multicast,
    unspecified (0.0.0.0), and non-loopback private networks.
    """
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False

    # Link-local / cloud metadata (169.254.0.0/16, fe80::/10) is ALWAYS prohibited
    if ip.is_link_local:
        return False

    # Inspect IPv4-mapped IPv6 addresses (e.g. ::ffff:127.0.0.1)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        mapped_ipv4 = ip.ipv4_mapped
        if mapped_ipv4.is_link_local or mapped_ipv4.is_multicast or mapped_ipv4.is_unspecified or mapped_ipv4.is_reserved:
            return False
        if mapped_ipv4.is_loopback:
            return True
        return bool(allowed_targets and str(mapped_ipv4) in allowed_targets)

    # Loopback addresses (127.0.0.0/8, ::1) are authorized by default
    if ip.is_loopback:
        return True

    # If allowed_targets specifies exact IP, check it (excluding link-local)
    if allowed_targets and ip_str.lower() in [t.lower() for t in allowed_targets]:
        return True

    # Disallow multicast, unspecified (0.0.0.0), and reserved ranges
    if ip.is_multicast or ip.is_unspecified or ip.is_reserved:
        return False

    # Disallow non-loopback private networks (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) unless allowlisted
    if ip.is_private:
        return False

    return False


def validate_target_url(
    url: str,
    allowed_targets: list[str] | None = None,
) -> tuple[str, str, int]:
    """
    Validate target URL server-side against authorization, SSRF, and safety policies.
    Returns (normalized_url, resolved_primary_ip, port).

    Raises TargetValidationError if the URL is invalid, unauthorized, or dangerous.
    """
    if not url or not isinstance(url, str):
        raise TargetValidationError("Target URL must be a non-empty string.")

    url = url.strip()
    if len(url) > 2048:
        raise TargetValidationError("Target URL exceeds maximum allowed length of 2048 characters.")

    try:
        parsed = urllib.parse.urlsplit(url)
    except Exception as exc:
        raise TargetValidationError(f"Invalid URL structure: {exc}") from exc

    if parsed.scheme.lower() not in ("http", "https"):
        raise TargetValidationError(
            f"Unsupported protocol scheme '{parsed.scheme}'. Only HTTP and HTTPS are permitted."
        )

    if not parsed.hostname:
        raise TargetValidationError("Target URL must include a valid hostname or IP address.")

    if len(parsed.hostname) > 253:
        raise TargetValidationError("Target hostname exceeds maximum RFC 1035 length (253 characters).")

    if parsed.username or parsed.password:
        raise TargetValidationError("URLs with embedded user credentials are not permitted.")

    hostname = parsed.hostname.lower()

    # Detect alternative or obfuscated IP representations
    is_obf, obf_reason = is_obfuscated_ip(hostname)
    if is_obf:
        raise TargetValidationError(f"Prohibited IP format '{hostname}': {obf_reason}")

    # Port extraction and boundary validation
    try:
        port = parsed.port if parsed.port is not None else (443 if parsed.scheme.lower() == "https" else 80)
    except ValueError as exc:
        raise TargetValidationError(f"Invalid port number in target URL: {exc}") from exc

    if port < 1 or port > 65535:
        raise TargetValidationError(f"Invalid port number {port}. Port must be between 1 and 65535.")

    if port in PROHIBITED_PORTS:
        raise TargetValidationError(
            f"Port {port} is a restricted system service port and cannot be scanned."
        )

    allowed_list = [t.lower() for t in (allowed_targets or ["localhost", "127.0.0.1", "::1"])]

    # Quick pre-validation for direct IP literals (avoids unnecessary DNS resolution)
    try:
        direct_ip = ipaddress.ip_address(hostname)
        if not is_authorized_ip(str(direct_ip), allowed_list):
            raise TargetValidationError(
                f"Scanning prohibited: destination IP '{hostname}' is not authorized. "
                "Only local loopback applications (localhost / 127.0.0.1 / ::1) are permitted."
            )
        resolved_ips = [str(direct_ip)]
    except ValueError:
        # Not a direct IP literal; resolve hostname via socket.getaddrinfo
        try:
            addr_info = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
        except socket.gaierror as exc:
            raise TargetValidationError(f"Could not resolve target hostname '{hostname}': {exc}") from exc

        if not addr_info:
            raise TargetValidationError(f"No IP addresses resolved for hostname '{hostname}'.")

        resolved_ips = list({info[4][0] for info in addr_info})

    # Ensure EVERY resolved IP is an authorized target (prevents multi-IP / DNS rebinding split)
    for resolved_ip in resolved_ips:
        if not is_authorized_ip(resolved_ip, allowed_list):
            raise TargetValidationError(
                f"Scanning prohibited: '{hostname}' resolves to unauthorized destination {resolved_ip}. "
                "Only local loopback applications (localhost / 127.0.0.1 / ::1) are permitted."
            )

    # Format netloc safely with brackets for IPv6 hostnames
    host_for_netloc = (
        f"[{parsed.hostname}]"
        if (":" in parsed.hostname and not parsed.hostname.startswith("["))
        else parsed.hostname
    )
    netloc = f"{host_for_netloc}:{port}" if parsed.port else host_for_netloc

    normalized_url = urllib.parse.urlunsplit((
        parsed.scheme.lower(),
        netloc,
        parsed.path or "/",
        parsed.query,
        "",
    ))

    primary_ip = resolved_ips[0]
    return normalized_url, primary_ip, port


class SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    """
    Custom redirect handler that validates target destination before following.
    Prevents open redirect SSRF attacks, protocol downgrades, and redirect loops.
    """

    def __init__(
        self,
        allowed_targets: list[str] | None = None,
        max_redirects: int = 3,
        verified_hosts: dict[str, str] | None = None,
    ):
        super().__init__()
        self.allowed_targets = allowed_targets or ["localhost", "127.0.0.1", "::1"]
        self.max_redirects = max_redirects
        self.redirect_count = 0
        self.verified_hosts = verified_hosts if verified_hosts is not None else {}

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        self.redirect_count += 1
        if self.redirect_count > self.max_redirects:
            raise TargetValidationError(f"Exceeded maximum allowed redirects ({self.max_redirects}).")

        # Resolve relative redirects against request full URL
        resolved_newurl = urllib.parse.urljoin(req.full_url, newurl)

        # Disallow HTTPS -> HTTP protocol downgrade
        orig_scheme = urllib.parse.urlsplit(req.full_url).scheme.lower()
        new_scheme = urllib.parse.urlsplit(resolved_newurl).scheme.lower()
        if orig_scheme == "https" and new_scheme == "http":
            raise TargetValidationError(
                "Insecure protocol downgrade from HTTPS to HTTP during redirect is prohibited."
            )

        # Validate the new URL against authorization and SSRF policies
        normalized_url, resolved_ip, _port = validate_target_url(
            resolved_newurl, self.allowed_targets
        )
        new_host = urllib.parse.urlsplit(normalized_url).hostname
        if new_host:
            self.verified_hosts[new_host.lower()] = resolved_ip

        return super().redirect_request(req, fp, code, msg, headers, resolved_newurl)


class PinnedHTTPConnection(http.client.HTTPConnection):
    """HTTPConnection that connects directly to pre-verified IP to eliminate DNS rebinding."""

    verified_hosts: ClassVar[dict[str, str]] = {}

    def connect(self) -> None:
        connect_host = self.verified_hosts.get(self.host.lower(), self.host)
        self.sock = socket.create_connection(
            (connect_host, self.port), self.timeout, self.source_address
        )


class PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPSConnection that connects directly to pre-verified IP with SNI preservation."""

    verified_hosts: ClassVar[dict[str, str]] = {}

    def connect(self) -> None:
        connect_host = self.verified_hosts.get(self.host.lower(), self.host)
        self.sock = socket.create_connection(
            (connect_host, self.port), self.timeout, self.source_address
        )
        server_hostname = self._tunnel_host if self._tunnel_host else self.host
        self.sock = self._context.wrap_socket(self.sock, server_hostname=server_hostname)


class PinnedHTTPHandler(urllib.request.HTTPHandler):
    """Urllib HTTP handler using PinnedHTTPConnection."""

    def __init__(self, verified_hosts: dict[str, str]):
        super().__init__()
        self.verified_hosts = verified_hosts

    def http_open(self, req: urllib.request.Request) -> http.client.HTTPResponse:
        conn_cls = type(
            "PinnedConn",
            (PinnedHTTPConnection,),
            {"verified_hosts": self.verified_hosts},
        )
        return self.do_open(conn_cls, req)


class PinnedHTTPSHandler(urllib.request.HTTPSHandler):
    """Urllib HTTPS handler using PinnedHTTPSConnection."""

    def __init__(self, verified_hosts: dict[str, str]):
        super().__init__()
        self.verified_hosts = verified_hosts

    def https_open(self, req: urllib.request.Request) -> http.client.HTTPResponse:
        conn_cls = type(
            "PinnedSecureConn",
            (PinnedHTTPSConnection,),
            {"verified_hosts": self.verified_hosts},
        )
        return self.do_open(conn_cls, req)


def build_safe_opener(
    target_ip: str,
    hostname: str,
    allowed_targets: list[str] | None = None,
    max_redirects: int = 3,
) -> urllib.request.OpenerDirector:
    """
    Build a hardened urllib opener configured with pre-resolved IP pinning,
    safe redirect inspection, and DNS rebinding immunity.
    """
    verified_hosts = {hostname.lower(): target_ip}
    redirect_handler = SafeRedirectHandler(
        allowed_targets=allowed_targets,
        max_redirects=max_redirects,
        verified_hosts=verified_hosts,
    )
    http_handler = PinnedHTTPHandler(verified_hosts)
    https_handler = PinnedHTTPSHandler(verified_hosts)
    return urllib.request.build_opener(redirect_handler, http_handler, https_handler)

