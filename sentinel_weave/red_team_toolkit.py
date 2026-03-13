"""
Red-Team Toolkit — SentinelWeave
=================================

Authorized-use offensive security tools that complement SentinelWeave's
defensive capabilities.  These modules are designed for **penetration testers,
security researchers, and red-team operators** who have *explicit written
authorization* to test the target systems.

.. warning::
    Use of these tools against systems you do not own or do not have explicit
    written permission to test may be illegal under the Computer Fraud and
    Abuse Act (CFAA), the UK Computer Misuse Act, and equivalent legislation
    in other jurisdictions.  Always obtain written authorization before
    performing any security testing.

Components
----------
* :class:`PortScanner` — TCP-connect port scanner with configurable port
  ranges and timeouts.  Returns :class:`PortScanResult` objects with service
  guesses based on well-known port assignments.
* :class:`ServiceFingerprinter` — Grabs TCP banners from open ports to
  identify service names, versions, and underlying software.
* :class:`VulnerabilityAssessor` — Maps service banner strings against a
  curated pattern library of known-vulnerable versions and CVE references.
  Returns :class:`VulnerabilityFinding` objects suitable for report generation.
* :class:`CredentialAuditor` — Analyses password strings for entropy,
  complexity, and common-credential patterns.  Does **not** transmit
  credentials anywhere.
* :class:`ReconScanner` — Passive reconnaissance using only the Python
  standard library: DNS forward/reverse lookups, hostname resolution, and
  basic service metadata gathering.

All classes are implemented with the Python standard library only (``socket``,
``ssl``, ``hashlib``, ``re``, ``math``, ``ipaddress``) so no third-party
packages are required.

Example usage::

    from sentinel_weave.red_team_toolkit import PortScanner, VulnerabilityAssessor

    # Scan a host for common web/admin ports
    scanner = PortScanner(timeout=1.0)
    results = scanner.scan("192.168.1.1", ports=[22, 80, 443, 8080, 8443])
    for r in results:
        if r.is_open:
            print(r.port, r.service_hint, r.banner)

    # Cross-reference open services with known CVE patterns
    assessor = VulnerabilityAssessor()
    for r in results:
        if r.is_open and r.banner:
            findings = assessor.assess(r.banner)
            for f in findings:
                print(f.cve_id, f.severity, f.description)
"""

from __future__ import annotations

import hashlib
import ipaddress
import math
import re
import socket
import ssl
from collections import Counter
from dataclasses import dataclass, field
from typing import Optional


# ===========================================================================
# Data structures
# ===========================================================================

@dataclass
class PortScanResult:
    """
    Result for a single port probe.

    Attributes:
        host:         Target hostname or IP address.
        port:         TCP port number probed.
        is_open:      *True* when a full TCP handshake was established.
        service_hint: Well-known service name derived from port number, e.g.
                      ``"SSH"``, ``"HTTP"``, ``"HTTPS"``.
        banner:       First few bytes of the server banner received on connect
                      (empty string if none was received or port is closed).
        error:        Exception message if the probe failed unexpectedly.
    """
    host: str
    port: int
    is_open: bool = False
    service_hint: str = "UNKNOWN"
    banner: str = ""
    error: str = ""


@dataclass
class ServiceFingerprintResult:
    """
    Result of banner-based service fingerprinting on a single host:port.

    Attributes:
        host:            Target hostname or IP address.
        port:            TCP port probed.
        raw_banner:      The raw bytes received (decoded to str, lossy).
        service_name:    Detected service name (e.g. ``"OpenSSH"``,
                         ``"Apache httpd"``).
        service_version: Version string if extractable from the banner.
        os_hint:         Operating-system hint derived from banner tokens.
    """
    host: str
    port: int
    raw_banner: str = ""
    service_name: str = "UNKNOWN"
    service_version: str = ""
    os_hint: str = ""


@dataclass
class VulnerabilityFinding:
    """
    A single potential vulnerability match for a service banner.

    Attributes:
        cve_id:      CVE identifier string (e.g. ``"CVE-2021-41617"``).
        severity:    Qualitative severity: ``"CRITICAL"``, ``"HIGH"``,
                     ``"MEDIUM"``, or ``"LOW"``.
        cvss_score:  CVSS v3 base score (0.0–10.0).
        service:     Affected service name.
        description: Human-readable description of the vulnerability.
        match_token: The token in the banner that triggered this match.
    """
    cve_id: str
    severity: str
    cvss_score: float
    service: str
    description: str
    match_token: str = ""


@dataclass
class PasswordAuditResult:
    """
    Outcome of auditing a single password string.

    Attributes:
        password_hash: SHA-256 hex digest of the password (never stored in
                       plaintext after the audit completes).
        length:        Number of characters.
        entropy_bits:  Shannon entropy (higher is better; ≥60 bits is good).
        strength:      Qualitative rating: ``"VERY_WEAK"``, ``"WEAK"``,
                       ``"MODERATE"``, ``"STRONG"``, or ``"VERY_STRONG"``.
        is_common:     *True* if the password matches a common-password pattern.
        issues:        List of specific weakness descriptions.
        suggestions:   Actionable improvement hints.
    """
    password_hash: str
    length: int
    entropy_bits: float
    strength: str
    is_common: bool
    issues: list[str] = field(default_factory=list)
    suggestions: list[str] = field(default_factory=list)


@dataclass
class ReconResult:
    """
    Summary of passive reconnaissance findings for a target.

    Attributes:
        target:          The original target string (hostname or IP).
        resolved_ips:    All IP addresses resolved from the target hostname.
        reverse_hostnames: PTR-record hostnames for each resolved IP.
        open_ports_hint: Well-known ports found open (populated if a quick
                         probe was requested alongside recon).
        ip_version:      ``"IPv4"`` or ``"IPv6"`` for the primary resolved
                         address.
        is_private:      *True* when the primary IP is in RFC-1918 / private
                         address space.
        metadata:        Arbitrary key/value enrichment data.
    """
    target: str
    resolved_ips: list[str] = field(default_factory=list)
    reverse_hostnames: list[str] = field(default_factory=list)
    open_ports_hint: list[int] = field(default_factory=list)
    ip_version: str = ""
    is_private: bool = False
    metadata: dict = field(default_factory=dict)


# ===========================================================================
# Port scanner
# ===========================================================================

# Mapping of well-known port numbers to service names
_WELL_KNOWN_PORTS: dict[int, str] = {
    21:    "FTP",
    22:    "SSH",
    23:    "TELNET",
    25:    "SMTP",
    53:    "DNS",
    80:    "HTTP",
    110:   "POP3",
    119:   "NNTP",
    123:   "NTP",
    143:   "IMAP",
    161:   "SNMP",
    194:   "IRC",
    389:   "LDAP",
    443:   "HTTPS",
    445:   "SMB",
    465:   "SMTPS",
    514:   "SYSLOG",
    587:   "SMTP-SUBMISSION",
    636:   "LDAPS",
    993:   "IMAPS",
    995:   "POP3S",
    1433:  "MSSQL",
    1521:  "ORACLE",
    3306:  "MYSQL",
    3389:  "RDP",
    5432:  "POSTGRESQL",
    5900:  "VNC",
    6379:  "REDIS",
    8080:  "HTTP-ALT",
    8443:  "HTTPS-ALT",
    8888:  "HTTP-ALT2",
    9200:  "ELASTICSEARCH",
    27017: "MONGODB",
}

# Common port sets for convenience
COMMON_PORTS: list[int] = sorted(_WELL_KNOWN_PORTS.keys())
WEB_PORTS:    list[int] = [80, 443, 8080, 8443, 8888]
DB_PORTS:     list[int] = [1433, 1521, 3306, 5432, 6379, 9200, 27017]
ADMIN_PORTS:  list[int] = [22, 23, 3389, 5900]


class PortScanner:
    """
    TCP-connect port scanner.

    Uses Python's ``socket`` module to attempt a full TCP handshake on each
    target port.  A successful handshake (without sending any data) means the
    port is *open*; a connection refused or timeout means it is *closed* or
    *filtered*.  After each successful connection the scanner reads up to
    *banner_bytes* bytes to capture any service banner.

    This is equivalent to ``nmap -sT`` (TCP connect scan).

    Parameters
    ----------
    timeout:
        Per-port connection timeout in seconds (default ``1.0``).
    banner_bytes:
        Maximum banner bytes to read after connecting (default ``256``).
    """

    def __init__(self, timeout: float = 1.0, banner_bytes: int = 256) -> None:
        self.timeout = timeout
        self.banner_bytes = banner_bytes

    def scan(
        self,
        host: str,
        ports: Optional[list[int]] = None,
        port_range: Optional[tuple[int, int]] = None,
    ) -> list[PortScanResult]:
        """
        Scan a single host.

        Provide either *ports* (an explicit list) or *port_range* (an
        inclusive ``(start, end)`` tuple).  If neither is supplied the 100
        most-common ports in :data:`COMMON_PORTS` are scanned.

        Args:
            host:       Target hostname or IP address.
            ports:      Explicit list of port numbers to probe.
            port_range: Inclusive ``(start, end)`` range of ports to probe.

        Returns:
            A :class:`PortScanResult` for every port probed.
        """
        if ports is not None:
            target_ports = ports
        elif port_range is not None:
            target_ports = list(range(port_range[0], port_range[1] + 1))
        else:
            target_ports = COMMON_PORTS

        results: list[PortScanResult] = []
        for port in target_ports:
            results.append(self._probe(host, port))
        return results

    def scan_range(
        self, host: str, start: int, end: int
    ) -> list[PortScanResult]:
        """Convenience wrapper: scan all ports from *start* to *end*."""
        return self.scan(host, port_range=(start, end))

    def open_ports(self, host: str, ports: Optional[list[int]] = None) -> list[int]:
        """
        Return only the open port numbers for *host*.

        Args:
            host:  Target hostname or IP.
            ports: Ports to probe (defaults to :data:`COMMON_PORTS`).

        Returns:
            Sorted list of open port numbers.
        """
        results = self.scan(host, ports=ports)
        return sorted(r.port for r in results if r.is_open)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _probe(self, host: str, port: int) -> PortScanResult:
        """Attempt a TCP connection to *host*:*port* and capture the banner."""
        result = PortScanResult(
            host=host,
            port=port,
            service_hint=_WELL_KNOWN_PORTS.get(port, "UNKNOWN"),
        )
        try:
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                result.is_open = True
                # Attempt a non-blocking banner read
                sock.settimeout(min(self.timeout, 0.5))
                try:
                    raw = sock.recv(self.banner_bytes)
                    result.banner = raw.decode("utf-8", errors="replace").strip()
                except (socket.timeout, OSError):
                    pass
        except ConnectionRefusedError:
            pass
        except OSError as exc:
            result.error = str(exc)
        return result


# ===========================================================================
# Service fingerprinter
# ===========================================================================

# Patterns: (service_name, version_pattern, os_hint_pattern)
_FINGERPRINT_RULES: list[tuple[str, re.Pattern[str], re.Pattern[str]]] = [
    # SSH
    (
        "OpenSSH",
        re.compile(r"OpenSSH[_\s]+([\d.p]+)", re.IGNORECASE),
        re.compile(r"Ubuntu|Debian|CentOS|Red Hat|Fedora|Alpine", re.IGNORECASE),
    ),
    # Apache httpd
    (
        "Apache httpd",
        re.compile(r"Apache/([\d.]+)", re.IGNORECASE),
        re.compile(r"Ubuntu|Debian|CentOS|Win(?:32|64)", re.IGNORECASE),
    ),
    # nginx
    (
        "nginx",
        re.compile(r"nginx/([\d.]+)", re.IGNORECASE),
        re.compile(r"", re.IGNORECASE),
    ),
    # Microsoft IIS
    (
        "Microsoft IIS",
        re.compile(r"Microsoft-IIS/([\d.]+)", re.IGNORECASE),
        re.compile(r"Windows", re.IGNORECASE),
    ),
    # vsftpd
    (
        "vsftpd",
        re.compile(r"vsftpd\s+([\d.]+)", re.IGNORECASE),
        re.compile(r"", re.IGNORECASE),
    ),
    # ProFTPD
    (
        "ProFTPD",
        re.compile(r"ProFTPD\s+([\d.]+)", re.IGNORECASE),
        re.compile(r"", re.IGNORECASE),
    ),
    # MySQL / MariaDB
    (
        "MySQL",
        re.compile(r"(\d+\.\d+\.\d+-(?:MariaDB|MySQL)[\w.-]*)", re.IGNORECASE),
        re.compile(r"", re.IGNORECASE),
    ),
    # PostgreSQL
    (
        "PostgreSQL",
        re.compile(r"PostgreSQL\s+([\d.]+)", re.IGNORECASE),
        re.compile(r"", re.IGNORECASE),
    ),
    # Redis
    (
        "Redis",
        re.compile(r"redis_version:([\d.]+)", re.IGNORECASE),
        re.compile(r"", re.IGNORECASE),
    ),
    # Elasticsearch
    (
        "Elasticsearch",
        re.compile(r'"version"\s*:\s*\{[^}]*"number"\s*:\s*"([\d.]+)"', re.IGNORECASE),
        re.compile(r"", re.IGNORECASE),
    ),
    # MongoDB
    (
        "MongoDB",
        re.compile(r'"version"\s*:\s*"([\d.]+)"', re.IGNORECASE),
        re.compile(r"", re.IGNORECASE),
    ),
    # OpenSSL in HTTP headers
    (
        "OpenSSL",
        re.compile(r"OpenSSL/([\d.a-z]+)", re.IGNORECASE),
        re.compile(r"", re.IGNORECASE),
    ),
]


class ServiceFingerprinter:
    """
    Identifies services and their versions from TCP banners.

    The fingerprinter applies a set of regex rules against the raw banner
    string to extract a service name, version, and (where possible) an
    operating-system hint.

    For SSL/TLS ports (443, 8443, and any user-supplied *ssl_ports*) it first
    performs an SSL handshake and reads the banner from the encrypted stream,
    additionally extracting the certificate CN as service metadata.

    Parameters
    ----------
    timeout:    Per-port connection timeout in seconds (default ``2.0``).
    ssl_ports:  Set of port numbers that should use TLS (default:
                ``{443, 8443}``).
    """

    def __init__(
        self,
        timeout: float = 2.0,
        ssl_ports: Optional[set[int]] = None,
    ) -> None:
        self.timeout = timeout
        self.ssl_ports: set[int] = ssl_ports if ssl_ports is not None else {443, 8443}

    def fingerprint(self, host: str, port: int) -> ServiceFingerprintResult:
        """
        Attempt a connection to *host*:*port*, grab the banner, and identify
        the service.

        Args:
            host: Target hostname or IP address.
            port: TCP port to connect to.

        Returns:
            :class:`ServiceFingerprintResult` with best-effort identification.
        """
        result = ServiceFingerprintResult(host=host, port=port)
        banner = self._grab_banner(host, port)
        result.raw_banner = banner
        if banner:
            self._apply_rules(result)
        return result

    def fingerprint_multiple(
        self, host: str, ports: list[int]
    ) -> list[ServiceFingerprintResult]:
        """Fingerprint multiple ports on the same host."""
        return [self.fingerprint(host, p) for p in ports]

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _grab_banner(self, host: str, port: int) -> str:
        """Connect and read banner bytes; return empty string on failure."""
        use_ssl = port in self.ssl_ports
        raw = b""
        try:
            if use_ssl:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                with socket.create_connection(
                    (host, port), timeout=self.timeout
                ) as raw_sock:
                    with ctx.wrap_socket(raw_sock, server_hostname=host) as ssock:
                        ssock.settimeout(min(self.timeout, 1.0))
                        try:
                            raw = ssock.recv(512)
                        except (ssl.SSLError, socket.timeout, OSError):
                            pass
            else:
                with socket.create_connection(
                    (host, port), timeout=self.timeout
                ) as sock:
                    sock.settimeout(min(self.timeout, 1.0))
                    try:
                        raw = sock.recv(512)
                    except (socket.timeout, OSError):
                        pass
        except OSError:
            pass
        return raw.decode("utf-8", errors="replace").strip()

    def _apply_rules(self, result: ServiceFingerprintResult) -> None:
        """Apply fingerprint rules to populate *result* fields."""
        for service_name, ver_pat, os_pat in _FINGERPRINT_RULES:
            ver_match = ver_pat.search(result.raw_banner)
            if ver_match:
                result.service_name = service_name
                result.service_version = ver_match.group(1)
                os_match = os_pat.search(result.raw_banner)
                if os_match and os_pat.pattern:
                    result.os_hint = os_match.group(0)
                return
        # Fallback: first non-empty token of the banner
        first_line = result.raw_banner.splitlines()[0] if result.raw_banner else ""
        if first_line:
            result.service_name = first_line[:40]


# ===========================================================================
# Vulnerability assessor
# ===========================================================================

# Each entry: (cve_id, severity, cvss_score, service, description, match_pattern)
_CVE_PATTERNS: list[tuple[str, str, float, str, str, re.Pattern[str]]] = [
    # OpenSSH
    (
        "CVE-2023-38408",
        "CRITICAL", 9.8, "OpenSSH",
        "Remote code execution via ssh-agent forwarding in OpenSSH < 9.3p2",
        re.compile(r"OpenSSH[_\s]+([1-8]\.|9\.[0-2])", re.IGNORECASE),
    ),
    (
        "CVE-2021-41617",
        "HIGH", 7.0, "OpenSSH",
        "Privilege escalation in OpenSSH 6.2–8.8p1 via supplemental groups",
        re.compile(r"OpenSSH[_\s]+([6-7]\.|8\.[0-8]p1)", re.IGNORECASE),
    ),
    (
        "CVE-2016-0777",
        "MEDIUM", 6.4, "OpenSSH",
        "Information leak / memory disclosure in OpenSSH < 7.1p2 (roaming)",
        re.compile(r"OpenSSH[_\s]+([1-6]\.|7\.0)", re.IGNORECASE),
    ),
    # Apache httpd
    (
        "CVE-2021-41773",
        "CRITICAL", 9.8, "Apache httpd",
        "Path traversal and remote code execution in Apache 2.4.49",
        re.compile(r"Apache/2\.4\.49\b", re.IGNORECASE),
    ),
    (
        "CVE-2021-42013",
        "CRITICAL", 9.8, "Apache httpd",
        "Path traversal and RCE in Apache 2.4.49–2.4.50",
        re.compile(r"Apache/2\.4\.50\b", re.IGNORECASE),
    ),
    (
        "CVE-2017-7679",
        "CRITICAL", 9.8, "Apache httpd",
        "Buffer overflow in Apache mod_mime < 2.2.32 / 2.4.25",
        re.compile(r"Apache/2\.(2\.[0-2]\d|4\.[01]\d|4\.2[0-4])\b", re.IGNORECASE),
    ),
    (
        "CVE-2022-31813",
        "HIGH", 7.5, "Apache httpd",
        "Forward/reverse proxy request forgery in Apache < 2.4.54",
        re.compile(r"Apache/2\.4\.(?:[0-4]\d|5[0-3])\b", re.IGNORECASE),
    ),
    # nginx
    (
        "CVE-2021-23017",
        "HIGH", 7.7, "nginx",
        "Off-by-one heap write via crafted DNS response in nginx < 1.20.1",
        re.compile(r"nginx/1\.((?:[0-9]\.|1[0-9]\.|20\.0))", re.IGNORECASE),
    ),
    (
        "CVE-2022-41741",
        "HIGH", 7.8, "nginx",
        "Memory corruption in MP4 module in nginx < 1.23.2",
        re.compile(r"nginx/1\.((?:[0-9]\.|1[0-9]\.|2[0-2]\.|23\.[01]))", re.IGNORECASE),
    ),
    # Microsoft IIS
    (
        "CVE-2022-21907",
        "CRITICAL", 9.8, "Microsoft IIS",
        "Remote code execution in HTTP protocol stack in IIS 10.x",
        re.compile(r"Microsoft-IIS/10\.[01]\b", re.IGNORECASE),
    ),
    (
        "CVE-2015-1635",
        "CRITICAL", 9.8, "Microsoft IIS",
        "Remote code execution via HTTP.sys in IIS 6–8.5 (MS15-034)",
        re.compile(r"Microsoft-IIS/[678]\.", re.IGNORECASE),
    ),
    # MySQL / MariaDB
    (
        "CVE-2016-6662",
        "CRITICAL", 9.8, "MySQL",
        "Remote root code execution via mysqld_safe config-file injection (< 5.7.15)",
        re.compile(r"5\.(5\.\d+|6\.\d+|7\.(0|[0-9]|1[0-4]))-MySQL", re.IGNORECASE),
    ),
    (
        "CVE-2023-21980",
        "HIGH", 7.5, "MySQL",
        "Remote code execution in MySQL Cluster NDB < 8.0.33",
        re.compile(r"8\.0\.(?:[0-2]\d|3[0-2])-MySQL", re.IGNORECASE),
    ),
    # Redis
    (
        "CVE-2022-0543",
        "CRITICAL", 10.0, "Redis",
        "Lua sandbox escape / RCE in Redis < 5.0.14 / < 6.0.16 / < 6.2.6",
        re.compile(r"redis_version:(4\.|5\.0\.(?:[0-9]|1[0-3])\b|6\.0\.(?:[0-9]|1[0-5])\b|6\.2\.[0-5]\b)", re.IGNORECASE),
    ),
    (
        "CVE-2023-28856",
        "MEDIUM", 6.5, "Redis",
        "Authenticated users can use OBJECT ENCODING to crash the server (< 7.0.11)",
        re.compile(r"redis_version:(4\.|5\.|6\.|7\.0\.(?:\d|10))\b", re.IGNORECASE),
    ),
    # vsftpd
    (
        "CVE-2011-2523",
        "CRITICAL", 10.0, "vsftpd",
        "Backdoor in vsftpd 2.3.4 allows unauthenticated shell access",
        re.compile(r"vsftpd\s+2\.3\.4", re.IGNORECASE),
    ),
    # Elasticsearch
    (
        "CVE-2021-22145",
        "MEDIUM", 6.5, "Elasticsearch",
        "Memory disclosure in Elasticsearch < 7.13.4 / < 7.14.1",
        re.compile(r'"number"\s*:\s*"7\.1[0-3]\.\d+"', re.IGNORECASE),
    ),
    (
        "CVE-2023-31419",
        "MEDIUM", 6.5, "Elasticsearch",
        "StackOverflow crash / DoS in Elasticsearch < 8.9.1",
        re.compile(r'"number"\s*:\s*"8\.[0-8]\.\d+"', re.IGNORECASE),
    ),
    # ProFTPD
    (
        "CVE-2020-9273",
        "CRITICAL", 9.8, "ProFTPD",
        "Use-after-free / RCE in ProFTPD < 1.3.7 (mod_copy)",
        re.compile(r"ProFTPD\s+1\.3\.[0-6]\b", re.IGNORECASE),
    ),
    # Telnet
    (
        "ISSUE-TELNET-PLAINTEXT",
        "HIGH", 8.0, "TELNET",
        "Telnet transmits credentials and session data in plaintext; replace with SSH",
        re.compile(r"telnet|Telnet", re.IGNORECASE),
    ),
]


class VulnerabilityAssessor:
    """
    Maps service banners to known-vulnerable version patterns and CVE
    references.

    The assessor applies a curated library of regex patterns—each annotated
    with a CVE ID, CVSS score, and description—against a raw banner string.
    It returns a list of :class:`VulnerabilityFinding` objects, one for every
    pattern that matches.

    Example::

        assessor = VulnerabilityAssessor()
        findings = assessor.assess("SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5")
        for f in findings:
            print(f.cve_id, f.severity, f.description)
    """

    def assess(self, banner: str) -> list[VulnerabilityFinding]:
        """
        Check *banner* against all CVE patterns.

        Args:
            banner: Raw service banner string (as returned by
                    :class:`PortScanner` or :class:`ServiceFingerprinter`).

        Returns:
            List of :class:`VulnerabilityFinding` objects for each matching
            pattern (empty list if none matched).
        """
        findings: list[VulnerabilityFinding] = []
        for cve_id, severity, cvss, service, description, pattern in _CVE_PATTERNS:
            m = pattern.search(banner)
            if m:
                findings.append(
                    VulnerabilityFinding(
                        cve_id=cve_id,
                        severity=severity,
                        cvss_score=cvss,
                        service=service,
                        description=description,
                        match_token=m.group(0),
                    )
                )
        return findings

    def assess_multiple(
        self, banners: list[str]
    ) -> list[list[VulnerabilityFinding]]:
        """
        Assess a list of banners.

        Returns a list of finding-lists, one per banner.
        """
        return [self.assess(b) for b in banners]

    @staticmethod
    def highest_severity(findings: list[VulnerabilityFinding]) -> str:
        """
        Return the highest severity string across *findings*, or ``"NONE"``
        if the list is empty.
        """
        order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "NONE": 0}
        best = "NONE"
        for f in findings:
            if order.get(f.severity, 0) > order.get(best, 0):
                best = f.severity
        return best


# ===========================================================================
# Credential auditor
# ===========================================================================

# Common password patterns (no actual passwords stored — these are *structural*
# patterns that match trivially guessable strings)
_COMMON_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("all-lowercase-word",    re.compile(r"^[a-z]{4,12}$")),
    ("all-digits",            re.compile(r"^\d{4,12}$")),
    ("keyboard-walk",         re.compile(r"(qwerty|asdfgh|zxcvbn|123456|654321|abcdef)", re.IGNORECASE)),
    ("repeated-chars",        re.compile(r"(.)\1{3,}")),
    ("sequential-digits",     re.compile(r"0123|1234|2345|3456|4567|5678|6789|7890")),
    ("year-suffix",           re.compile(r"(19|20)\d{2}$")),
    ("password-literal",      re.compile(r"^(password|passwd|pass|secret|admin|root|login|welcome|letmein|changeme|default)", re.IGNORECASE)),
    ("company-generic",       re.compile(r"^(company|corp|user|test|demo|guest|temp)[\w]*$", re.IGNORECASE)),
]


class CredentialAuditor:
    """
    Analyses password strings for entropy, complexity, and common-credential
    patterns to support security audits.

    .. note::
        This class analyses the *strength* of passwords to help identify weak
        credentials during an authorized audit.  Passwords are **never stored**
        beyond the scope of the :meth:`audit` call; only their SHA-256 hash is
        retained in the returned :class:`PasswordAuditResult`.

    The entropy calculation uses Shannon entropy over the password's character
    set:  ``H = L × log2(C)``  where *L* is the length and *C* is the size of
    the character alphabet used (digits=10, lower=26, upper=26, special=32).
    """

    def audit(self, password: str) -> PasswordAuditResult:
        """
        Audit a single password string.

        Args:
            password: The password string to evaluate.

        Returns:
            :class:`PasswordAuditResult` — the input password is hashed
            immediately and never stored in plaintext.
        """
        pw_hash = hashlib.sha256(password.encode()).hexdigest()
        length = len(password)
        entropy = self._entropy(password)
        issues: list[str] = []
        suggestions: list[str] = []

        # Length checks
        if length < 8:
            issues.append("Too short (< 8 characters)")
            suggestions.append("Use at least 12 characters")
        elif length < 12:
            issues.append("Short password (< 12 characters)")
            suggestions.append("Use at least 16 characters for sensitive accounts")

        # Character-class checks
        has_lower   = bool(re.search(r"[a-z]", password))
        has_upper   = bool(re.search(r"[A-Z]", password))
        has_digit   = bool(re.search(r"\d",    password))
        has_special = bool(re.search(r"[^a-zA-Z0-9]", password))

        classes = sum([has_lower, has_upper, has_digit, has_special])
        if not has_upper:
            issues.append("No uppercase letters")
            suggestions.append("Mix upper and lower case")
        if not has_digit:
            issues.append("No digits")
            suggestions.append("Include numbers")
        if not has_special:
            issues.append("No special characters")
            suggestions.append("Include symbols such as !@#$%")
        if classes < 3:
            issues.append(f"Only {classes}/4 character classes present")

        # Common-pattern checks
        is_common = False
        for pattern_name, pattern in _COMMON_PATTERNS:
            if pattern.search(password):
                is_common = True
                issues.append(f"Matches common pattern: {pattern_name}")
                suggestions.append("Avoid predictable patterns like keyboard walks or dictionary words")
                break

        # Entropy threshold
        if entropy < 28:
            issues.append(f"Very low entropy ({entropy:.1f} bits)")
        elif entropy < 40:
            issues.append(f"Low entropy ({entropy:.1f} bits)")

        strength = self._strength(entropy, issues)

        if not suggestions and strength in ("STRONG", "VERY_STRONG"):
            suggestions.append("Good password — consider using a password manager for uniqueness")

        return PasswordAuditResult(
            password_hash=pw_hash,
            length=length,
            entropy_bits=round(entropy, 2),
            strength=strength,
            is_common=is_common,
            issues=issues,
            suggestions=suggestions,
        )

    def audit_bulk(self, passwords: list[str]) -> list[PasswordAuditResult]:
        """Audit a list of passwords, returning one result per entry."""
        return [self.audit(p) for p in passwords]

    def weak_passwords(
        self, passwords: list[str]
    ) -> list[tuple[int, PasswordAuditResult]]:
        """
        Return ``(index, result)`` pairs for passwords rated WEAK or VERY_WEAK.

        Args:
            passwords: List of password strings.

        Returns:
            Pairs of ``(original_index, PasswordAuditResult)`` for weak entries.
        """
        weak: list[tuple[int, PasswordAuditResult]] = []
        for i, pw in enumerate(passwords):
            result = self.audit(pw)
            if result.strength in ("VERY_WEAK", "WEAK"):
                weak.append((i, result))
        return weak

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _entropy(password: str) -> float:
        """
        Estimate Shannon entropy in bits using alphabet-size estimation.

        The alphabet size is determined by which character classes appear in
        the password, then multiplied by the length.
        """
        if not password:
            return 0.0
        alphabet = 0
        if re.search(r"[a-z]", password):
            alphabet += 26
        if re.search(r"[A-Z]", password):
            alphabet += 26
        if re.search(r"\d", password):
            alphabet += 10
        if re.search(r"[^a-zA-Z0-9]", password):
            alphabet += 32
        if alphabet == 0:
            alphabet = 1
        return len(password) * math.log2(alphabet)

    @staticmethod
    def _strength(entropy: float, issues: list[str]) -> str:
        """Map entropy + issue count to a qualitative strength rating."""
        penalty = len(issues)
        adjusted = entropy - penalty * 4
        if adjusted >= 70:
            return "VERY_STRONG"
        if adjusted >= 50:
            return "STRONG"
        if adjusted >= 35:
            return "MODERATE"
        if adjusted >= 20:
            return "WEAK"
        return "VERY_WEAK"


# ===========================================================================
# Recon scanner
# ===========================================================================

class ReconScanner:
    """
    Passive reconnaissance using only the Python standard library.

    Performs DNS forward lookups (``socket.getaddrinfo``), reverse PTR lookups
    (``socket.gethostbyaddr``), and IP-address classification
    (``ipaddress`` module).  No active probing beyond DNS queries is performed
    unless *quick_probe_ports* is provided.

    Parameters
    ----------
    timeout:
        DNS resolution timeout in seconds (default ``3.0``).
    """

    def __init__(self, timeout: float = 3.0) -> None:
        self.timeout = timeout

    def recon(
        self,
        target: str,
        quick_probe_ports: Optional[list[int]] = None,
    ) -> ReconResult:
        """
        Perform passive reconnaissance against *target*.

        Args:
            target:             Hostname or IP address string.
            quick_probe_ports:  If supplied, perform a quick TCP connect probe
                                on these ports and record which are open.

        Returns:
            :class:`ReconResult` populated with DNS and IP-classification data.
        """
        result = ReconResult(target=target)

        # 1. Forward DNS resolution
        resolved = self._resolve(target)
        result.resolved_ips = resolved

        if not resolved:
            return result

        primary = resolved[0]

        # 2. IP version and private-address classification
        try:
            ip_obj = ipaddress.ip_address(primary)
            result.ip_version = f"IPv{ip_obj.version}"
            result.is_private = ip_obj.is_private
        except ValueError:
            pass

        # 3. Reverse DNS lookups
        reverse: list[str] = []
        for ip in resolved:
            hostname = self._reverse_lookup(ip)
            if hostname:
                reverse.append(hostname)
        result.reverse_hostnames = list(dict.fromkeys(reverse))  # deduplicate

        # 4. Optional quick port probe
        if quick_probe_ports:
            scanner = PortScanner(timeout=min(self.timeout, 1.0))
            for port in quick_probe_ports:
                r = scanner._probe(primary, port)
                if r.is_open:
                    result.open_ports_hint.append(port)

        # 5. Metadata enrichment
        result.metadata["primary_ip"] = primary
        result.metadata["total_ips"] = len(resolved)
        if result.reverse_hostnames:
            result.metadata["primary_ptr"] = result.reverse_hostnames[0]

        return result

    def recon_multiple(
        self,
        targets: list[str],
        quick_probe_ports: Optional[list[int]] = None,
    ) -> list[ReconResult]:
        """Recon multiple targets, returning one :class:`ReconResult` each."""
        return [self.recon(t, quick_probe_ports) for t in targets]

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _resolve(self, target: str) -> list[str]:
        """Return all IP addresses for *target* via getaddrinfo."""
        old_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(self.timeout)
        try:
            infos = socket.getaddrinfo(target, None)
            seen: dict[str, None] = {}
            for info in infos:
                addr = info[4][0]
                seen[addr] = None
            return list(seen.keys())
        except OSError:
            return []
        finally:
            socket.setdefaulttimeout(old_timeout)

    def _reverse_lookup(self, ip: str) -> str:
        """Attempt a PTR record lookup; return empty string on failure."""
        old_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(self.timeout)
        try:
            return socket.gethostbyaddr(ip)[0]
        except OSError:
            return ""
        finally:
            socket.setdefaulttimeout(old_timeout)


# ===========================================================================
# Public convenience summary
# ===========================================================================

def summarize_scan(
    results: list[PortScanResult],
) -> dict:
    """
    Produce a concise summary dict over a list of :class:`PortScanResult`
    objects.

    Returns a dict with keys:
        ``host``, ``total_probed``, ``open_count``, ``open_ports``,
        ``services``.
    """
    if not results:
        return {}
    open_results = [r for r in results if r.is_open]
    return {
        "host":         results[0].host,
        "total_probed": len(results),
        "open_count":   len(open_results),
        "open_ports":   [r.port for r in open_results],
        "services":     {r.port: r.service_hint for r in open_results},
    }


# ===========================================================================
# pandas-backed scan aggregation
# ===========================================================================

def aggregate_scan_results(
    port_results: Optional[list[PortScanResult]] = None,
    vuln_findings: Optional[list["VulnerabilityFinding"]] = None,
    fingerprints: Optional[list["ServiceFingerprintResult"]] = None,
) -> "pd.DataFrame":
    """
    Aggregate heterogeneous scan results into a single :class:`pandas.DataFrame`
    for analyst review, reporting, and downstream ML scoring.

    Each row represents one discovery (open port, vulnerability finding, or
    service fingerprint).  A ``result_type`` column distinguishes the source.

    Columns:

    * ``result_type``   — ``"port_scan"`` | ``"vuln_finding"`` | ``"fingerprint"``
    * ``host``          — target hostname / IP
    * ``port``          — TCP/UDP port (0 for host-level findings)
    * ``is_open``       — bool (only meaningful for ``port_scan`` rows)
    * ``service``       — detected service name / hint
    * ``severity``      — ``"CRITICAL"`` / ``"HIGH"`` / ``"MEDIUM"`` / ``"LOW"``
      (empty for ``port_scan`` rows)
    * ``description``   — one-line description / banner
    * ``cve_ids``       — pipe-joined CVE identifiers (empty if none)

    Requires pandas to be installed.

    Args:
        port_results:   List of :class:`PortScanResult` objects.
        vuln_findings:  List of :class:`VulnerabilityFinding` objects.
        fingerprints:   List of :class:`ServiceFingerprintResult` objects.

    Returns:
        :class:`pandas.DataFrame` combining all inputs.

    Raises:
        ImportError: If pandas is not installed.

    Example
    -------
    ::

        df = aggregate_scan_results(port_results=scanner.scan_range(...))
        open_ports_df = df[df["is_open"]]
        print(df.groupby("severity").size())
    """
    try:
        import pandas as pd  # noqa: PLC0415
    except ImportError as exc:  # pragma: no cover
        raise ImportError("pandas is required for aggregate_scan_results().") from exc

    rows: list[dict] = []

    if port_results:
        for r in port_results:
            rows.append({
                "result_type": "port_scan",
                "host":        r.host,
                "port":        r.port,
                "is_open":     r.is_open,
                "service":     r.service_hint or "",
                "severity":    "",
                "description": r.banner or "",
                "cve_ids":     "",
            })

    if vuln_findings:
        for f in vuln_findings:
            rows.append({
                "result_type": "vuln_finding",
                "host":        "",
                "port":        0,
                "is_open":     True,
                "service":     f.service,
                "severity":    f.severity,
                "description": f.description,
                "cve_ids":     f.cve_id,
            })

    if fingerprints:
        for fp in fingerprints:
            rows.append({
                "result_type": "fingerprint",
                "host":        fp.host,
                "port":        fp.port,
                "is_open":     True,
                "service":     fp.service_name or "",
                "severity":    "",
                "description": fp.raw_banner or "",
                "cve_ids":     "",
            })

    if not rows:
        return pd.DataFrame(
            columns=["result_type", "host", "port", "is_open",
                     "service", "severity", "description", "cve_ids"]
        )
    return pd.DataFrame(rows)


# ===========================================================================
# pwntools-backed binary fuzzer
# ===========================================================================

class BinaryFuzzer:
    """
    Generates binary fuzzing payloads using `pwntools
    <https://github.com/Gallopsled/pwntools>`_.

    Useful for controlled red-team exercises to test how target services
    handle malformed or oversized inputs.  Three payload strategies are
    available:

    * **cyclic** — De Bruijn cyclic sequences for crash-offset identification.
    * **de_bruijn** — Same as cyclic but generated via the raw
      ``de_bruijn()`` generator; useful when a non-standard alphabet is
      needed.
    * **repeat** — Simple repeated-byte patterns (``"A" * n``,
      ``"\\x00" * n``, etc.) for basic overflow testing.

    All methods are pure (no network activity) and safe to call in CI.

    Parameters
    ----------
    arch:
        Target architecture string (``"amd64"`` / ``"i386"`` / ``"arm"`` /
        ``"aarch64"``).  Used to set pwntools context.  Default ``"amd64"``.
    endian:
        ``"little"`` or ``"big"``.  Default ``"little"``.

    Example
    -------
    ::

        fuzzer = BinaryFuzzer(arch="amd64")
        payload = fuzzer.cyclic_payload(256)
        offset  = fuzzer.find_offset(b"baaa")  # → int or None
        repeat  = fuzzer.repeat_payload(b"A", 512)
    """

    def __init__(
        self,
        arch: str = "amd64",
        endian: str = "little",
    ) -> None:
        self.arch   = arch
        self.endian = endian
        try:
            from pwn import context  # type: ignore[import]  # noqa: PLC0415
            context.arch    = arch
            context.endian  = endian
            context.log_level = "error"   # suppress pwntools banner/info
        except ImportError as exc:  # pragma: no cover
            raise ImportError("pwntools is required for BinaryFuzzer.") from exc

    def cyclic_payload(self, length: int) -> bytes:
        """
        Generate a De Bruijn cyclic byte sequence of *length* bytes.

        Any 4-byte sub-sequence within the payload is unique, allowing crash
        analysis tools to determine the exact byte offset of a saved return
        address or instruction pointer overwrite.

        Args:
            length: Number of bytes to generate (must be ≥ 1).

        Returns:
            Byte string of exactly *length* bytes.
        """
        from pwn import cyclic  # type: ignore[import]  # noqa: PLC0415
        return bytes(cyclic(length))

    def find_offset(self, value: bytes) -> Optional[int]:
        """
        Find the byte offset of *value* within a previously generated cyclic
        payload using :func:`pwnlib.util.cyclic.cyclic_find`.

        Args:
            value: A 4-byte sub-sequence found at the crash address (e.g.
                   from a core dump or SIGSEGV handler).

        Returns:
            Integer byte offset (0-based), or ``None`` if not found.

        Example
        -------
        ::

            payload = fuzzer.cyclic_payload(512)
            # Crash captures EIP/RIP = 0x61616167 ("gaaa" little-endian)
            offset = fuzzer.find_offset(b"gaaa")
            print(f"Overwrite starts at offset {offset}")   # → 24
        """
        try:
            from pwn import cyclic_find  # type: ignore[import]  # noqa: PLC0415
            result = int(cyclic_find(value))
            return result if result >= 0 else None
        except Exception:  # noqa: BLE001
            return None

    def repeat_payload(self, byte_pattern: bytes, length: int) -> bytes:
        """
        Generate a repeated-pattern payload of *length* bytes.

        Useful for basic overflow tests where offset identification is not
        required.

        Args:
            byte_pattern: Byte sequence to repeat.  Common choices: ``b"A"``,
                          ``b"\\x00"``, ``b"\\x41\\x42"``.
            length:       Total output length in bytes.

        Returns:
            Byte string of exactly *length* bytes.

        Raises:
            ValueError: If *byte_pattern* is empty.
        """
        if not byte_pattern:
            raise ValueError("byte_pattern must not be empty.")
        reps    = (length // len(byte_pattern)) + 1
        return (byte_pattern * reps)[:length]

    def format_string_probes(self, count: int = 8) -> list[bytes]:
        """
        Generate a list of classic format-string attack probes.

        Probes include ``%s``, ``%x``, ``%n``, ``%p`` repetitions (ASCII)
        as well as ``%08x.`` chains used to leak stack values.

        Args:
            count: Number of format specifier repetitions.  Default 8.

        Returns:
            List of byte strings, one per format specifier.
        """
        templates = ["%s", "%x", "%n", "%p", "%08x.", "%d", "%.10000d", "%hn"]
        probes = []
        for tmpl in templates:
            probes.append((tmpl * count).encode())
        return probes

    def overflow_with_pattern(self, offset: int, payload: bytes = b"") -> bytes:
        """
        Build a standard overflow payload: ``cyclic(offset) + payload``.

        Useful for constructing a ROP chain exploit once the offset to the
        saved return address has been determined with :meth:`find_offset`.

        Args:
            offset:  Byte distance from the start of user input to the return
                     address (obtained via :meth:`find_offset`).
            payload: Shell payload / ROP chain appended after the padding.
                     Defaults to empty bytes.

        Returns:
            ``cyclic(offset) + payload`` as a bytes object.
        """
        from pwn import cyclic  # type: ignore[import]  # noqa: PLC0415
        return bytes(cyclic(offset)) + payload
