"""
Email Scanner — SentinelWeave
==============================

Threat-detection for email messages.  Works for individual users (scan a
single message) and enterprise deployments (bulk scan + optional IMAP inbox
fetch).  No external libraries are required for core scanning; the standard
``email``, ``re``, ``math``, and ``urllib.parse`` modules are used throughout.
IMAP support uses the built-in ``imaplib`` and ``ssl`` modules.

Architecture
------------
1. **EmailMessage** — lightweight dataclass holding the parsed header and body
   fields extracted from a raw RFC 5322 message string or provided directly.
2. **Threat-indicator detectors** — nine independent rule-based checks each
   returning an :class:`EmailIndicator` with a name, description, severity
   weight (0.0–1.0), and matched evidence.
3. **EmailScanner** — orchestrates the detectors, aggregates the weighted
   scores into a final *risk_score* (0.0–1.0), maps it to a
   :class:`~sentinel_weave.threat_detector.ThreatLevel`, and returns an
   :class:`EmailScanResult`.
4. **IMAP integration** — optional ``connect_and_scan_imap()`` helper that
   fetches the most-recent *N* messages from a real mailbox and returns a
   list of :class:`EmailScanResult` objects.

Usage
-----
::

    from sentinel_weave.email_scanner import EmailScanner, EmailMessage

    scanner = EmailScanner()

    # Scan a single raw RFC 5322 email string
    result = scanner.scan_raw(raw_email_text)
    print(result.threat_level.value, f"{result.risk_score:.2%}")
    for ind in result.indicators:
        print(" •", ind.name, "—", ind.description)

    # Scan multiple emails at once (business / enterprise use)
    results = scanner.scan_bulk_raw([raw1, raw2, raw3])
    summary = EmailScanner.summarize(results)

    # Optional IMAP: connect and scan the last 20 inbox messages
    results = scanner.connect_and_scan_imap(
        host="imap.gmail.com", port=993, username="you@gmail.com",
        password="app-password", folder="INBOX", limit=20,
    )
"""

from __future__ import annotations

import email as _email_stdlib
import email.header as _email_header
import imaplib
import math
import re
import ssl
from dataclasses import dataclass, field
from email.message import Message as _RawMessage
from typing import Optional
from urllib.parse import urlparse

from .threat_detector import ThreatLevel


# ---------------------------------------------------------------------------
# Phishing / threat keyword lists
# ---------------------------------------------------------------------------

_PHISHING_KEYWORDS: list[tuple[str, float]] = [
    # (keyword_pattern, weight)
    (r"\bverify\s+your\s+(account|identity|email|password)\b",     0.70),
    (r"\bclick\s+here\s+(immediately|now|urgently|to\s+avoid)\b",  0.65),
    (r"\b(your\s+)?account\s+(has\s+been\s+)?(suspended|locked|compromised|hacked)\b", 0.75),
    (r"\bact\s+(now|immediately|today)\s+(or|to\s+avoid|before)\b", 0.60),
    (r"\bunusual\s+(sign.?in|login|activity|access)\b",            0.55),
    (r"\bconfirm\s+(your\s+)?(password|credit\s+card|billing|ssn|social\s+security)\b", 0.80),
    (r"\b(limited\s+time|expires?\s+(in\s+)?\d+\s+hours?|offer\s+expires?)\b", 0.45),
    (r"\bwe\s+(detected|noticed|found)\s+(suspicious|unusual|unauthori[sz]ed)\b", 0.55),
    (r"\bfree\s+(gift|prize|reward|iphone|laptop)\b",              0.50),
    (r"\b(nigerian|inheritance|lottery|jackpot|million\s+dollars?)\b", 0.85),
    (r"\b(update|re.?enter|re.?confirm|re.?submit)\s+your\s+(payment|card|bank|account)\b", 0.75),
    (r"\bpassword\s+(will\s+)?expire[sd]?\b",                      0.60),
    (r"\bclick\s+the\s+link\s+below\b",                            0.45),
    (r"\bdo\s+not\s+(ignore|delete)\s+this\s+(email|message)\b",   0.55),
    (r"\byour\s+delivery\s+(is\s+)?(on\s+hold|failed|pending\s+customs)\b", 0.50),
]

_SOCIAL_ENGINEERING: list[tuple[str, float]] = [
    (r"\b(this\s+is\s+)?(your\s+)?final\s+(warning|notice|reminder)\b", 0.65),
    (r"\bwe\s+will\s+(terminate|suspend|cancel|close)\s+your\s+account\b", 0.70),
    (r"\byou\s+(must|need\s+to|have\s+to)\s+(respond|reply|verify|confirm)\s+within\b", 0.60),
    (r"\bIT\s+(helpdesk|support|department|administrator|security)\b", 0.40),
    (r"\bDear\s+(customer|user|valued\s+member|account\s+holder)\b", 0.35),
    (r"\bcongratulations\s*[,!]\s+(you\s+have\s+been\s+selected|you\s+won)\b", 0.70),
    (r"\bbank\s+(transfer|wire|mandate|authority)\b",               0.55),
    (r"\b(ceo|cfo|president|director|executive)\s+(request|approval)\b", 0.65),
    (r"\bkeep\s+this\s+(email\s+)?(confidential|secret|private)\b", 0.55),
    (r"\bdo\s+not\s+forward\s+this\s+email\b",                     0.45),
]

# URL shorteners and common abused services
_URL_SHORTENER_PATTERNS: list[str] = [
    "bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "t.co", "is.gd", "buff.ly",
    "adf.ly", "shorte.st", "clck.ru", "rb.gy", "cutt.ly", "shorturl.at",
    "tiny.cc", "su.pr", "bl.ink", "lnkd.in",
]

# Domains that commonly appear in spoofing / lookalike attacks
_IMPERSONATED_BRANDS: list[str] = [
    "paypal", "amazon", "microsoft", "apple", "google", "facebook", "netflix",
    "chase", "wellsfargo", "bankofamerica", "citibank", "irs", "gov",
    "outlook", "office365", "dropbox", "docusign", "linkedin",
]

# Suspicious file extensions mentioned in body or subject
# Note: `.com` is intentionally excluded to avoid false positives with domain names
_SUSPICIOUS_EXTENSIONS = re.compile(
    r"\b\w+\.(exe|bat|ps1|vbs|js|jar|msi|scr|hta|cmd|pif|lnk|iso|img"
    r"|zip|rar|7z|gz)\b",
    re.IGNORECASE,
)

# Regex for bare IPv4 addresses used in URLs
_IP_URL_RE = re.compile(
    r"https?://(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})",
    re.IGNORECASE,
)

# Regex to extract all URLs from text
_URL_RE = re.compile(
    r"https?://[^\s\"'<>\]\[)]+",
    re.IGNORECASE,
)

# HTML obfuscation / hidden content
_HTML_OBFUSCATION_RE = re.compile(
    r"(display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0|"
    r"color\s*:\s*white.*?background\s*:\s*white|&#x|%[0-9a-fA-F]{2}.*?%[0-9a-fA-F]{2})",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class EmailIndicator:
    """
    A single threat signal found in an email.

    Attributes:
        name:        Short identifier (e.g. ``"PHISHING_KEYWORDS"``).
        description: Human-readable explanation of what was found.
        weight:      Severity contribution in range 0.0–1.0.
        evidence:    List of matching strings or patterns that triggered this.
    """

    name:        str
    description: str
    weight:      float
    evidence:    list[str] = field(default_factory=list)


@dataclass
class EmailMessage:
    """
    A parsed email message.

    Can be built manually or via :meth:`EmailScanner.parse_raw`.

    Attributes:
        raw_text:    Original RFC 5322 string (may be empty if built manually).
        subject:     Decoded subject line.
        sender:      ``From`` header value (display name + address).
        recipients:  List of ``To``/``Cc`` addresses.
        reply_to:    ``Reply-To`` header value (if present).
        body_text:   Plain-text body.
        body_html:   HTML body (empty string if not present).
        headers:     All headers as a ``{name: value}`` dict.
        attachments: List of attachment filenames mentioned / present.
    """

    raw_text:    str              = ""
    subject:     str              = ""
    sender:      str              = ""
    recipients:  list[str]        = field(default_factory=list)
    reply_to:    str              = ""
    body_text:   str              = ""
    body_html:   str              = ""
    headers:     dict[str, str]   = field(default_factory=dict)
    attachments: list[str]        = field(default_factory=list)


@dataclass
class EmailScanResult:
    """
    Result of scanning a single :class:`EmailMessage` for threats.

    Attributes:
        email:        The scanned message.
        threat_level: Categorical severity (:class:`~sentinel_weave.threat_detector.ThreatLevel`).
        risk_score:   Aggregated risk 0.0–1.0 (higher = more threatening).
        indicators:   Ordered list of :class:`EmailIndicator` objects (highest-weight first).
        explanation:  One-paragraph human-readable verdict summary.
        safe:         ``True`` if ``threat_level`` is ``BENIGN`` or ``LOW``.
    """

    email:        EmailMessage
    threat_level: ThreatLevel
    risk_score:   float
    indicators:   list[EmailIndicator]  = field(default_factory=list)
    explanation:  str                   = ""

    @property
    def safe(self) -> bool:
        """True when the email is considered low-risk."""
        return self.threat_level in (ThreatLevel.BENIGN, ThreatLevel.LOW)

    def __str__(self) -> str:
        verdict = "✅ SAFE" if self.safe else "🚨 THREAT"
        return (
            f"[{verdict}] {self.threat_level.value}  "
            f"risk={self.risk_score:.2%}  "
            f"subject={self.email.subject!r}"
        )


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

class EmailScanner:
    """
    Scans email messages for phishing, social engineering, and malware
    delivery threats.

    The scanner is **stateless** and **dependency-free** for core operation.
    All nine threat-indicator checks run against the parsed email fields.
    The final *risk_score* is a *capped weighted average* of the individual
    indicator weights — it can never exceed 1.0.

    Parameters
    ----------
    risk_threshold_medium:
        Minimum risk_score for :attr:`~ThreatLevel.MEDIUM` classification.
        Default 0.35.
    risk_threshold_high:
        Minimum risk_score for :attr:`~ThreatLevel.HIGH` classification.
        Default 0.60.
    risk_threshold_critical:
        Minimum risk_score for :attr:`~ThreatLevel.CRITICAL` classification.
        Default 0.82.

    Example
    -------
    ::

        scanner = EmailScanner()
        result  = scanner.scan_raw(raw_email)
        print(result)
        for ind in result.indicators:
            print(f"  {ind.name}: {ind.description}")
    """

    def __init__(
        self,
        risk_threshold_medium:   float = 0.35,
        risk_threshold_high:     float = 0.60,
        risk_threshold_critical: float = 0.82,
    ) -> None:
        self._thresh_med  = risk_threshold_medium
        self._thresh_high = risk_threshold_high
        self._thresh_crit = risk_threshold_critical

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan(self, msg: EmailMessage) -> EmailScanResult:
        """
        Scan a pre-parsed :class:`EmailMessage` for threats.

        Args:
            msg: Parsed email message.

        Returns:
            :class:`EmailScanResult` with threat level, risk score, and
            indicator breakdown.
        """
        indicators = self._run_all_detectors(msg)
        risk_score = self._aggregate_score(indicators)
        level      = self._classify(risk_score)
        explanation = self._explain(msg, level, risk_score, indicators)
        return EmailScanResult(
            email=msg,
            threat_level=level,
            risk_score=risk_score,
            indicators=sorted(indicators, key=lambda x: x.weight, reverse=True),
            explanation=explanation,
        )

    def scan_raw(self, raw_email: str) -> EmailScanResult:
        """
        Parse *raw_email* (RFC 5322 string) and scan it for threats.

        This is the most convenient entry point for individual users who
        paste a raw email into the GUI.

        Args:
            raw_email: Full RFC 5322 email string, or a plain-text blob
                       (subject / body free-text without headers).

        Returns:
            :class:`EmailScanResult`.
        """
        return self.scan(self.parse_raw(raw_email))

    def scan_bulk(self, messages: list[EmailMessage]) -> list[EmailScanResult]:
        """
        Scan a list of pre-parsed messages (enterprise batch mode).

        Args:
            messages: List of :class:`EmailMessage` objects.

        Returns:
            List of :class:`EmailScanResult` in the same order.
        """
        return [self.scan(m) for m in messages]

    def scan_bulk_raw(self, raw_emails: list[str]) -> list[EmailScanResult]:
        """
        Parse and scan a list of raw RFC 5322 strings (enterprise batch mode).

        Args:
            raw_emails: List of raw email strings.

        Returns:
            List of :class:`EmailScanResult` in the same order.
        """
        return [self.scan_raw(r) for r in raw_emails]

    # ------------------------------------------------------------------
    # Parsing
    # ------------------------------------------------------------------

    @staticmethod
    def parse_raw(raw: str) -> EmailMessage:
        """
        Parse a raw RFC 5322 email string into an :class:`EmailMessage`.

        Falls back gracefully if the input is not valid RFC 5322 — the
        entire string is treated as the plain-text body.

        Args:
            raw: Raw email string.

        Returns:
            :class:`EmailMessage`.
        """
        msg = EmailMessage(raw_text=raw)

        try:
            parsed: _RawMessage = _email_stdlib.message_from_string(raw)
        except Exception:  # noqa: BLE001
            msg.body_text = raw
            return msg

        # ---- Headers ----
        for key in set(parsed.keys()):
            val = parsed.get(key, "")
            msg.headers[key.lower()] = EmailScanner._decode_header(str(val))

        msg.subject   = EmailScanner._decode_header(parsed.get("Subject", ""))
        msg.sender    = EmailScanner._decode_header(parsed.get("From",    ""))
        msg.reply_to  = EmailScanner._decode_header(parsed.get("Reply-To", ""))

        to_cc = []
        for hdr in ("To", "Cc", "Delivered-To"):
            val = parsed.get(hdr)
            if val:
                to_cc.extend(
                    a.strip() for a in EmailScanner._decode_header(val).split(",")
                    if a.strip()
                )
        msg.recipients = to_cc

        # ---- Body + attachments ----
        if parsed.is_multipart():
            for part in parsed.walk():
                ct   = part.get_content_type()
                disp = part.get_content_disposition() or ""

                if "attachment" in disp:
                    fn = part.get_filename()
                    if fn:
                        msg.attachments.append(EmailScanner._decode_header(fn))
                elif ct == "text/plain":
                    try:
                        charset   = part.get_content_charset() or "utf-8"
                        payload   = part.get_payload(decode=True)
                        if payload:
                            msg.body_text += payload.decode(charset, errors="replace")
                    except Exception:  # noqa: BLE001
                        msg.body_text += str(part.get_payload())
                elif ct == "text/html":
                    try:
                        charset = part.get_content_charset() or "utf-8"
                        payload = part.get_payload(decode=True)
                        if payload:
                            msg.body_html += payload.decode(charset, errors="replace")
                    except Exception:  # noqa: BLE001
                        msg.body_html += str(part.get_payload())
        else:
            ct = parsed.get_content_type()
            try:
                charset = parsed.get_content_charset() or "utf-8"
                payload = parsed.get_payload(decode=True)
                if payload:
                    text = payload.decode(charset, errors="replace")
                    if ct == "text/html":
                        msg.body_html = text
                    else:
                        msg.body_text = text
                else:
                    raw_payload = parsed.get_payload()
                    if isinstance(raw_payload, str):
                        msg.body_text = raw_payload
            except Exception:  # noqa: BLE001
                msg.body_text = str(parsed.get_payload())

        # If no body was extracted treat the whole raw string as body
        if not msg.body_text and not msg.body_html:
            msg.body_text = raw

        return msg

    # ------------------------------------------------------------------
    # IMAP (optional)
    # ------------------------------------------------------------------

    def connect_and_scan_imap(
        self,
        host:     str,
        username: str,
        password: str,
        port:     int   = 993,
        folder:   str   = "INBOX",
        limit:    int   = 20,
        use_ssl:  bool  = True,
    ) -> list[EmailScanResult]:
        """
        Connect to an IMAP server, fetch the *limit* most-recent messages
        from *folder*, and scan each one.

        This method is available to both individual users (connecting to
        Gmail, Outlook, etc. with an app password) and enterprise
        deployments (connecting to on-premises Exchange / M365 via IMAP).

        Args:
            host:     IMAP server hostname (e.g. ``"imap.gmail.com"``).
            username: Email address / login.
            password: Password or app-specific password.
            port:     IMAP port (993 for IMAPS, 143 for STARTTLS).
            folder:   Mailbox folder to scan.  Default ``"INBOX"``.
            limit:    Maximum number of recent messages to fetch.  Default 20.
            use_ssl:  Use SSL/TLS for the connection.  Default ``True``.

        Returns:
            List of :class:`EmailScanResult` ordered newest-first.

        Raises:
            imaplib.IMAP4.error: On authentication or connection failure.
            ConnectionError:     If the server is unreachable.
        """
        ctx = ssl.create_default_context() if use_ssl else None

        if use_ssl:
            conn: imaplib.IMAP4 = imaplib.IMAP4_SSL(host, port, ssl_context=ctx)
        else:
            conn = imaplib.IMAP4(host, port)

        try:
            conn.login(username, password)
            conn.select(folder, readonly=True)

            _, data = conn.search(None, "ALL")
            all_ids = data[0].split()
            fetch_ids = all_ids[-limit:] if len(all_ids) > limit else all_ids
            fetch_ids = list(reversed(fetch_ids))  # newest first

            results: list[EmailScanResult] = []
            for uid in fetch_ids:
                _, msg_data = conn.fetch(uid, "(RFC822)")
                for part in msg_data:
                    if isinstance(part, tuple):
                        raw = part[1]
                        if isinstance(raw, bytes):
                            raw = raw.decode("utf-8", errors="replace")
                        results.append(self.scan_raw(str(raw)))
                        break
            return results
        finally:
            try:
                conn.logout()
            except Exception:  # noqa: BLE001
                pass

    # ------------------------------------------------------------------
    # Summary / reporting
    # ------------------------------------------------------------------

    @staticmethod
    def summarize(results: list[EmailScanResult]) -> dict:
        """
        Produce a summary dictionary for a batch of scan results.

        Args:
            results: List of :class:`EmailScanResult` objects.

        Returns:
            Dict with keys:

            ``"total"``
                Total number of emails scanned.
            ``"safe"``
                Count of BENIGN or LOW results.
            ``"threats"``
                Count of MEDIUM, HIGH, or CRITICAL results.
            ``"by_level"``
                Mapping ``{ThreatLevel.value: count}``.
            ``"avg_risk_score"``
                Mean risk score across all results.
            ``"top_indicators"``
                List of ``(indicator_name, count)`` tuples sorted by
                frequency, showing which threat signals appeared most.
        """
        if not results:
            return {
                "total": 0, "safe": 0, "threats": 0,
                "by_level": {}, "avg_risk_score": 0.0, "top_indicators": [],
            }

        by_level: dict[str, int] = {}
        indicator_counts: dict[str, int] = {}
        total_risk = 0.0
        safe_count = 0
        threat_count = 0

        for r in results:
            lv = r.threat_level.value
            by_level[lv] = by_level.get(lv, 0) + 1
            total_risk += r.risk_score
            if r.safe:
                safe_count += 1
            else:
                threat_count += 1
            for ind in r.indicators:
                indicator_counts[ind.name] = indicator_counts.get(ind.name, 0) + 1

        top = sorted(indicator_counts.items(), key=lambda kv: kv[1], reverse=True)

        return {
            "total":          len(results),
            "safe":           safe_count,
            "threats":        threat_count,
            "by_level":       by_level,
            "avg_risk_score": round(total_risk / len(results), 4),
            "top_indicators": top,
        }

    # ------------------------------------------------------------------
    # Internal detectors
    # ------------------------------------------------------------------

    def _run_all_detectors(self, msg: EmailMessage) -> list[EmailIndicator]:
        indicators: list[EmailIndicator] = []
        full_text = (
            f"{msg.subject}\n{msg.sender}\n{msg.reply_to}\n"
            f"{msg.body_text}\n{msg.body_html}"
        )

        _maybe_add(indicators, self._detect_phishing_keywords(full_text))
        _maybe_add(indicators, self._detect_social_engineering(full_text))
        _maybe_add(indicators, self._detect_suspicious_urls(full_text))
        _maybe_add(indicators, self._detect_sender_spoofing(msg))
        _maybe_add(indicators, self._detect_lookalike_domains(full_text, msg.sender))
        _maybe_add(indicators, self._detect_suspicious_attachments(msg, full_text))
        _maybe_add(indicators, self._detect_link_density(full_text))
        _maybe_add(indicators, self._detect_html_obfuscation(msg.body_html))
        _maybe_add(indicators, self._detect_header_anomalies(msg))

        return indicators

    # ---- Detector 1: Phishing keywords ----

    @staticmethod
    def _detect_phishing_keywords(text: str) -> Optional[EmailIndicator]:
        matched: list[str] = []
        total_weight = 0.0
        for pattern, w in _PHISHING_KEYWORDS:
            m = re.search(pattern, text, re.IGNORECASE | re.DOTALL)
            if m:
                matched.append(m.group(0).strip())
                total_weight = max(total_weight, w)

        if not matched:
            return None

        weight = min(total_weight + 0.05 * (len(matched) - 1), 1.0)
        return EmailIndicator(
            name="PHISHING_KEYWORDS",
            description=f"Found {len(matched)} phishing keyword pattern(s).",
            weight=round(weight, 3),
            evidence=matched[:5],
        )

    # ---- Detector 2: Social engineering ----

    @staticmethod
    def _detect_social_engineering(text: str) -> Optional[EmailIndicator]:
        matched: list[str] = []
        top_weight = 0.0
        for pattern, w in _SOCIAL_ENGINEERING:
            m = re.search(pattern, text, re.IGNORECASE | re.DOTALL)
            if m:
                matched.append(m.group(0).strip())
                top_weight = max(top_weight, w)

        if not matched:
            return None

        weight = min(top_weight + 0.04 * (len(matched) - 1), 1.0)
        return EmailIndicator(
            name="SOCIAL_ENGINEERING",
            description=f"Found {len(matched)} social-engineering tactic(s).",
            weight=round(weight, 3),
            evidence=matched[:5],
        )

    # ---- Detector 3: Suspicious URLs ----

    @staticmethod
    def _detect_suspicious_urls(text: str) -> Optional[EmailIndicator]:
        urls    = _URL_RE.findall(text)
        evidence: list[str] = []
        max_w   = 0.0

        for url in urls:
            try:
                parsed = urlparse(url)
                host   = (parsed.hostname or "").lower()
            except Exception:  # noqa: BLE001
                continue

            # IP-based URL
            if _IP_URL_RE.search(url):
                evidence.append(f"IP URL: {url[:80]}")
                max_w = max(max_w, 0.75)

            # URL shortener
            for shortener in _URL_SHORTENER_PATTERNS:
                if host == shortener or host.endswith("." + shortener):
                    evidence.append(f"URL shortener: {url[:80]}")
                    max_w = max(max_w, 0.60)
                    break

            # Mismatch between displayed text and actual URL (heuristic:
            # domain contains another domain as substring to confuse)
            if host.count(".") > 3:
                evidence.append(f"Deeply nested domain: {host}")
                max_w = max(max_w, 0.45)

        if not evidence:
            return None

        weight = min(max_w + 0.05 * (len(evidence) - 1), 1.0)
        return EmailIndicator(
            name="SUSPICIOUS_URLS",
            description=f"Found {len(evidence)} suspicious URL(s).",
            weight=round(weight, 3),
            evidence=evidence[:6],
        )

    # ---- Detector 4: Sender spoofing ----

    @staticmethod
    def _detect_sender_spoofing(msg: EmailMessage) -> Optional[EmailIndicator]:
        sender   = msg.sender
        reply_to = msg.reply_to

        evidence: list[str] = []
        max_w = 0.0

        # Display-name vs address mismatch
        # e.g. "PayPal Support <phisher@evil.com>"
        name_addr_re = re.compile(r"^(.+?)\s*<([^>]+)>$")
        m = name_addr_re.match(sender.strip())
        if m:
            display_name = m.group(1).strip().lower()
            addr_domain  = (m.group(2).split("@")[-1]).lower().strip(">")

            for brand in _IMPERSONATED_BRANDS:
                if brand in display_name and brand not in addr_domain:
                    evidence.append(
                        f"Display name '{m.group(1)}' impersonates '{brand}' "
                        f"but sends from '{addr_domain}'"
                    )
                    max_w = max(max_w, 0.85)
                    break

        # Reply-To domain differs from From domain
        if reply_to and "@" in reply_to and "@" in sender:
            from_domain  = sender.split("@")[-1].strip(">").lower()
            reply_domain = reply_to.split("@")[-1].strip(">").lower()
            if from_domain and reply_domain and from_domain != reply_domain:
                evidence.append(
                    f"Reply-To domain '{reply_domain}' differs from "
                    f"From domain '{from_domain}'"
                )
                max_w = max(max_w, 0.70)

        if not evidence:
            return None

        return EmailIndicator(
            name="SENDER_SPOOFING",
            description=f"Potential sender spoofing/impersonation detected.",
            weight=round(max_w, 3),
            evidence=evidence,
        )

    # ---- Detector 5: Lookalike domains ----

    @staticmethod
    def _detect_lookalike_domains(text: str, sender: str) -> Optional[EmailIndicator]:
        urls   = _URL_RE.findall(text)
        # also check sender domain
        if "@" in sender:
            domain_part = sender.split("@")[-1].strip(">").lower()
            urls.append(f"http://{domain_part}/")

        evidence: list[str] = []
        max_w = 0.0

        for url in urls:
            try:
                host = (urlparse(url).hostname or "").lower()
            except Exception:  # noqa: BLE001
                continue
            for brand in _IMPERSONATED_BRANDS:
                if brand in host and host != brand + ".com":
                    # e.g. paypal-security.com, amazon-support.net
                    if re.search(
                        r"[-_.]?" + re.escape(brand) + r"[-_.]",
                        host,
                    ):
                        evidence.append(f"Lookalike domain: {host} (targets '{brand}')")
                        max_w = max(max_w, 0.80)
                        break

        if not evidence:
            return None

        weight = min(max_w + 0.04 * (len(evidence) - 1), 1.0)
        return EmailIndicator(
            name="LOOKALIKE_DOMAIN",
            description=f"Found {len(evidence)} domain(s) impersonating trusted brands.",
            weight=round(weight, 3),
            evidence=evidence[:5],
        )

    # ---- Detector 6: Suspicious attachments ----

    @staticmethod
    def _detect_suspicious_attachments(
        msg: EmailMessage, full_text: str
    ) -> Optional[EmailIndicator]:
        evidence: list[str] = []
        max_w = 0.0

        # Actual MIME attachments
        for fn in msg.attachments:
            m = _SUSPICIOUS_EXTENSIONS.search(fn)
            if m:
                evidence.append(f"Attachment: {fn}")
                ext = m.group(1).lower()
                w = 0.90 if ext in ("exe", "bat", "ps1", "vbs", "hta", "scr") else 0.65
                max_w = max(max_w, w)

        # Mentions in body text
        for m in _SUSPICIOUS_EXTENSIONS.finditer(full_text):
            fn = m.group(0)
            if fn not in evidence:
                evidence.append(f"Mentioned: {fn}")
                ext = m.group(1).lower()
                w = 0.70 if ext in ("exe", "bat", "ps1", "vbs") else 0.50
                max_w = max(max_w, w)

        # Password-protected zip pattern
        if re.search(r"(password|passcode).*?zip|zip.*?(password|passcode)", full_text, re.IGNORECASE | re.DOTALL):
            evidence.append("Password-protected archive mentioned")
            max_w = max(max_w, 0.75)

        if not evidence:
            return None

        weight = min(max_w + 0.03 * (len(evidence) - 1), 1.0)
        return EmailIndicator(
            name="SUSPICIOUS_ATTACHMENTS",
            description=f"Found {len(evidence)} suspicious attachment indicator(s).",
            weight=round(weight, 3),
            evidence=evidence[:6],
        )

    # ---- Detector 7: Excessive link density ----

    @staticmethod
    def _detect_link_density(text: str) -> Optional[EmailIndicator]:
        urls  = _URL_RE.findall(text)
        n     = len(urls)
        if n < 5:
            return None

        weight = min(0.20 + 0.05 * (n - 5), 0.70)
        return EmailIndicator(
            name="EXCESSIVE_LINKS",
            description=f"{n} hyperlinks found — unusually high for a legitimate email.",
            weight=round(weight, 3),
            evidence=[u[:80] for u in urls[:5]],
        )

    # ---- Detector 8: HTML obfuscation ----

    @staticmethod
    def _detect_html_obfuscation(html_body: str) -> Optional[EmailIndicator]:
        if not html_body:
            return None

        evidence: list[str] = []
        for m in _HTML_OBFUSCATION_RE.finditer(html_body):
            snippet = m.group(0)[:60].strip()
            if snippet not in evidence:
                evidence.append(snippet)

        if not evidence:
            return None

        weight = min(0.50 + 0.10 * len(evidence), 0.90)
        return EmailIndicator(
            name="HTML_OBFUSCATION",
            description=f"HTML body contains {len(evidence)} obfuscation technique(s).",
            weight=round(weight, 3),
            evidence=evidence[:5],
        )

    # ---- Detector 9: Header anomalies ----

    @staticmethod
    def _detect_header_anomalies(msg: EmailMessage) -> Optional[EmailIndicator]:
        evidence: list[str] = []
        max_w = 0.0
        h = msg.headers

        # Missing standard headers
        if not h.get("message-id"):
            evidence.append("Missing Message-ID header")
            max_w = max(max_w, 0.40)

        if not h.get("date"):
            evidence.append("Missing Date header")
            max_w = max(max_w, 0.30)

        # SPF / DKIM / DMARC failures in Authentication-Results
        auth = h.get("authentication-results", "")
        if auth:
            if re.search(r"spf\s*=\s*fail", auth, re.IGNORECASE):
                evidence.append("SPF check failed")
                max_w = max(max_w, 0.75)
            if re.search(r"dkim\s*=\s*fail", auth, re.IGNORECASE):
                evidence.append("DKIM signature failed")
                max_w = max(max_w, 0.80)
            if re.search(r"dmarc\s*=\s*fail", auth, re.IGNORECASE):
                evidence.append("DMARC policy failed")
                max_w = max(max_w, 0.85)

        # Received chain anomaly: first hop is an unusual TLD
        received = h.get("received", "")
        if received:
            suspicious_tld = re.search(
                r"\bfrom\b.*?\.(ru|cn|tk|ml|ga|cf|gq|xyz|top|click|loan|work)\b",
                received, re.IGNORECASE,
            )
            if suspicious_tld:
                evidence.append(
                    f"Received from suspicious TLD: {suspicious_tld.group(0)[:60]}"
                )
                max_w = max(max_w, 0.60)

        # X-Mailer revealing mass-mailing software
        mailer = h.get("x-mailer", "")
        if mailer and re.search(
            r"(phpmailer|bulk|mass.?mail|blat|sendblaster|mailchimp\s+abuse)",
            mailer, re.IGNORECASE,
        ):
            evidence.append(f"Suspicious X-Mailer: {mailer[:60]}")
            max_w = max(max_w, 0.45)

        if not evidence:
            return None

        weight = min(max_w + 0.04 * (len(evidence) - 1), 1.0)
        return EmailIndicator(
            name="HEADER_ANOMALIES",
            description=f"Found {len(evidence)} suspicious header anomaly/anomalies.",
            weight=round(weight, 3),
            evidence=evidence,
        )

    # ------------------------------------------------------------------
    # Score aggregation and classification
    # ------------------------------------------------------------------

    @staticmethod
    def _aggregate_score(indicators: list[EmailIndicator]) -> float:
        """
        Compute a final risk score using a *soft-max* weighted formula so
        that multiple moderate signals combine to a higher score without a
        single indicator dominating unfairly.

        The formula:  score = 1 - ∏(1 - wᵢ)
        This is the probability that *at least one* independent risk event
        of weight *wᵢ* occurs — it grows monotonically with more signals
        and naturally stays in [0, 1].
        """
        if not indicators:
            return 0.0
        complement = 1.0
        for ind in indicators:
            complement *= (1.0 - ind.weight)
        return round(min(1.0 - complement, 1.0), 4)

    def _classify(self, risk_score: float) -> ThreatLevel:
        if risk_score >= self._thresh_crit:
            return ThreatLevel.CRITICAL
        if risk_score >= self._thresh_high:
            return ThreatLevel.HIGH
        if risk_score >= self._thresh_med:
            return ThreatLevel.MEDIUM
        if risk_score > 0.0:
            return ThreatLevel.LOW
        return ThreatLevel.BENIGN

    @staticmethod
    def _explain(
        msg:        EmailMessage,
        level:      ThreatLevel,
        risk_score: float,
        indicators: list[EmailIndicator],
    ) -> str:
        if not indicators:
            return (
                f"No threat indicators detected. "
                f"Risk score: {risk_score:.1%}. "
                f"The email appears safe to open."
            )

        top = sorted(indicators, key=lambda x: x.weight, reverse=True)
        top3_names = ", ".join(i.name for i in top[:3])
        subject_str = f"'{msg.subject}'" if msg.subject else "(no subject)"

        severity_str = {
            ThreatLevel.BENIGN:   "appears safe",
            ThreatLevel.LOW:      "has minor concerns",
            ThreatLevel.MEDIUM:   "is suspicious",
            ThreatLevel.HIGH:     "is highly suspicious",
            ThreatLevel.CRITICAL: "is extremely dangerous",
        }[level]

        return (
            f"Email {subject_str} {severity_str} "
            f"(risk score {risk_score:.1%}, level {level.value}). "
            f"Top threat signals: {top3_names}. "
            f"{len(indicators)} indicator(s) triggered in total. "
            + ("Do NOT click links or open attachments." if not level == ThreatLevel.BENIGN else "")
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _decode_header(value: str) -> str:
        """Decode RFC 2047-encoded header value to plain string."""
        try:
            parts = _email_header.decode_header(value)
            decoded = []
            for part, charset in parts:
                if isinstance(part, bytes):
                    decoded.append(part.decode(charset or "utf-8", errors="replace"))
                else:
                    decoded.append(str(part))
            return " ".join(decoded)
        except Exception:  # noqa: BLE001
            return value


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _maybe_add(
    lst: list[EmailIndicator],
    indicator: Optional[EmailIndicator],
) -> None:
    """Append *indicator* to *lst* only if it is not None."""
    if indicator is not None:
        lst.append(indicator)
