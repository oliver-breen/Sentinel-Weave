"""
Advanced Offensive Security Strategies — SentinelWeave
=======================================================

Five higher-order offensive/research components that integrate
industry-standard security libraries.  These tools are designed for
**authorized penetration testers, malware analysts, and red-team operators**
who have *explicit written permission* to investigate the target systems.

.. warning::
    Use of these tools against systems or files you do not own or do not have
    explicit written authorization to test may violate the Computer Fraud and
    Abuse Act (CFAA), the UK Computer Misuse Act, and equivalent legislation.
    Always obtain written authorization before performing any security testing.

Components
----------
* :class:`ShellcodeAnalyzer` — Disassembles raw shellcode bytes with Capstone
  and classifies the presence of dangerous instruction patterns
  (syscall/int 0x80, ret2libc, shellcode stagers).

* :class:`YaraScanner` — Scans in-memory buffers or file content against
  YARA rules.  Bundles a default rule library for common malware patterns and
  accepts custom user-supplied rules at runtime.

* :class:`AnomalyDetector` — Builds a pandas DataFrame from port-scan or
  vulnerability-finding observations and applies scikit-learn IsolationForest
  anomaly detection.  Returns per-observation risk scores and a summary
  DataFrame suitable for downstream analysis.

* :class:`BinaryAuditor` — Wraps pwntools ELF + ROP analysis.  Reports binary
  security mitigations (NX, PIE, stack canary, RELRO, FORTIFY), extracts ROP
  gadgets, and generates cyclic fuzzing patterns for buffer-overflow research.

* :class:`MemoryForensicsScanner` — Wraps Volatility 3 to inspect a memory
  image and extract process lists, network connections, and injected-code
  indicators without requiring an interactive Volatility session.

Example usage::

    from sentinel_weave.advanced_offensive import ShellcodeAnalyzer

    analyzer = ShellcodeAnalyzer(arch="x86_64")
    result = analyzer.analyze(bytes.fromhex("4831c04889c7b03b0f05"))
    print(result.threat_level, result.mnemonic_summary)
"""

from __future__ import annotations

import io
import os
import re
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

# ---------------------------------------------------------------------------
# Optional third-party imports — each is wrapped so that the module remains
# importable even if a library is missing in the environment (e.g., during
# static analysis or minimal CI runs).
# ---------------------------------------------------------------------------

try:
    import capstone  # type: ignore[import-untyped]
    _HAS_CAPSTONE = True
except ImportError:
    capstone = None  # type: ignore[assignment]
    _HAS_CAPSTONE = False

try:
    import yara  # type: ignore[import-untyped]
    _HAS_YARA = True
except ImportError:
    yara = None  # type: ignore[assignment]
    _HAS_YARA = False

try:
    import pandas as pd  # type: ignore[import-untyped]
    from sklearn.ensemble import IsolationForest  # type: ignore[import-untyped]
    _HAS_SKLEARN = True
except ImportError:
    pd = None  # type: ignore[assignment]
    IsolationForest = None  # type: ignore[assignment]
    _HAS_SKLEARN = False

try:
    from pwnlib.elf import ELF  # type: ignore[import-untyped]
    from pwnlib.rop import ROP  # type: ignore[import-untyped]
    from pwnlib.util.cyclic import cyclic, cyclic_find  # type: ignore[import-untyped]
    _HAS_PWNTOOLS = True
except ImportError:
    ELF = None  # type: ignore[assignment]
    ROP = None  # type: ignore[assignment]
    cyclic = None  # type: ignore[assignment]
    cyclic_find = None  # type: ignore[assignment]
    _HAS_PWNTOOLS = False

try:
    from volatility3.framework import contexts as _vol_contexts
    from volatility3.framework import automagic as _vol_automagic
    from volatility3.framework import interfaces as _vol_interfaces
    from volatility3.framework import plugins as _vol_plugins
    from volatility3 import framework as _vol_framework
    _HAS_VOLATILITY = True
except ImportError:
    _vol_contexts = None  # type: ignore[assignment]
    _vol_automagic = None  # type: ignore[assignment]
    _vol_interfaces = None  # type: ignore[assignment]
    _vol_plugins = None  # type: ignore[assignment]
    _vol_framework = None  # type: ignore[assignment]
    _HAS_VOLATILITY = False

__all__ = [
    # ShellcodeAnalyzer
    "ShellcodeAnalyzer",
    "ShellcodeAnalysisResult",
    "DisassembledInstruction",
    # YaraScanner
    "YaraScanner",
    "YaraMatch",
    "YaraScanResult",
    "BUILTIN_RULE_NAMES",
    # AnomalyDetector
    "AnomalyDetector",
    "AnomalyRecord",
    "AnomalyReport",
    # BinaryAuditor
    "BinaryAuditor",
    "MitigationReport",
    "RopGadget",
    "BinaryAuditResult",
    # MemoryForensicsScanner
    "MemoryForensicsScanner",
    "ProcessEntry",
    "NetworkEntry",
    "ForensicsReport",
]

# ---------------------------------------------------------------------------
# ── 1. ShellcodeAnalyzer ─────────────────────────────────────────────────
# ---------------------------------------------------------------------------

_DANGEROUS_MNEMONICS: frozenset[str] = frozenset({
    "syscall", "sysenter", "int", "iret", "iretd", "iretq",
})

_CONTROL_FLOW_MNEMONICS: frozenset[str] = frozenset({
    "call", "jmp", "je", "jne", "jz", "jnz", "jl", "jle",
    "jg", "jge", "ja", "jae", "jb", "jbe", "ret", "retn", "retf",
})

# Simplified pattern name → byte sequences (any match flags shellcode as suspicious)
_SHELLCODE_PATTERNS: dict[str, list[bytes]] = {
    "execve_x86_64": [b"\x48\x31\xc0", b"\xb0\x3b", b"\x0f\x05"],   # xor rax,rax; mov al,0x3b; syscall
    "execve_x86":    [b"\x31\xc0", b"\xb0\x0b", b"\xcd\x80"],         # xor eax,eax; mov al,11; int 0x80
    "bind_shell":    [b"\x6a\x02", b"\x6a\x29"],                       # socket syscall args
    "reverse_shell": [b"\x6a\x66", b"\x31\xdb"],                       # socketcall / connect
    "nop_sled":      [b"\x90\x90\x90\x90\x90\x90\x90\x90"],              # classic NOP sled (≥8 bytes)
    "egg_hunter":    [b"\x66\x81\xca\xff\x0f"],                        # egghunter signature
}


@dataclass
class DisassembledInstruction:
    """A single disassembled instruction."""

    address: int
    mnemonic: str
    op_str: str
    bytes_hex: str

    def __str__(self) -> str:
        return f"0x{self.address:08x}  {self.mnemonic:<10} {self.op_str}"


@dataclass
class ShellcodeAnalysisResult:
    """
    Result of :meth:`ShellcodeAnalyzer.analyze`.

    Attributes
    ----------
    arch:
        Target architecture string (e.g. ``"x86_64"``).
    byte_count:
        Number of input bytes.
    instruction_count:
        Number of successfully decoded instructions.
    instructions:
        List of :class:`DisassembledInstruction` objects.
    mnemonic_summary:
        Frequency mapping of mnemonics → count.
    dangerous_mnemonics:
        Subset of mnemonics considered dangerous (syscall, int, …).
    matched_patterns:
        Known shellcode pattern names that were detected.
    entropy:
        Shannon entropy of the input bytes (0–8 bits).
    threat_level:
        One of ``"BENIGN"``, ``"SUSPICIOUS"``, ``"MALICIOUS"``.
    notes:
        Human-readable diagnostic notes.
    """

    arch: str
    byte_count: int
    instruction_count: int
    instructions: list[DisassembledInstruction]
    mnemonic_summary: dict[str, int]
    dangerous_mnemonics: list[str]
    matched_patterns: list[str]
    entropy: float
    threat_level: str
    notes: list[str]


class ShellcodeAnalyzer:
    """
    Disassemble raw shellcode bytes and classify their threat level.

    Uses the **Capstone** disassembly engine.

    Parameters
    ----------
    arch:
        One of ``"x86"``, ``"x86_64"``, ``"arm"``, ``"arm64"``
        (default: ``"x86_64"``).
    base_address:
        Virtual address to assign to the first byte of input
        (default: ``0x400000``).
    """

    _ARCH_MAP: dict[str, tuple[int, int]] = {
        "x86":    (0, 0),   # capstone.CS_ARCH_X86, capstone.CS_MODE_32
        "x86_64": (0, 8),   # capstone.CS_ARCH_X86, capstone.CS_MODE_64
        "arm":    (1, 4),   # capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM
        "arm64":  (2, 0),   # capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM
    }

    def __init__(
        self,
        arch: str = "x86_64",
        base_address: int = 0x400000,
    ) -> None:
        if arch not in self._ARCH_MAP:
            raise ValueError(
                f"arch must be one of {sorted(self._ARCH_MAP)}, got {arch!r}"
            )
        self.arch = arch
        self.base_address = base_address

    # ------------------------------------------------------------------
    def analyze(self, data: bytes) -> ShellcodeAnalysisResult:
        """
        Disassemble *data* and return a :class:`ShellcodeAnalysisResult`.

        Parameters
        ----------
        data:
            Raw shellcode bytes to analyse.
        """
        if not _HAS_CAPSTONE:
            raise RuntimeError(
                "capstone is required for ShellcodeAnalyzer. "
                "Install it with: pip install capstone"
            )

        cs_arch_id, cs_mode_id = self._ARCH_MAP[self.arch]
        # Resolve Capstone constants at runtime (avoids import-time issues)
        cs_arch = getattr(capstone, "CS_ARCH_X86") if cs_arch_id == 0 else (
            getattr(capstone, "CS_ARCH_ARM")   if cs_arch_id == 1 else
            getattr(capstone, "CS_ARCH_ARM64")
        )
        if cs_arch_id == 0:
            cs_mode = (
                getattr(capstone, "CS_MODE_64") if cs_mode_id == 8
                else getattr(capstone, "CS_MODE_32")
            )
        else:
            cs_mode = getattr(capstone, "CS_MODE_ARM")

        md = capstone.Cs(cs_arch, cs_mode)
        md.detail = False

        instructions: list[DisassembledInstruction] = []
        mnemonic_count: dict[str, int] = {}

        for insn in md.disasm(data, self.base_address):
            di = DisassembledInstruction(
                address   = insn.address,
                mnemonic  = insn.mnemonic,
                op_str    = insn.op_str,
                bytes_hex = insn.bytes.hex(),
            )
            instructions.append(di)
            mnemonic_count[insn.mnemonic] = mnemonic_count.get(insn.mnemonic, 0) + 1

        dangerous = [
            m for m in mnemonic_count
            if m.lower() in _DANGEROUS_MNEMONICS
        ]

        matched_patterns = self._detect_patterns(data)
        entropy = self._entropy(data)
        threat_level, notes = self._classify(
            dangerous, matched_patterns, entropy, len(instructions), len(data)
        )

        return ShellcodeAnalysisResult(
            arch              = self.arch,
            byte_count        = len(data),
            instruction_count = len(instructions),
            instructions      = instructions,
            mnemonic_summary  = mnemonic_count,
            dangerous_mnemonics = dangerous,
            matched_patterns  = matched_patterns,
            entropy           = round(entropy, 4),
            threat_level      = threat_level,
            notes             = notes,
        )

    # ------------------------------------------------------------------
    def _detect_patterns(self, data: bytes) -> list[str]:
        matched: list[str] = []
        for name, sequences in _SHELLCODE_PATTERNS.items():
            if all(seq in data for seq in sequences):
                matched.append(name)
        return matched

    @staticmethod
    def _entropy(data: bytes) -> float:
        if not data:
            return 0.0
        import math
        freq: dict[int, int] = {}
        for b in data:
            freq[b] = freq.get(b, 0) + 1
        length = len(data)
        return -sum(
            (c / length) * math.log2(c / length)
            for c in freq.values()
            if c > 0
        )

    @staticmethod
    def _classify(
        dangerous: list[str],
        patterns:  list[str],
        entropy:   float,
        n_insn:    int,
        n_bytes:   int,
    ) -> tuple[str, list[str]]:
        notes: list[str] = []
        score = 0

        if dangerous:
            score += 3
            notes.append(f"Dangerous mnemonics present: {', '.join(dangerous)}")
        if patterns:
            score += 4
            notes.append(f"Matched known shellcode patterns: {', '.join(patterns)}")
        if entropy > 6.5:
            score += 1
            notes.append(f"High entropy ({entropy:.2f} bits) — possible packed/encoded shellcode")
        if n_bytes > 0 and n_insn / n_bytes < 0.05:
            score += 1
            notes.append("Low instruction density — possible data/encoded blob")

        if score >= 4:
            return "MALICIOUS", notes
        if score >= 2:
            return "SUSPICIOUS", notes
        return "BENIGN", notes


# ---------------------------------------------------------------------------
# ── 2. YaraScanner ──────────────────────────────────────────────────────
# ---------------------------------------------------------------------------

#: Names of the built-in YARA rule sets that ship with SentinelWeave.
BUILTIN_RULE_NAMES: tuple[str, ...] = (
    "suspicious_strings",
    "shellcode_patterns",
    "crypto_constants",
    "packer_signatures",
    "network_iocs",
    "credential_harvesting",
    "process_injection",
    "persistence_mechanisms",
)

_BUILTIN_YARA_RULES: dict[str, str] = {
    "suspicious_strings": r"""
rule SuspiciousStrings {
    meta:
        description = "Detects common suspicious strings used by malware"
        severity    = "MEDIUM"
    strings:
        $cmd1  = "cmd.exe"           nocase
        $cmd2  = "powershell"        nocase
        $cmd3  = "wscript"           nocase
        $cmd4  = "cscript"           nocase
        $dl1   = "URLDownloadToFile" nocase
        $dl2   = "InternetOpenUrl"   nocase
        $dl3   = "WinHttpOpen"       nocase
        $pass1 = "password="         nocase
        $pass2 = "passwd="           nocase
        $enc1  = "base64_decode"
        $enc2  = "FromBase64String"
    condition:
        2 of them
}
""",
    "shellcode_patterns": r"""
rule ShellcodeNopSled {
    meta:
        description = "NOP sled followed by high-entropy code"
        severity    = "HIGH"
    strings:
        $nop_sled = { 90 90 90 90 90 90 90 90 }
    condition:
        $nop_sled
}
rule X86SyscallShellcode {
    meta:
        description = "x86 int 0x80 syscall pattern"
        severity    = "HIGH"
    strings:
        $int80  = { CD 80 }
        $xoreax = { 31 C0 }
    condition:
        all of them
}
rule X86_64Syscall {
    meta:
        description = "x86_64 syscall instruction"
        severity    = "HIGH"
    strings:
        $syscall = { 0F 05 }
    condition:
        $syscall
}
""",
    "crypto_constants": r"""
rule MagicCryptoConstants {
    meta:
        description = "RC4/AES/XOR key scheduling magic bytes"
        severity    = "LOW"
    strings:
        $aes_sbox  = { 63 7C 77 7B F2 6B 6F C5 }
        $rc4_start = { 00 01 02 03 04 05 06 07 }
        $xor_stub  = { 30 ?? 46 E2 FA }
    condition:
        any of them
}
""",
    "packer_signatures": r"""
rule UPXPacker {
    meta:
        description = "UPX packed binary"
        severity    = "MEDIUM"
    strings:
        $upx0 = "UPX0"
        $upx1 = "UPX1"
        $upx2 = "UPX!"
    condition:
        2 of them
}
rule ASPackPacker {
    meta:
        description = "ASPack packed binary"
        severity    = "MEDIUM"
    strings:
        $asp = ".aspack"
    condition:
        $asp
}
""",
    "network_iocs": r"""
rule SuspiciousNetworkActivity {
    meta:
        description = "Hardcoded IPs, C2 beacon strings, raw socket creation"
        severity    = "HIGH"
    strings:
        $sock1  = "SOCKET"         nocase
        $sock2  = "connect"        nocase
        $beacon = "beacon"         nocase
        $c2_1   = /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{2,5}\b/
        $onion  = ".onion"
    condition:
        2 of them
}
""",
    "credential_harvesting": r"""
rule CredentialHarvesting {
    meta:
        description = "Credential-dumping artefacts"
        severity    = "CRITICAL"
    strings:
        $lsass1  = "lsass.exe"          nocase
        $lsass2  = "lsass"              nocase
        $mimikatz = "sekurlsa"          nocase
        $sam     = "\\SAM"              nocase
        $ntds    = "ntds.dit"           nocase
        $cred    = "CredentialBlob"     nocase
    condition:
        any of them
}
""",
    "process_injection": r"""
rule ProcessInjection {
    meta:
        description = "Classic process injection API sequences"
        severity    = "HIGH"
    strings:
        $virt1  = "VirtualAllocEx"       nocase
        $virt2  = "VirtualProtectEx"     nocase
        $write  = "WriteProcessMemory"   nocase
        $create = "CreateRemoteThread"   nocase
        $nt1    = "NtWriteVirtualMemory" nocase
        $nt2    = "NtCreateThreadEx"     nocase
    condition:
        2 of them
}
""",
    "persistence_mechanisms": r"""
rule PersistenceMechanisms {
    meta:
        description = "Registry/scheduled-task persistence artefacts"
        severity    = "HIGH"
    strings:
        $reg1   = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"  nocase
        $reg2   = "HKEY_CURRENT_USER"                                  nocase
        $schtsk = "schtasks"                                            nocase
        $start  = "\\Startup"                                          nocase
        $serv   = "CreateService"                                       nocase
    condition:
        any of them
}
""",
}


@dataclass
class YaraMatch:
    """A single YARA rule match."""

    rule_name:   str
    rule_set:    str
    description: str
    severity:    str
    offset:      int
    data_hex:    str


@dataclass
class YaraScanResult:
    """
    Result of :meth:`YaraScanner.scan`.

    Attributes
    ----------
    match_count:
        Total number of rule matches.
    matches:
        List of :class:`YaraMatch` objects.
    severity:
        Highest severity among all matches, or ``"NONE"`` if no matches.
    rule_sets_used:
        Names of the YARA rule sets that were compiled and evaluated.
    """

    match_count:    int
    matches:        list[YaraMatch]
    severity:       str
    rule_sets_used: list[str]


_SEVERITY_ORDER = {"NONE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


class YaraScanner:
    """
    Scan byte buffers against YARA rules.

    Parameters
    ----------
    rule_sets:
        Names of built-in rule sets to load from
        :data:`BUILTIN_RULE_NAMES`.  Pass ``None`` to load all built-in
        sets (the default).
    extra_rules:
        Additional YARA source code string to compile alongside the built-in
        rules.  Useful for appending custom threat intelligence.
    """

    def __init__(
        self,
        rule_sets: list[str] | None = None,
        extra_rules: str = "",
    ) -> None:
        if not _HAS_YARA:
            raise RuntimeError(
                "yara-python is required for YaraScanner. "
                "Install it with: pip install yara-python"
            )
        self._rule_sets: list[str] = (
            list(BUILTIN_RULE_NAMES) if rule_sets is None else rule_sets
        )
        self._extra_rules = extra_rules
        self._compiled = self._compile()

    # ------------------------------------------------------------------
    def _compile(self) -> Any:
        source_parts: list[str] = []
        for name in self._rule_sets:
            if name not in _BUILTIN_YARA_RULES:
                raise ValueError(f"Unknown built-in rule set: {name!r}")
            source_parts.append(_BUILTIN_YARA_RULES[name])
        if self._extra_rules:
            source_parts.append(self._extra_rules)
        combined = "\n".join(source_parts)
        return yara.compile(source=combined)

    # ------------------------------------------------------------------
    def scan(self, data: bytes) -> YaraScanResult:
        """
        Scan *data* against the compiled YARA rules.

        Parameters
        ----------
        data:
            Raw bytes to scan (file content, memory buffer, etc.).
        """
        raw_matches = self._compiled.match(data=data)
        matches: list[YaraMatch] = []

        for m in raw_matches:
            description = m.meta.get("description", "")
            severity = m.meta.get("severity", "LOW")
            rule_set = self._find_rule_set(m.rule)
            # yara-python >= 4.3: m.strings is a list of StringMatch objects
            # each with an .instances attribute containing StringMatchInstance objects
            representative_offset    = 0
            representative_data_hex  = ""
            for string_match in m.strings:
                for inst in string_match.instances:
                    representative_offset   = inst.offset
                    representative_data_hex = bytes(inst.matched_data)[:32].hex()
                    break
                break  # only use the first string's first instance per rule
            matches.append(YaraMatch(
                rule_name   = m.rule,
                rule_set    = rule_set,
                description = description,
                severity    = severity,
                offset      = representative_offset,
                data_hex    = representative_data_hex,
            ))

        highest_sev = "NONE"
        for m in matches:
            if _SEVERITY_ORDER.get(m.severity, 0) > _SEVERITY_ORDER[highest_sev]:
                highest_sev = m.severity

        return YaraScanResult(
            match_count    = len(matches),
            matches        = matches,
            severity       = highest_sev,
            rule_sets_used = list(self._rule_sets),
        )

    def scan_file(self, path: str | Path) -> YaraScanResult:
        """Convenience wrapper that reads *path* and calls :meth:`scan`."""
        return self.scan(Path(path).read_bytes())

    def _find_rule_set(self, rule_name: str) -> str:
        for rs_name, src in _BUILTIN_YARA_RULES.items():
            if rule_name in src:
                return rs_name
        return "custom"

    @classmethod
    def compile_custom(cls, source: str) -> "YaraScanner":
        """
        Create a :class:`YaraScanner` that uses *only* the provided YARA
        source (no built-in rules).

        Parameters
        ----------
        source:
            Valid YARA rule source code.
        """
        scanner = object.__new__(cls)
        scanner._rule_sets = ["custom"]
        scanner._extra_rules = source
        if not _HAS_YARA:
            raise RuntimeError("yara-python is required for YaraScanner.")
        scanner._compiled = yara.compile(source=source)
        return scanner


# ---------------------------------------------------------------------------
# ── 3. AnomalyDetector ──────────────────────────────────────────────────
# ---------------------------------------------------------------------------

@dataclass
class AnomalyRecord:
    """
    A single observation annotated with an anomaly score.

    Attributes
    ----------
    index:
        Original row index in the input sequence.
    features:
        Dict of feature name → numeric value used for scoring.
    anomaly_score:
        Raw IsolationForest decision score (lower → more anomalous).
    is_anomaly:
        ``True`` when the model classifies this record as an outlier.
    risk_label:
        One of ``"NORMAL"``, ``"SUSPICIOUS"``, or ``"ANOMALOUS"``.
    """

    index:         int
    features:      dict[str, float]
    anomaly_score: float
    is_anomaly:    bool
    risk_label:    str


@dataclass
class AnomalyReport:
    """
    Full result of :meth:`AnomalyDetector.detect`.

    Attributes
    ----------
    total_observations:
        Number of input observations.
    anomaly_count:
        Number classified as anomalous.
    contamination:
        Contamination parameter used to train IsolationForest.
    records:
        All annotated records.
    summary_df:
        pandas DataFrame with all records + scores (``None`` if pandas
        is unavailable).
    """

    total_observations: int
    anomaly_count:      int
    contamination:      float
    records:            list[AnomalyRecord]
    summary_df:         Any  # pd.DataFrame | None


class AnomalyDetector:
    """
    Unsupervised anomaly detection on security-event observations.

    Fits an **IsolationForest** model from *scikit-learn* on a set of
    feature dictionaries, then classifies each observation as normal or
    anomalous.  Uses **pandas** for feature extraction and result
    presentation.

    Parameters
    ----------
    contamination:
        Expected fraction of anomalies in the dataset (passed directly to
        :class:`sklearn.ensemble.IsolationForest`).  Defaults to
        ``"auto"``.
    n_estimators:
        Number of trees in the IsolationForest (default: 100).
    random_state:
        Random seed for reproducibility (default: 42).
    """

    def __init__(
        self,
        contamination: float | str = "auto",
        n_estimators: int = 100,
        random_state: int = 42,
    ) -> None:
        if not _HAS_SKLEARN:
            raise RuntimeError(
                "scikit-learn and pandas are required for AnomalyDetector. "
                "Install with: pip install scikit-learn pandas"
            )
        self.contamination = contamination
        self.n_estimators  = n_estimators
        self.random_state  = random_state

    # ------------------------------------------------------------------
    def detect(
        self,
        observations: list[dict[str, float]],
    ) -> AnomalyReport:
        """
        Detect anomalies in *observations*.

        Parameters
        ----------
        observations:
            A list of dicts, each mapping feature names to numeric values.
            All dicts should share the same key set.  Missing values are
            filled with 0.

        Returns
        -------
        :class:`AnomalyReport`
        """
        if not observations:
            return AnomalyReport(
                total_observations = 0,
                anomaly_count      = 0,
                contamination      = 0.0,
                records            = [],
                summary_df         = pd.DataFrame() if _HAS_SKLEARN else None,
            )

        df = pd.DataFrame(observations).fillna(0.0)
        # Keep only numeric columns
        numeric_df = df.select_dtypes(include="number")
        if numeric_df.empty:
            raise ValueError("No numeric features found in observations")

        model = IsolationForest(
            contamination = self.contamination,
            n_estimators  = self.n_estimators,
            random_state  = self.random_state,
        )
        labels = model.fit_predict(numeric_df)          # 1 = normal, -1 = anomaly
        scores = model.decision_function(numeric_df)    # higher = more normal

        records: list[AnomalyRecord] = []
        for i, (label, score) in enumerate(zip(labels, scores)):
            is_anomaly = label == -1
            if is_anomaly:
                risk = "ANOMALOUS"
            elif score < 0.05:
                risk = "SUSPICIOUS"
            else:
                risk = "NORMAL"
            records.append(AnomalyRecord(
                index         = i,
                features      = observations[i],
                anomaly_score = round(float(score), 4),
                is_anomaly    = bool(is_anomaly),
                risk_label    = risk,
            ))

        result_df = numeric_df.copy()
        result_df["anomaly_score"] = scores
        result_df["is_anomaly"]    = labels == -1
        result_df["risk_label"]    = [r.risk_label for r in records]

        cont_val = float(
            sum(labels == -1) / len(labels) if self.contamination == "auto"
            else self.contamination
        )

        return AnomalyReport(
            total_observations = len(observations),
            anomaly_count      = int(sum(r.is_anomaly for r in records)),
            contamination      = round(cont_val, 4),
            records            = records,
            summary_df         = result_df,
        )

    # ------------------------------------------------------------------
    def from_port_scan_results(self, results: list[Any]) -> AnomalyReport:
        """
        Convert a list of :class:`~sentinel_weave.red_team_toolkit.PortScanResult`
        objects into feature dicts and run :meth:`detect`.

        Features extracted per result:
        ``port``, ``is_open``, ``has_banner``.
        """
        obs: list[dict[str, float]] = []
        for r in results:
            obs.append({
                "port":       float(r.port),
                "is_open":    1.0 if r.is_open else 0.0,
                "has_banner": 1.0 if (r.banner if hasattr(r, "banner") else "") else 0.0,
            })
        return self.detect(obs)


# ---------------------------------------------------------------------------
# ── 4. BinaryAuditor ────────────────────────────────────────────────────
# ---------------------------------------------------------------------------

@dataclass
class MitigationReport:
    """
    Security mitigations detected in an ELF binary.

    All boolean fields default to ``False`` (not present / not enabled).
    """

    nx:           bool = False   # Non-executable stack (NX/DEP)
    pie:          bool = False   # Position-independent executable
    canary:       bool = False   # Stack canary / SSP
    relro:        str  = "No"    # "No" | "Partial" | "Full"
    fortify:      bool = False   # FORTIFY_SOURCE
    stripped:     bool = False   # Debug symbols stripped

    def as_dict(self) -> dict[str, Any]:
        return {
            "nx":      self.nx,
            "pie":     self.pie,
            "canary":  self.canary,
            "relro":   self.relro,
            "fortify": self.fortify,
            "stripped": self.stripped,
        }


@dataclass
class RopGadget:
    """A single ROP gadget extracted from a binary."""

    address:    int
    insns:      str    # mnemonic sequence, e.g. "pop rdi ; ret"
    bytes_hex:  str


@dataclass
class BinaryAuditResult:
    """
    Full result of :meth:`BinaryAuditor.audit`.

    Attributes
    ----------
    path:
        Path to the audited binary.
    arch:
        Architecture string (e.g. ``"amd64"``).
    mitigations:
        :class:`MitigationReport` describing security mitigations.
    rop_gadgets:
        List of discovered :class:`RopGadget` objects (capped at
        ``max_gadgets``).
    cyclic_pattern:
        Sample cyclic fuzzing pattern of ``pattern_length`` bytes.
    notes:
        Human-readable risk notes.
    """

    path:           str
    arch:           str
    mitigations:    MitigationReport
    rop_gadgets:    list[RopGadget]
    cyclic_pattern: bytes
    notes:          list[str]


class BinaryAuditor:
    """
    Audit an ELF binary for security mitigations and exploitation primitives.

    Uses **pwntools** (``pwnlib.elf`` and ``pwnlib.rop``) for binary loading
    and gadget discovery, and ``pwnlib.util.cyclic`` for fuzzing pattern
    generation.

    Parameters
    ----------
    max_gadgets:
        Maximum number of ROP gadgets to return (default: 50).
    pattern_length:
        Length of the cyclic fuzzing pattern to generate (default: 64).
    """

    def __init__(
        self,
        max_gadgets:    int = 50,
        pattern_length: int = 64,
    ) -> None:
        if not _HAS_PWNTOOLS:
            raise RuntimeError(
                "pwntools is required for BinaryAuditor. "
                "Install with: pip install pwntools"
            )
        self.max_gadgets    = max_gadgets
        self.pattern_length = pattern_length

    # ------------------------------------------------------------------
    def audit(self, path: str | Path) -> BinaryAuditResult:
        """
        Load the ELF binary at *path* and return a :class:`BinaryAuditResult`.

        Parameters
        ----------
        path:
            Filesystem path to an ELF binary.
        """
        import pwnlib.context as _ctx  # noqa: PLC0415
        _ctx.context.log_level = "error"  # suppress pwntools banner

        elf = ELF(str(path), checksec=False)
        mitigations = self._checksec(elf)
        gadgets     = self._extract_gadgets(elf)
        pattern     = bytes(cyclic(self.pattern_length))
        notes       = self._generate_notes(mitigations, gadgets)

        return BinaryAuditResult(
            path           = str(path),
            arch           = elf.arch,
            mitigations    = mitigations,
            rop_gadgets    = gadgets,
            cyclic_pattern = pattern,
            notes          = notes,
        )

    # ------------------------------------------------------------------
    def _checksec(self, elf: Any) -> MitigationReport:
        return MitigationReport(
            nx      = bool(getattr(elf, "nx",      False)),
            pie     = bool(getattr(elf, "pie",     False)),
            canary  = bool(getattr(elf, "canary",  False)),
            relro   = self._relro_str(elf),
            fortify = bool(getattr(elf, "fortify", False)),
            stripped = not bool(elf.symbols),
        )

    @staticmethod
    def _relro_str(elf: Any) -> str:
        relro = getattr(elf, "relro", None)
        if relro is None:
            return "No"
        low = str(relro).lower()
        if "full" in low:
            return "Full"
        if "partial" in low:
            return "Partial"
        return "No"

    def _extract_gadgets(self, elf: Any) -> list[RopGadget]:
        try:
            rop = ROP(elf)
            gadgets: list[RopGadget] = []
            for addr, g in list(rop.gadgets.items())[: self.max_gadgets]:
                insns = " ; ".join(str(i).split(":")[0].strip() for i in g.insns)
                gadgets.append(RopGadget(
                    address   = addr,
                    insns     = insns,
                    bytes_hex = "",
                ))
            return gadgets
        except Exception:
            return []

    @staticmethod
    def _generate_notes(m: MitigationReport, gadgets: list[RopGadget]) -> list[str]:
        notes: list[str] = []
        if not m.nx:
            notes.append("NX not enabled — stack/heap may be executable (shellcode injection risk)")
        if not m.pie:
            notes.append("PIE not enabled — fixed load address makes ROP easier")
        if not m.canary:
            notes.append("Stack canary absent — classic stack buffer overflows possible")
        if m.relro == "No":
            notes.append("RELRO not enabled — GOT overwrite attacks possible")
        elif m.relro == "Partial":
            notes.append("Partial RELRO — GOT is still writable")
        if not m.fortify:
            notes.append("FORTIFY_SOURCE not enabled")
        if gadgets:
            notes.append(f"{len(gadgets)} ROP gadgets found — ROP chain construction feasible")
        if not notes:
            notes.append("Binary has strong security mitigations")
        return notes

    def generate_pattern(self, length: int | None = None) -> bytes:
        """
        Generate a cyclic de-Bruijn fuzzing pattern.

        Parameters
        ----------
        length:
            Length of the pattern. Defaults to :attr:`pattern_length`.
        """
        return bytes(cyclic(length or self.pattern_length))

    def find_offset(self, pattern: bytes, value: bytes) -> int | None:
        """
        Find the offset of *value* in a cyclic pattern.

        Returns ``None`` if *value* is not found.
        """
        try:
            return cyclic_find(value)
        except Exception:
            return None


# ---------------------------------------------------------------------------
# ── 5. MemoryForensicsScanner ────────────────────────────────────────────
# ---------------------------------------------------------------------------

@dataclass
class ProcessEntry:
    """A single process entry from a memory image."""

    pid:         int
    ppid:        int
    name:        str
    offset:      str   # hex string of virtual offset
    is_suspicious: bool
    reasons:     list[str]


@dataclass
class NetworkEntry:
    """A network connection entry from a memory image."""

    protocol:    str
    local_addr:  str
    local_port:  int
    remote_addr: str
    remote_port: int
    state:       str
    pid:         int


@dataclass
class ForensicsReport:
    """
    Full result of :meth:`MemoryForensicsScanner.scan`.

    Attributes
    ----------
    image_path:
        Path to the memory image file.
    os_profile:
        Detected OS profile string (e.g. ``"Win10x64_19041"``).
    process_count:
        Total number of processes found.
    suspicious_process_count:
        Number of processes flagged as suspicious.
    processes:
        List of :class:`ProcessEntry` objects.
    network_entries:
        List of :class:`NetworkEntry` objects.
    injected_code_indicators:
        List of human-readable strings describing suspected code injection.
    notes:
        Analyst-level notes and recommendations.
    """

    image_path:                 str
    os_profile:                 str
    process_count:              int
    suspicious_process_count:   int
    processes:                  list[ProcessEntry]
    network_entries:            list[NetworkEntry]
    injected_code_indicators:   list[str]
    notes:                      list[str]


# Processes whose presence is inherently suspicious in most environments
_SUSPICIOUS_PROCESS_NAMES: frozenset[str] = frozenset({
    "mimikatz.exe", "wce.exe", "fgdump.exe", "pwdump.exe",
    "procdump.exe", "meterpreter", "nc.exe", "netcat.exe",
    "ncat.exe", "psexec.exe", "psexesvc.exe",
    "wmiexec.exe", "smbexec.exe", "cobaltstrike", "beacon.exe",
})

# Parent–child relationships that are inherently suspicious
_SUSPICIOUS_PARENT_CHILD: frozenset[tuple[str, str]] = frozenset({
    ("winword.exe",    "cmd.exe"),
    ("excel.exe",      "cmd.exe"),
    ("winword.exe",    "powershell.exe"),
    ("excel.exe",      "powershell.exe"),
    ("outlook.exe",    "cmd.exe"),
    ("iexplore.exe",   "cmd.exe"),
    ("chrome.exe",     "cmd.exe"),
    ("mshta.exe",      "powershell.exe"),
    ("wscript.exe",    "cmd.exe"),
    ("cscript.exe",    "cmd.exe"),
})


class MemoryForensicsScanner:
    """
    Inspect a memory image using **Volatility 3**.

    This class provides a high-level interface over Volatility 3's plugin
    architecture.  It extracts process lists and network connections and
    applies heuristic rules to flag suspicious artefacts.

    Parameters
    ----------
    os_profile:
        Volatility 3 OS profile string (e.g. ``"Win10x64_19041"``).  When
        ``None`` (default), automagic profile detection is used.
    """

    def __init__(self, os_profile: str | None = None) -> None:
        if not _HAS_VOLATILITY:
            raise RuntimeError(
                "volatility3 is required for MemoryForensicsScanner. "
                "Install with: pip install volatility3"
            )
        self.os_profile = os_profile

    # ------------------------------------------------------------------
    def scan(self, image_path: str | Path) -> ForensicsReport:
        """
        Scan the memory image at *image_path* and return a
        :class:`ForensicsReport`.

        Parameters
        ----------
        image_path:
            Path to a raw/vmem/lime memory dump file.
        """
        image_path = str(image_path)
        if not os.path.isfile(image_path):
            raise FileNotFoundError(f"Memory image not found: {image_path!r}")

        ctx, automagics = self._build_context(image_path)
        processes    = self._list_processes(ctx, automagics, image_path)
        network      = self._list_network(ctx, automagics, image_path)
        injected     = self._detect_injection(ctx, automagics, image_path, processes)
        profile      = self._detect_profile(ctx, automagics, image_path)
        notes        = self._build_notes(processes, network, injected)

        suspicious = [p for p in processes if p.is_suspicious]

        return ForensicsReport(
            image_path               = image_path,
            os_profile               = profile,
            process_count            = len(processes),
            suspicious_process_count = len(suspicious),
            processes                = processes,
            network_entries          = network,
            injected_code_indicators = injected,
            notes                    = notes,
        )

    # ------------------------------------------------------------------
    def _build_context(self, image_path: str) -> tuple[Any, Any]:
        """Build a Volatility 3 context and discover automagic layers."""
        ctx = _vol_contexts.Context()
        _vol_framework.require_interface_version(2, 0, 0)

        single_location = "file://" + os.path.abspath(image_path)
        ctx.config["automagic.LayerStacker.single_location"] = single_location

        automagics = _vol_automagic.available(ctx)
        return ctx, automagics

    # ------------------------------------------------------------------
    def _detect_profile(self, ctx: Any, automagics: Any, image_path: str) -> str:
        try:
            from volatility3.framework.plugins.windows import info as _info_plugin  # noqa
            list(_vol_automagic.run(automagics, _info_plugin.Info, ctx, ""))
            banner = ctx.config.get("automagic.WinSwapLayers.kernel_banner", "")
            if banner:
                return str(banner)
        except Exception:
            pass
        return self.os_profile or "unknown"

    # ------------------------------------------------------------------
    def _list_processes(
        self, ctx: Any, automagics: Any, image_path: str
    ) -> list[ProcessEntry]:
        entries: list[ProcessEntry] = []
        try:
            from volatility3.framework.plugins.windows import pslist as _pslist  # noqa
            procs = list(
                _vol_automagic.run(automagics, _pslist.PsList, ctx, "")
            )
            # Build a pid→name map for parent-lookup
            pid_name: dict[int, str] = {}
            for p in procs:
                try:
                    pid_name[int(p.UniqueProcessId)] = str(p.ImageFileName or "")
                except Exception:
                    pass

            for p in procs:
                try:
                    pid  = int(p.UniqueProcessId)
                    ppid = int(p.InheritedFromUniqueProcessId)
                    name = str(p.ImageFileName or "").lower()
                    parent_name = pid_name.get(ppid, "").lower()
                    offset = hex(int(p.vol.offset))
                    suspicious, reasons = self._assess_process(
                        name, pid, ppid, parent_name
                    )
                    entries.append(ProcessEntry(
                        pid          = pid,
                        ppid         = ppid,
                        name         = name,
                        offset       = offset,
                        is_suspicious = suspicious,
                        reasons      = reasons,
                    ))
                except Exception:
                    continue
        except Exception:
            pass
        return entries

    # ------------------------------------------------------------------
    def _list_network(
        self, ctx: Any, automagics: Any, image_path: str
    ) -> list[NetworkEntry]:
        entries: list[NetworkEntry] = []
        try:
            from volatility3.framework.plugins.windows import netscan as _netscan  # noqa
            conns = list(
                _vol_automagic.run(automagics, _netscan.NetScan, ctx, "")
            )
            for c in conns:
                try:
                    entries.append(NetworkEntry(
                        protocol    = str(c.Proto),
                        local_addr  = str(c.LocalAddr),
                        local_port  = int(c.LocalPort),
                        remote_addr = str(c.ForeignAddr),
                        remote_port = int(c.ForeignPort),
                        state       = str(c.State),
                        pid         = int(c.PID),
                    ))
                except Exception:
                    continue
        except Exception:
            pass
        return entries

    # ------------------------------------------------------------------
    def _detect_injection(
        self,
        ctx: Any,
        automagics: Any,
        image_path: str,
        processes: list[ProcessEntry],
    ) -> list[str]:
        indicators: list[str] = []
        try:
            from volatility3.framework.plugins.windows import malfind as _mf  # noqa
            hits = list(
                _vol_automagic.run(automagics, _mf.VadYaraScan, ctx, "")
            )
            for hit in hits:
                try:
                    indicators.append(
                        f"Possible injected code in PID {hit.PID} "
                        f"at 0x{hit.Start:08x} (rule: {hit.Rule})"
                    )
                except Exception:
                    continue
        except Exception:
            pass
        return indicators

    # ------------------------------------------------------------------
    @staticmethod
    def _assess_process(
        name: str, pid: int, ppid: int, parent_name: str
    ) -> tuple[bool, list[str]]:
        reasons: list[str] = []

        if name in _SUSPICIOUS_PROCESS_NAMES:
            reasons.append(f"Process name {name!r} is a known offensive tool")

        for parent_pattern, child_pattern in _SUSPICIOUS_PARENT_CHILD:
            if parent_pattern in parent_name and child_pattern in name:
                reasons.append(
                    f"Suspicious parent-child: {parent_name!r} → {name!r}"
                )

        # Hollow process heuristic: PID 0 parent with non-system process name
        if ppid == 0 and name not in {"system", "idle"}:
            reasons.append("Parent PID is 0 — possible process hollowing")

        return bool(reasons), reasons

    @staticmethod
    def _build_notes(
        processes: list[ProcessEntry],
        network:   list[NetworkEntry],
        injected:  list[str],
    ) -> list[str]:
        notes: list[str] = []
        suspicious = [p for p in processes if p.is_suspicious]
        if suspicious:
            names = ", ".join(p.name for p in suspicious[:5])
            notes.append(f"Suspicious processes detected: {names}")
        if network:
            notes.append(f"{len(network)} active network connections found")
        if injected:
            notes.append(
                f"{len(injected)} code-injection indicators — investigate with malfind"
            )
        if not notes:
            notes.append("No obvious artefacts detected in this memory image")
        return notes
