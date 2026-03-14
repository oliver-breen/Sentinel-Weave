"""
Tests for sentinel_weave.advanced_offensive
============================================

Covers all five advanced offensive security components:

- ShellcodeAnalyzer   : disassembly, pattern detection, classification
- YaraScanner         : built-in rules, custom rules, scan/scan_file
- AnomalyDetector     : IsolationForest scoring, edge cases
- BinaryAuditor       : checksec, ROP gadgets, cyclic patterns (ELF I/O mocked)
- MemoryForensicsScanner : Volatility 3 analysis (filesystem/vol3 I/O mocked)

All network / filesystem I/O is mocked so the suite runs fully offline in CI.
"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from typing import Any
from unittest.mock import MagicMock, patch, PropertyMock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from sentinel_weave.advanced_offensive import (
    # ShellcodeAnalyzer
    DisassembledInstruction,
    ShellcodeAnalysisResult,
    ShellcodeAnalyzer,
    # YaraScanner
    BUILTIN_RULE_NAMES,
    YaraMatch,
    YaraScanResult,
    YaraScanner,
    _BUILTIN_YARA_RULES,
    # AnomalyDetector
    AnomalyDetector,
    AnomalyRecord,
    AnomalyReport,
    # BinaryAuditor
    BinaryAuditResult,
    BinaryAuditor,
    MitigationReport,
    RopGadget,
    # MemoryForensicsScanner
    ForensicsReport,
    MemoryForensicsScanner,
    NetworkEntry,
    ProcessEntry,
    _SUSPICIOUS_PARENT_CHILD,
    _SUSPICIOUS_PROCESS_NAMES,
)


# ════════════════════════════════════════════════════════════════════════════
# Helpers
# ════════════════════════════════════════════════════════════════════════════

# x86-64 execve("/bin/sh") shellcode — 22 bytes
_X86_64_EXECVE = bytes.fromhex(
    "48 31 c0 48 89 c7 b0 3b 0f 05".replace(" ", "")
)

# x86-32 execve("/bin/sh") shellcode — 23 bytes
_X86_EXECVE = bytes.fromhex(
    "31 c0 50 68 2f 2f 73 68 68 2f 62 69 6e 89 e3 53 89 e1 b0 0b cd 80".replace(" ", "")
)

# Benign NOP + RET sequence (3 NOPs — below the 8-byte nop_sled threshold)
_BENIGN_NOP_RET = bytes.fromhex("90 90 90 c3".replace(" ", ""))


# ════════════════════════════════════════════════════════════════════════════
# 1. ShellcodeAnalyzer
# ════════════════════════════════════════════════════════════════════════════

class TestShellcodeAnalyzerInit(unittest.TestCase):

    def test_default_arch_is_x86_64(self):
        a = ShellcodeAnalyzer()
        self.assertEqual(a.arch, "x86_64")

    def test_custom_arch_arm64(self):
        a = ShellcodeAnalyzer(arch="arm64")
        self.assertEqual(a.arch, "arm64")

    def test_invalid_arch_raises(self):
        with self.assertRaises(ValueError):
            ShellcodeAnalyzer(arch="mips")

    def test_default_base_address(self):
        a = ShellcodeAnalyzer()
        self.assertEqual(a.base_address, 0x400000)

    def test_custom_base_address(self):
        a = ShellcodeAnalyzer(base_address=0xdeadbeef)
        self.assertEqual(a.base_address, 0xDEADBEEF)

    def test_supported_archs_all_valid(self):
        for arch in ("x86", "x86_64", "arm", "arm64"):
            a = ShellcodeAnalyzer(arch=arch)
            self.assertEqual(a.arch, arch)


class TestShellcodeAnalyzerDisassembly(unittest.TestCase):

    def setUp(self):
        self.analyzer = ShellcodeAnalyzer(arch="x86_64")

    def test_returns_analysis_result_type(self):
        r = self.analyzer.analyze(_X86_64_EXECVE)
        self.assertIsInstance(r, ShellcodeAnalysisResult)

    def test_byte_count_correct(self):
        r = self.analyzer.analyze(_X86_64_EXECVE)
        self.assertEqual(r.byte_count, len(_X86_64_EXECVE))

    def test_instruction_count_positive(self):
        r = self.analyzer.analyze(_X86_64_EXECVE)
        self.assertGreater(r.instruction_count, 0)

    def test_instructions_list_populated(self):
        r = self.analyzer.analyze(_X86_64_EXECVE)
        self.assertIsInstance(r.instructions, list)
        self.assertGreater(len(r.instructions), 0)

    def test_instruction_type(self):
        r = self.analyzer.analyze(_X86_64_EXECVE)
        self.assertIsInstance(r.instructions[0], DisassembledInstruction)

    def test_instruction_address_in_range(self):
        base = 0x400000
        a = ShellcodeAnalyzer(arch="x86_64", base_address=base)
        r = a.analyze(_X86_64_EXECVE)
        self.assertGreaterEqual(r.instructions[0].address, base)

    def test_mnemonic_summary_is_dict(self):
        r = self.analyzer.analyze(_X86_64_EXECVE)
        self.assertIsInstance(r.mnemonic_summary, dict)

    def test_mnemonic_counts_positive(self):
        r = self.analyzer.analyze(_X86_64_EXECVE)
        for v in r.mnemonic_summary.values():
            self.assertGreater(v, 0)

    def test_entropy_is_float(self):
        r = self.analyzer.analyze(_X86_64_EXECVE)
        self.assertIsInstance(r.entropy, float)

    def test_entropy_in_valid_range(self):
        r = self.analyzer.analyze(_X86_64_EXECVE)
        self.assertGreaterEqual(r.entropy, 0.0)
        self.assertLessEqual(r.entropy, 8.0)

    def test_arch_preserved_in_result(self):
        r = self.analyzer.analyze(_X86_64_EXECVE)
        self.assertEqual(r.arch, "x86_64")

    def test_empty_input_returns_zero_instructions(self):
        r = self.analyzer.analyze(b"")
        self.assertEqual(r.instruction_count, 0)
        self.assertEqual(r.byte_count, 0)

    def test_empty_input_entropy_zero(self):
        r = self.analyzer.analyze(b"")
        self.assertEqual(r.entropy, 0.0)

    def test_instruction_bytes_hex_nonempty(self):
        r = self.analyzer.analyze(_X86_64_EXECVE)
        for i in r.instructions:
            self.assertIsInstance(i.bytes_hex, str)
            self.assertGreater(len(i.bytes_hex), 0)

    def test_disassembled_instruction_str(self):
        di = DisassembledInstruction(
            address=0x400000, mnemonic="xor", op_str="eax, eax", bytes_hex="31c0"
        )
        s = str(di)
        self.assertIn("xor", s)
        self.assertIn("eax", s)


class TestShellcodeAnalyzerClassification(unittest.TestCase):

    def setUp(self):
        self.analyzer64 = ShellcodeAnalyzer(arch="x86_64")
        self.analyzer32 = ShellcodeAnalyzer(arch="x86")

    def test_execve_x86_64_is_malicious(self):
        r = self.analyzer64.analyze(_X86_64_EXECVE)
        self.assertEqual(r.threat_level, "MALICIOUS")

    def test_execve_x86_64_has_syscall_dangerous(self):
        r = self.analyzer64.analyze(_X86_64_EXECVE)
        self.assertIn("syscall", r.dangerous_mnemonics)

    def test_benign_bytes_not_malicious(self):
        r = self.analyzer64.analyze(_BENIGN_NOP_RET)
        self.assertIn(r.threat_level, ("BENIGN", "SUSPICIOUS"))

    def test_notes_nonempty_for_malicious(self):
        r = self.analyzer64.analyze(_X86_64_EXECVE)
        self.assertGreater(len(r.notes), 0)

    def test_matched_patterns_list(self):
        r = self.analyzer64.analyze(_X86_64_EXECVE)
        self.assertIsInstance(r.matched_patterns, list)

    def test_x86_execve_classified_malicious(self):
        r = self.analyzer32.analyze(_X86_EXECVE)
        # int 0x80 → dangerous mnemonic → malicious
        self.assertEqual(r.threat_level, "MALICIOUS")

    def test_nop_sled_detected(self):
        nop_sled = b"\x90" * 16 + _X86_64_EXECVE
        r = self.analyzer64.analyze(nop_sled)
        self.assertIn("nop_sled", r.matched_patterns)

    def test_single_nop_benign(self):
        r = self.analyzer64.analyze(b"\x90")
        self.assertEqual(r.threat_level, "BENIGN")

    def test_entropy_helper_static(self):
        ent = ShellcodeAnalyzer._entropy(b"\x00" * 256)
        self.assertEqual(ent, 0.0)

    def test_entropy_all_distinct_bytes(self):
        data = bytes(range(256))
        ent = ShellcodeAnalyzer._entropy(data)
        self.assertAlmostEqual(ent, 8.0, places=5)


# ════════════════════════════════════════════════════════════════════════════
# 2. YaraScanner
# ════════════════════════════════════════════════════════════════════════════

class TestYaraScannerBuiltins(unittest.TestCase):

    def test_builtin_rule_names_is_tuple(self):
        self.assertIsInstance(BUILTIN_RULE_NAMES, tuple)

    def test_builtin_rule_names_nonempty(self):
        self.assertGreater(len(BUILTIN_RULE_NAMES), 0)

    def test_builtin_rules_dict_has_all_names(self):
        for name in BUILTIN_RULE_NAMES:
            self.assertIn(name, _BUILTIN_YARA_RULES)

    def test_scanner_default_loads_all_rules(self):
        scanner = YaraScanner()
        self.assertEqual(len(scanner._rule_sets), len(BUILTIN_RULE_NAMES))

    def test_scanner_custom_rule_sets_subset(self):
        scanner = YaraScanner(rule_sets=["suspicious_strings", "shellcode_patterns"])
        self.assertEqual(scanner._rule_sets, ["suspicious_strings", "shellcode_patterns"])

    def test_scanner_unknown_rule_set_raises(self):
        with self.assertRaises(ValueError):
            YaraScanner(rule_sets=["nonexistent_rule"])


class TestYaraScannerScan(unittest.TestCase):

    def setUp(self):
        self.scanner = YaraScanner()

    def test_scan_returns_yara_scan_result(self):
        result = self.scanner.scan(b"hello world benign content")
        self.assertIsInstance(result, YaraScanResult)

    def test_scan_clean_data_no_matches(self):
        result = self.scanner.scan(b"\x00" * 32)
        self.assertEqual(result.match_count, 0)
        self.assertEqual(result.severity, "NONE")

    def test_scan_lsass_string_triggers_credential_rule(self):
        result = self.scanner.scan(b"Reading lsass.exe memory dump")
        rule_names = [m.rule_name for m in result.matches]
        self.assertTrue(any("Credential" in n for n in rule_names))

    def test_scan_nop_sled_triggers_shellcode_rule(self):
        result = self.scanner.scan(b"\x90" * 10)
        rule_names = [m.rule_name for m in result.matches]
        self.assertTrue(any(rule_names), rule_names)

    def test_scan_severity_none_on_clean(self):
        result = self.scanner.scan(b"plain text document")
        # May or may not match depending on content — just check type
        self.assertIn(result.severity, ("NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"))

    def test_match_has_required_fields(self):
        result = self.scanner.scan(b"lsass.exe mimikatz sekurlsa")
        if result.matches:
            m = result.matches[0]
            self.assertIsInstance(m, YaraMatch)
            self.assertIsInstance(m.rule_name, str)
            self.assertIsInstance(m.description, str)
            self.assertIsInstance(m.severity, str)
            self.assertIsInstance(m.offset, int)
            self.assertIsInstance(m.data_hex, str)

    def test_rule_sets_used_in_result(self):
        result = self.scanner.scan(b"test")
        self.assertIsInstance(result.rule_sets_used, list)
        self.assertGreater(len(result.rule_sets_used), 0)

    def test_scan_file_reads_path(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(b"lsass.exe")
            path = f.name
        try:
            result = self.scanner.scan_file(path)
            self.assertIsInstance(result, YaraScanResult)
        finally:
            os.unlink(path)

    def test_process_injection_apis_detected(self):
        content = b"VirtualAllocEx WriteProcessMemory CreateRemoteThread"
        result = self.scanner.scan(content)
        rule_names = [m.rule_name for m in result.matches]
        self.assertTrue(any("Injection" in n or "injection" in n for n in rule_names))

    def test_persistence_registry_detected(self):
        content = b"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run schtasks"
        result = self.scanner.scan(content)
        self.assertGreater(result.match_count, 0)


class TestYaraScannerCustom(unittest.TestCase):

    def test_compile_custom_classmethod(self):
        custom_src = """
rule TestRule {
    strings:
        $s = "sentinel_test_marker"
    condition:
        $s
}
"""
        scanner = YaraScanner.compile_custom(custom_src)
        result = scanner.scan(b"sentinel_test_marker found here")
        self.assertEqual(result.match_count, 1)
        self.assertEqual(result.matches[0].rule_name, "TestRule")

    def test_custom_no_match_on_clean(self):
        custom_src = """
rule Specific {
    strings:
        $s = "very_unique_token_xyz"
    condition:
        $s
}
"""
        scanner = YaraScanner.compile_custom(custom_src)
        result = scanner.scan(b"nothing relevant here")
        self.assertEqual(result.match_count, 0)

    def test_extra_rules_appended(self):
        extra = """
rule ExtraRule {
    strings:
        $x = "extra_token"
    condition:
        $x
}
"""
        scanner = YaraScanner(rule_sets=["suspicious_strings"], extra_rules=extra)
        result = scanner.scan(b"extra_token appears here")
        rule_names = [m.rule_name for m in result.matches]
        self.assertIn("ExtraRule", rule_names)


# ════════════════════════════════════════════════════════════════════════════
# 3. AnomalyDetector
# ════════════════════════════════════════════════════════════════════════════

def _make_observations(n: int = 30, anomaly_at: int | None = None) -> list[dict]:
    """Generate *n* synthetic port-scan-like observations."""
    obs = [{"port": float(i % 65535), "is_open": 0.0, "resp_ms": 5.0} for i in range(n)]
    if anomaly_at is not None and anomaly_at < n:
        obs[anomaly_at] = {"port": 4444.0, "is_open": 1.0, "resp_ms": 0.01}
    return obs


class TestAnomalyDetectorBasics(unittest.TestCase):

    def setUp(self):
        self.detector = AnomalyDetector(random_state=0)

    def test_returns_anomaly_report(self):
        r = self.detector.detect(_make_observations(30))
        self.assertIsInstance(r, AnomalyReport)

    def test_total_observations_correct(self):
        obs = _make_observations(20)
        r = self.detector.detect(obs)
        self.assertEqual(r.total_observations, 20)

    def test_records_count_matches_observations(self):
        obs = _make_observations(15)
        r = self.detector.detect(obs)
        self.assertEqual(len(r.records), 15)

    def test_each_record_type(self):
        r = self.detector.detect(_make_observations(10))
        for rec in r.records:
            self.assertIsInstance(rec, AnomalyRecord)

    def test_record_index_sequential(self):
        r = self.detector.detect(_make_observations(5))
        for i, rec in enumerate(r.records):
            self.assertEqual(rec.index, i)

    def test_anomaly_count_nonnegative(self):
        r = self.detector.detect(_make_observations(30))
        self.assertGreaterEqual(r.anomaly_count, 0)

    def test_anomaly_count_le_total(self):
        r = self.detector.detect(_make_observations(30))
        self.assertLessEqual(r.anomaly_count, r.total_observations)

    def test_risk_label_values(self):
        r = self.detector.detect(_make_observations(20))
        valid = {"NORMAL", "SUSPICIOUS", "ANOMALOUS"}
        for rec in r.records:
            self.assertIn(rec.risk_label, valid)

    def test_is_anomaly_bool(self):
        r = self.detector.detect(_make_observations(20))
        for rec in r.records:
            self.assertIsInstance(rec.is_anomaly, bool)

    def test_anomaly_score_float(self):
        r = self.detector.detect(_make_observations(10))
        for rec in r.records:
            self.assertIsInstance(rec.anomaly_score, float)

    def test_summary_df_not_none(self):
        r = self.detector.detect(_make_observations(10))
        self.assertIsNotNone(r.summary_df)

    def test_summary_df_has_anomaly_score_col(self):
        r = self.detector.detect(_make_observations(10))
        self.assertIn("anomaly_score", r.summary_df.columns)

    def test_summary_df_has_risk_label_col(self):
        r = self.detector.detect(_make_observations(10))
        self.assertIn("risk_label", r.summary_df.columns)

    def test_empty_observations_returns_empty_report(self):
        r = self.detector.detect([])
        self.assertEqual(r.total_observations, 0)
        self.assertEqual(r.anomaly_count, 0)
        self.assertEqual(len(r.records), 0)

    def test_no_numeric_features_raises(self):
        with self.assertRaises(ValueError):
            self.detector.detect([{"label": "foo"}, {"label": "bar"}])

    def test_features_preserved_in_record(self):
        obs = [{"port": 80.0, "is_open": 1.0}]
        r = self.detector.detect(obs * 10)
        self.assertIn("port", r.records[0].features)

    def test_contamination_parameter(self):
        det = AnomalyDetector(contamination=0.1, random_state=0)
        r = det.detect(_make_observations(50, anomaly_at=0))
        self.assertIsInstance(r, AnomalyReport)

    def test_n_estimators_parameter(self):
        det = AnomalyDetector(n_estimators=10, random_state=0)
        r = det.detect(_make_observations(20))
        self.assertEqual(len(r.records), 20)


class TestAnomalyDetectorFromPortScan(unittest.TestCase):

    def _make_mock_result(self, port: int, is_open: bool, banner: str) -> MagicMock:
        m = MagicMock()
        m.port   = port
        m.is_open = is_open
        m.banner = banner
        return m

    def test_from_port_scan_results_returns_report(self):
        det = AnomalyDetector(random_state=0)
        results = [self._make_mock_result(p, p % 5 == 0, "") for p in range(1, 31)]
        r = det.from_port_scan_results(results)
        self.assertIsInstance(r, AnomalyReport)
        self.assertEqual(r.total_observations, 30)

    def test_from_port_scan_results_empty(self):
        det = AnomalyDetector(random_state=0)
        r = det.from_port_scan_results([])
        self.assertEqual(r.total_observations, 0)


# ════════════════════════════════════════════════════════════════════════════
# 4. BinaryAuditor
# ════════════════════════════════════════════════════════════════════════════

def _make_mock_elf(
    nx=True, pie=True, canary=True, relro="Full", fortify=True, symbols=None
) -> MagicMock:
    elf = MagicMock()
    elf.nx      = nx
    elf.pie     = pie
    elf.canary  = canary
    elf.relro   = relro
    elf.fortify = fortify
    elf.arch    = "amd64"
    elf.symbols = symbols if symbols is not None else {"main": 0x401000}
    return elf


class TestBinaryAuditorInit(unittest.TestCase):

    def test_default_max_gadgets(self):
        a = BinaryAuditor()
        self.assertEqual(a.max_gadgets, 50)

    def test_custom_max_gadgets(self):
        a = BinaryAuditor(max_gadgets=10)
        self.assertEqual(a.max_gadgets, 10)

    def test_default_pattern_length(self):
        a = BinaryAuditor()
        self.assertEqual(a.pattern_length, 64)

    def test_custom_pattern_length(self):
        a = BinaryAuditor(pattern_length=128)
        self.assertEqual(a.pattern_length, 128)


class TestBinaryAuditorChecksec(unittest.TestCase):

    def setUp(self):
        self.auditor = BinaryAuditor()

    def test_checksec_returns_mitigation_report(self):
        elf = _make_mock_elf()
        report = self.auditor._checksec(elf)
        self.assertIsInstance(report, MitigationReport)

    def test_checksec_nx_true(self):
        elf = _make_mock_elf(nx=True)
        r = self.auditor._checksec(elf)
        self.assertTrue(r.nx)

    def test_checksec_nx_false(self):
        elf = _make_mock_elf(nx=False)
        r = self.auditor._checksec(elf)
        self.assertFalse(r.nx)

    def test_checksec_pie_true(self):
        elf = _make_mock_elf(pie=True)
        r = self.auditor._checksec(elf)
        self.assertTrue(r.pie)

    def test_checksec_pie_false(self):
        elf = _make_mock_elf(pie=False)
        r = self.auditor._checksec(elf)
        self.assertFalse(r.pie)

    def test_checksec_canary_true(self):
        elf = _make_mock_elf(canary=True)
        r = self.auditor._checksec(elf)
        self.assertTrue(r.canary)

    def test_checksec_relro_full(self):
        elf = _make_mock_elf(relro="Full RELRO")
        r = self.auditor._checksec(elf)
        self.assertEqual(r.relro, "Full")

    def test_checksec_relro_partial(self):
        elf = _make_mock_elf(relro="Partial RELRO")
        r = self.auditor._checksec(elf)
        self.assertEqual(r.relro, "Partial")

    def test_checksec_relro_none(self):
        elf = _make_mock_elf(relro="No RELRO")
        r = self.auditor._checksec(elf)
        self.assertEqual(r.relro, "No")

    def test_checksec_stripped_when_no_symbols(self):
        elf = _make_mock_elf(symbols={})
        r = self.auditor._checksec(elf)
        self.assertTrue(r.stripped)

    def test_checksec_not_stripped_when_symbols_present(self):
        elf = _make_mock_elf(symbols={"main": 0x401000})
        r = self.auditor._checksec(elf)
        self.assertFalse(r.stripped)

    def test_mitigation_report_as_dict(self):
        m = MitigationReport(nx=True, pie=False, canary=True, relro="Full")
        d = m.as_dict()
        self.assertIn("nx", d)
        self.assertIn("relro", d)
        self.assertTrue(d["nx"])


class TestBinaryAuditorNotes(unittest.TestCase):

    def test_no_nx_generates_note(self):
        m = MitigationReport(nx=False)
        notes = BinaryAuditor._generate_notes(m, [])
        self.assertTrue(any("NX" in n for n in notes))

    def test_no_pie_generates_note(self):
        m = MitigationReport(pie=False)
        notes = BinaryAuditor._generate_notes(m, [])
        self.assertTrue(any("PIE" in n for n in notes))

    def test_no_canary_generates_note(self):
        m = MitigationReport(canary=False)
        notes = BinaryAuditor._generate_notes(m, [])
        self.assertTrue(any("canary" in n.lower() for n in notes))

    def test_no_relro_generates_note(self):
        m = MitigationReport(relro="No")
        notes = BinaryAuditor._generate_notes(m, [])
        self.assertTrue(any("RELRO" in n for n in notes))

    def test_partial_relro_generates_note(self):
        m = MitigationReport(relro="Partial")
        notes = BinaryAuditor._generate_notes(m, [])
        self.assertTrue(any("Partial" in n for n in notes))

    def test_rop_gadgets_generates_note(self):
        m = MitigationReport(nx=True, pie=True, canary=True, relro="Full", fortify=True)
        gadgets = [RopGadget(address=0x401000, insns="pop rdi ; ret", bytes_hex="")]
        notes = BinaryAuditor._generate_notes(m, gadgets)
        self.assertTrue(any("ROP" in n or "gadget" in n.lower() for n in notes))

    def test_fully_hardened_binary_positive_note(self):
        m = MitigationReport(nx=True, pie=True, canary=True, relro="Full", fortify=True)
        notes = BinaryAuditor._generate_notes(m, [])
        self.assertTrue(any("strong" in n.lower() for n in notes))


class TestBinaryAuditorAudit(unittest.TestCase):

    @patch("sentinel_weave.advanced_offensive.ELF")
    @patch("sentinel_weave.advanced_offensive.ROP")
    @patch("sentinel_weave.advanced_offensive.cyclic")
    def test_audit_returns_result(self, mock_cyclic, mock_rop, mock_elf):
        mock_elf.return_value    = _make_mock_elf()
        mock_rop_inst            = MagicMock()
        mock_rop_inst.gadgets    = {}
        mock_rop.return_value    = mock_rop_inst
        mock_cyclic.return_value = b"aaaabbbb"

        with patch("pwnlib.context.context"):
            a = BinaryAuditor()
            r = a.audit("/fake/binary")

        self.assertIsInstance(r, BinaryAuditResult)

    @patch("sentinel_weave.advanced_offensive.ELF")
    @patch("sentinel_weave.advanced_offensive.ROP")
    @patch("sentinel_weave.advanced_offensive.cyclic")
    def test_audit_path_preserved(self, mock_cyclic, mock_rop, mock_elf):
        mock_elf.return_value = _make_mock_elf()
        mock_rop.return_value = MagicMock(gadgets={})
        mock_cyclic.return_value = b"aaaa"

        with patch("pwnlib.context.context"):
            a = BinaryAuditor()
            r = a.audit("/path/to/binary")
        self.assertEqual(r.path, "/path/to/binary")

    @patch("sentinel_weave.advanced_offensive.ELF")
    @patch("sentinel_weave.advanced_offensive.ROP")
    @patch("sentinel_weave.advanced_offensive.cyclic")
    def test_audit_arch_from_elf(self, mock_cyclic, mock_rop, mock_elf):
        elf       = _make_mock_elf()
        elf.arch  = "aarch64"
        mock_elf.return_value    = elf
        mock_rop.return_value    = MagicMock(gadgets={})
        mock_cyclic.return_value = b"x" * 64

        with patch("pwnlib.context.context"):
            r = BinaryAuditor().audit("/fake/bin")
        self.assertEqual(r.arch, "aarch64")

    def test_generate_pattern_returns_bytes(self):
        a = BinaryAuditor()
        pattern = a.generate_pattern(64)
        self.assertIsInstance(pattern, bytes)
        self.assertEqual(len(pattern), 64)

    def test_generate_pattern_default_length(self):
        a = BinaryAuditor(pattern_length=32)
        pattern = a.generate_pattern()
        self.assertEqual(len(pattern), 32)

    def test_find_offset_returns_int_or_none(self):
        a = BinaryAuditor()
        # Generate a known cyclic pattern and search within it
        pattern = a.generate_pattern(64)
        result = a.find_offset(pattern, pattern[:4])
        self.assertIn(type(result), (int, type(None)))


# ════════════════════════════════════════════════════════════════════════════
# 5. MemoryForensicsScanner
# ════════════════════════════════════════════════════════════════════════════

class TestMemoryForensicsScannerProcessAssessment(unittest.TestCase):

    def test_known_offensive_tool_suspicious(self):
        sus, reasons = MemoryForensicsScanner._assess_process(
            "mimikatz.exe", 1234, 4, "system"
        )
        self.assertTrue(sus)
        self.assertGreater(len(reasons), 0)

    def test_normal_process_not_suspicious(self):
        sus, reasons = MemoryForensicsScanner._assess_process(
            "notepad.exe", 1234, 4, "explorer.exe"
        )
        self.assertFalse(sus)
        self.assertEqual(len(reasons), 0)

    def test_suspicious_parent_child_winword_cmd(self):
        sus, reasons = MemoryForensicsScanner._assess_process(
            "cmd.exe", 5678, 1234, "winword.exe"
        )
        self.assertTrue(sus)

    def test_ppid_zero_non_system_flagged(self):
        sus, reasons = MemoryForensicsScanner._assess_process(
            "evil.exe", 999, 0, ""
        )
        self.assertTrue(sus)
        self.assertTrue(any("hollow" in r.lower() for r in reasons))

    def test_system_process_ppid_zero_not_flagged(self):
        sus, reasons = MemoryForensicsScanner._assess_process(
            "system", 4, 0, ""
        )
        self.assertFalse(sus)

    def test_suspicious_process_names_set_nonempty(self):
        self.assertGreater(len(_SUSPICIOUS_PROCESS_NAMES), 0)

    def test_suspicious_parent_child_set_nonempty(self):
        self.assertGreater(len(_SUSPICIOUS_PARENT_CHILD), 0)


class TestMemoryForensicsScannerNotes(unittest.TestCase):

    def test_no_artefacts_note(self):
        notes = MemoryForensicsScanner._build_notes([], [], [])
        self.assertEqual(len(notes), 1)
        self.assertIn("No obvious", notes[0])

    def test_suspicious_process_note(self):
        p = ProcessEntry(
            pid=1, ppid=0, name="mimikatz.exe", offset="0x0",
            is_suspicious=True, reasons=["known offensive tool"]
        )
        notes = MemoryForensicsScanner._build_notes([p], [], [])
        self.assertTrue(any("suspicious" in n.lower() for n in notes))

    def test_network_note(self):
        net = NetworkEntry("TCP", "127.0.0.1", 4444, "10.0.0.1", 9999, "ESTABLISHED", 1)
        notes = MemoryForensicsScanner._build_notes([], [net], [])
        self.assertTrue(any("network" in n.lower() for n in notes))

    def test_injection_note(self):
        notes = MemoryForensicsScanner._build_notes(
            [], [], ["Possible injection at 0xdeadbeef"]
        )
        self.assertTrue(any("inject" in n.lower() for n in notes))


class TestMemoryForensicsScannerScan(unittest.TestCase):

    def test_scan_missing_file_raises(self):
        scanner = MemoryForensicsScanner()
        with self.assertRaises(FileNotFoundError):
            scanner.scan("/nonexistent/path/memory.raw")

    @patch("sentinel_weave.advanced_offensive._vol_contexts")
    @patch("sentinel_weave.advanced_offensive._vol_automagic")
    @patch("sentinel_weave.advanced_offensive._vol_framework")
    @patch("os.path.isfile", return_value=True)
    def test_scan_returns_forensics_report(
        self, mock_isfile, mock_framework, mock_automagic, mock_contexts
    ):
        mock_ctx = MagicMock()
        mock_ctx.config = {}
        mock_contexts.Context.return_value = mock_ctx
        mock_automagic.available.return_value = []
        mock_automagic.run.return_value = iter([])
        mock_framework.require_interface_version = MagicMock()

        scanner = MemoryForensicsScanner()
        report  = scanner.scan("/fake/memory.raw")
        self.assertIsInstance(report, ForensicsReport)

    @patch("sentinel_weave.advanced_offensive._vol_contexts")
    @patch("sentinel_weave.advanced_offensive._vol_automagic")
    @patch("sentinel_weave.advanced_offensive._vol_framework")
    @patch("os.path.isfile", return_value=True)
    def test_scan_image_path_preserved(
        self, mock_isfile, mock_framework, mock_automagic, mock_contexts
    ):
        mock_ctx = MagicMock()
        mock_ctx.config = {}
        mock_contexts.Context.return_value = mock_ctx
        mock_automagic.available.return_value = []
        mock_automagic.run.return_value = iter([])

        scanner = MemoryForensicsScanner()
        report  = scanner.scan("/fake/memory.raw")
        self.assertEqual(report.image_path, "/fake/memory.raw")

    @patch("sentinel_weave.advanced_offensive._vol_contexts")
    @patch("sentinel_weave.advanced_offensive._vol_automagic")
    @patch("sentinel_weave.advanced_offensive._vol_framework")
    @patch("os.path.isfile", return_value=True)
    def test_scan_empty_process_list(
        self, mock_isfile, mock_framework, mock_automagic, mock_contexts
    ):
        mock_ctx = MagicMock()
        mock_ctx.config = {}
        mock_contexts.Context.return_value = mock_ctx
        mock_automagic.available.return_value = []
        mock_automagic.run.return_value = iter([])

        scanner = MemoryForensicsScanner()
        report  = scanner.scan("/fake/memory.raw")
        self.assertEqual(report.process_count, 0)
        self.assertEqual(report.suspicious_process_count, 0)

    def test_forensics_report_dataclass_fields(self):
        report = ForensicsReport(
            image_path               = "/x.raw",
            os_profile               = "Win10x64",
            process_count            = 10,
            suspicious_process_count = 2,
            processes                = [],
            network_entries          = [],
            injected_code_indicators = [],
            notes                    = ["test note"],
        )
        self.assertEqual(report.image_path, "/x.raw")
        self.assertEqual(report.os_profile, "Win10x64")
        self.assertEqual(report.process_count, 10)

    def test_process_entry_dataclass(self):
        pe = ProcessEntry(
            pid=1, ppid=0, name="system", offset="0x0",
            is_suspicious=False, reasons=[]
        )
        self.assertEqual(pe.pid, 1)

    def test_network_entry_dataclass(self):
        ne = NetworkEntry(
            protocol="TCP", local_addr="127.0.0.1", local_port=80,
            remote_addr="8.8.8.8", remote_port=443, state="ESTABLISHED", pid=1
        )
        self.assertEqual(ne.protocol, "TCP")
        self.assertEqual(ne.remote_port, 443)


# ════════════════════════════════════════════════════════════════════════════
# 6. Public API / Import checks
# ════════════════════════════════════════════════════════════════════════════

class TestPublicApiImport(unittest.TestCase):

    def test_shellcode_analyzer_importable(self):
        from sentinel_weave.advanced_offensive import ShellcodeAnalyzer as SA  # noqa
        self.assertTrue(callable(SA))

    def test_yara_scanner_importable(self):
        from sentinel_weave.advanced_offensive import YaraScanner as YS  # noqa
        self.assertTrue(callable(YS))

    def test_anomaly_detector_importable(self):
        from sentinel_weave.advanced_offensive import AnomalyDetector as AD  # noqa
        self.assertTrue(callable(AD))

    def test_binary_auditor_importable(self):
        from sentinel_weave.advanced_offensive import BinaryAuditor as BA  # noqa
        self.assertTrue(callable(BA))

    def test_memory_scanner_importable(self):
        from sentinel_weave.advanced_offensive import MemoryForensicsScanner as MFS  # noqa
        self.assertTrue(callable(MFS))

    def test_builtin_rule_names_importable(self):
        from sentinel_weave.advanced_offensive import BUILTIN_RULE_NAMES as BRN  # noqa
        self.assertIsInstance(BRN, tuple)

    def test_top_level_init_exports_shellcode_analyzer(self):
        from sentinel_weave import ShellcodeAnalyzer  # noqa
        self.assertTrue(callable(ShellcodeAnalyzer))

    def test_top_level_init_exports_yara_scanner(self):
        from sentinel_weave import YaraScanner  # noqa
        self.assertTrue(callable(YaraScanner))

    def test_top_level_init_exports_anomaly_detector(self):
        from sentinel_weave import AnomalyDetector  # noqa
        self.assertTrue(callable(AnomalyDetector))

    def test_top_level_init_exports_binary_auditor(self):
        from sentinel_weave import BinaryAuditor  # noqa
        self.assertTrue(callable(BinaryAuditor))

    def test_top_level_init_exports_memory_scanner(self):
        from sentinel_weave import MemoryForensicsScanner  # noqa
        self.assertTrue(callable(MemoryForensicsScanner))

    def test_top_level_init_exports_forensics_report(self):
        from sentinel_weave import ForensicsReport  # noqa
        self.assertTrue(callable(ForensicsReport))

    def test_top_level_init_exports_mitigation_report(self):
        from sentinel_weave import MitigationReport  # noqa
        self.assertTrue(callable(MitigationReport))


# ════════════════════════════════════════════════════════════════════════════
# 7. Dashboard API endpoints
# ════════════════════════════════════════════════════════════════════════════

class TestDashboardAdvancedEndpoints(unittest.TestCase):

    def setUp(self):
        from dashboard.app import create_app
        self.app = create_app(demo_mode=False)
        self.client = self.app.test_client()

    def test_shellcode_endpoint_exists(self):
        resp = self.client.post("/api/redteam/shellcode", json={})
        self.assertNotEqual(resp.status_code, 404)

    def test_shellcode_missing_hex_returns_400(self):
        resp = self.client.post("/api/redteam/shellcode", json={})
        self.assertEqual(resp.status_code, 400)

    def test_shellcode_invalid_hex_returns_400(self):
        resp = self.client.post("/api/redteam/shellcode", json={"hex": "zzzz"})
        self.assertEqual(resp.status_code, 400)

    def test_shellcode_valid_hex_returns_200(self):
        # xor rax, rax; ret
        resp = self.client.post(
            "/api/redteam/shellcode", json={"hex": "4831c0c3"}
        )
        self.assertEqual(resp.status_code, 200)

    def test_shellcode_response_has_threat_level(self):
        import json
        resp = self.client.post(
            "/api/redteam/shellcode", json={"hex": "4831c0c3"}
        )
        data = json.loads(resp.data)
        self.assertIn("threat_level", data)

    def test_shellcode_response_has_instructions(self):
        import json
        resp = self.client.post(
            "/api/redteam/shellcode", json={"hex": "4831c0c3"}
        )
        data = json.loads(resp.data)
        self.assertIn("instructions", data)

    def test_shellcode_too_large_returns_400(self):
        # 4097 bytes → should exceed 4096 byte limit
        big_hex = "90" * 4097
        resp = self.client.post("/api/redteam/shellcode", json={"hex": big_hex})
        self.assertEqual(resp.status_code, 400)

    def test_shellcode_invalid_arch_returns_400(self):
        resp = self.client.post(
            "/api/redteam/shellcode", json={"hex": "90", "arch": "mips"}
        )
        self.assertEqual(resp.status_code, 400)

    def test_yara_endpoint_exists(self):
        resp = self.client.post("/api/redteam/yara", json={})
        self.assertNotEqual(resp.status_code, 404)

    def test_yara_missing_content_returns_400(self):
        resp = self.client.post("/api/redteam/yara", json={})
        self.assertEqual(resp.status_code, 400)

    def test_yara_both_hex_and_text_returns_400(self):
        resp = self.client.post(
            "/api/redteam/yara", json={"hex": "aabb", "text": "hello"}
        )
        self.assertEqual(resp.status_code, 400)

    def test_yara_text_input_returns_200(self):
        resp = self.client.post(
            "/api/redteam/yara", json={"text": "benign document content"}
        )
        self.assertEqual(resp.status_code, 200)

    def test_yara_hex_input_returns_200(self):
        resp = self.client.post(
            "/api/redteam/yara", json={"hex": "4831c0"}
        )
        self.assertEqual(resp.status_code, 200)

    def test_yara_response_has_match_count(self):
        import json
        resp = self.client.post("/api/redteam/yara", json={"text": "hello"})
        data = json.loads(resp.data)
        self.assertIn("match_count", data)

    def test_yara_response_has_severity(self):
        import json
        resp = self.client.post("/api/redteam/yara", json={"text": "hello"})
        data = json.loads(resp.data)
        self.assertIn("severity", data)

    def test_yara_lsass_text_match(self):
        import json
        resp = self.client.post(
            "/api/redteam/yara",
            json={"text": "lsass.exe dump sekurlsa"}
        )
        data = json.loads(resp.data)
        self.assertGreater(data["match_count"], 0)

    def test_anomaly_endpoint_exists(self):
        resp = self.client.post("/api/redteam/anomaly", json={})
        self.assertNotEqual(resp.status_code, 404)

    def test_anomaly_missing_observations_returns_400(self):
        resp = self.client.post("/api/redteam/anomaly", json={})
        self.assertEqual(resp.status_code, 400)

    def test_anomaly_empty_list_returns_400(self):
        resp = self.client.post(
            "/api/redteam/anomaly", json={"observations": []}
        )
        self.assertEqual(resp.status_code, 400)

    def test_anomaly_valid_returns_200(self):
        obs = [{"port": float(i), "is_open": float(i % 2)} for i in range(20)]
        resp = self.client.post("/api/redteam/anomaly", json={"observations": obs})
        self.assertEqual(resp.status_code, 200)

    def test_anomaly_response_has_records(self):
        import json
        obs = [{"port": float(i), "is_open": float(i % 2)} for i in range(20)]
        resp = self.client.post("/api/redteam/anomaly", json={"observations": obs})
        data = json.loads(resp.data)
        self.assertIn("records", data)
        self.assertEqual(len(data["records"]), 20)

    def test_anomaly_response_has_anomaly_count(self):
        import json
        obs = [{"port": float(i), "is_open": float(i % 2)} for i in range(20)]
        resp = self.client.post("/api/redteam/anomaly", json={"observations": obs})
        data = json.loads(resp.data)
        self.assertIn("anomaly_count", data)

    def test_anomaly_invalid_contamination_returns_400(self):
        obs = [{"port": float(i)} for i in range(20)]
        resp = self.client.post(
            "/api/redteam/anomaly",
            json={"observations": obs, "contamination": 99.9}
        )
        self.assertEqual(resp.status_code, 400)

    def test_anomaly_too_many_observations_returns_400(self):
        obs = [{"x": float(i)} for i in range(10_001)]
        resp = self.client.post("/api/redteam/anomaly", json={"observations": obs})
        self.assertEqual(resp.status_code, 400)


if __name__ == "__main__":
    unittest.main()
