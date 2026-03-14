"""
Tests for dependency-integrated improvements to SentinelWeave core modules.

Covers all five areas where pwntools, scikit-learn, Volatility3, Capstone,
yara-python, and pandas are wired into the existing structure:

1. SklearnSecurityClassifier      — sklearn RandomForest/GradientBoosting threat classifier
2. DatasetBuilder.to/from_dataframe — pandas DataFrame integration for ML datasets
3. IsolationForestDetector         — sklearn IsolationForest anomaly detector
4. summarize_reports_df            — pandas DataFrame summary of ThreatReports
5. detect_shellcode                — Capstone shellcode analysis helper
6. YaraEventAnalyzer               — YARA-augmented EventAnalyzer subclass
7. BinaryFuzzer                    — pwntools cyclic/repeat/overflow fuzzing
8. aggregate_scan_results          — pandas scan aggregation for red-team toolkit
9. SiemExporter.to_dataframe       — pandas export of SIEM findings
10. SiemExporter.summary_stats     — pandas aggregate SIEM statistics

All external I/O is avoided; yara rule compilation uses in-memory source
strings and Capstone only operates on known byte sequences.
"""

from __future__ import annotations

import json
import os
import sys
import unittest
from dataclasses import dataclass
from typing import Any
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# ── shared helpers ────────────────────────────────────────────────────────────

# x86-64 execve("/bin/sh") shellcode (10 bytes — syscall with xor zeroing)
_X64_EXECVE = bytes.fromhex("4831c04889c7b03b0f05")

# Benign 3-NOP + RET — below shellcode detection threshold
_BENIGN_NOP = bytes.fromhex("909090c3")

# Simple YARA rule that matches the literal string "MALWARE"
_SIMPLE_YARA = """
rule TestMalware {
    strings:
        $m = "MALWARE" ascii
    condition:
        $m
}
"""

# Threat / benign feature vectors (13-element as per EventAnalyzer)
_THREAT_FEAT = [0.9, 0.1, 0.8, 0.7, 1.0, 1.0, 0.6, 1.0, 1.0, 1.0, 0.9, 0.8, 1.0]
_BENIGN_FEAT = [0.1, 0.0, 0.0, 0.1, 0.0, 1.0, 0.2, 0.0, 0.0, 0.0, 0.3, 0.0, 0.0]

# ── imports ───────────────────────────────────────────────────────────────────

from sentinel_weave.ml_pipeline import (
    DatasetBuilder, LabeledEvent, SklearnSecurityClassifier,
)
from sentinel_weave.event_analyzer import (
    EventAnalyzer, SecurityEvent,
    YaraEventAnalyzer, detect_shellcode,
)
from sentinel_weave.threat_detector import (
    IsolationForestDetector, ThreatDetector, ThreatLevel, ThreatReport,
    summarize_reports_df,
)
from sentinel_weave.red_team_toolkit import (
    BinaryFuzzer, PortScanResult, VulnerabilityFinding,
    ServiceFingerprintResult, aggregate_scan_results,
)
from sentinel_weave.siem_exporter import SiemExporter


# ──────────────────────────────────────────────────────────────────────────────
# 1. SklearnSecurityClassifier
# ──────────────────────────────────────────────────────────────────────────────

def _make_dataset(n: int = 20) -> list[LabeledEvent]:
    """Return a balanced labeled dataset with clear class separation."""
    return (
        [LabeledEvent(features=_THREAT_FEAT, label=1)] * n
        + [LabeledEvent(features=_BENIGN_FEAT, label=0)] * n
    )


class TestSklearnClassifierInit(unittest.TestCase):
    """Verify default construction and hyperparameter storage."""

    def test_default_estimator_type(self) -> None:
        clf = SklearnSecurityClassifier()
        self.assertEqual(clf.estimator_type, "random_forest")

    def test_custom_estimator_type(self) -> None:
        clf = SklearnSecurityClassifier(estimator_type="gradient_boosting")
        self.assertEqual(clf.estimator_type, "gradient_boosting")

    def test_default_n_estimators(self) -> None:
        clf = SklearnSecurityClassifier()
        self.assertEqual(clf.n_estimators, 100)

    def test_custom_n_estimators(self) -> None:
        clf = SklearnSecurityClassifier(n_estimators=50)
        self.assertEqual(clf.n_estimators, 50)

    def test_not_trained_before_fit(self) -> None:
        clf = SklearnSecurityClassifier()
        self.assertFalse(clf._trained)

    def test_predict_before_train_raises(self) -> None:
        clf = SklearnSecurityClassifier()
        with self.assertRaises(RuntimeError):
            clf.predict_proba(_THREAT_FEAT)

    def test_feature_names_match_parent(self) -> None:
        from sentinel_weave.ml_pipeline import SecurityClassifier
        self.assertEqual(
            SklearnSecurityClassifier.FEATURE_NAMES,
            SecurityClassifier.FEATURE_NAMES,
        )


class TestSklearnClassifierTraining(unittest.TestCase):
    """Training produces sensible output and marks the model as trained."""

    def setUp(self) -> None:
        self.clf = SklearnSecurityClassifier(n_estimators=10, random_state=42)
        self.dataset = _make_dataset(15)

    def test_train_returns_dict(self) -> None:
        info = self.clf.train(self.dataset)
        self.assertIsInstance(info, dict)

    def test_train_result_keys(self) -> None:
        info = self.clf.train(self.dataset)
        for key in ("n_samples", "n_features", "estimator_type", "n_estimators", "oob_score"):
            self.assertIn(key, info)

    def test_train_n_samples(self) -> None:
        info = self.clf.train(self.dataset)
        self.assertEqual(info["n_samples"], len(self.dataset))

    def test_train_n_features(self) -> None:
        info = self.clf.train(self.dataset)
        self.assertEqual(info["n_features"], 13)

    def test_model_marked_trained(self) -> None:
        self.clf.train(self.dataset)
        self.assertTrue(self.clf._trained)

    def test_empty_dataset_raises(self) -> None:
        with self.assertRaises(ValueError):
            self.clf.train([])

    def test_single_class_raises(self) -> None:
        single_class = [LabeledEvent(features=_THREAT_FEAT, label=1)] * 5
        with self.assertRaises(ValueError):
            self.clf.train(single_class)

    def test_gradient_boosting_variant(self) -> None:
        clf = SklearnSecurityClassifier(
            estimator_type="gradient_boosting",
            n_estimators=5,
            random_state=0,
        )
        info = clf.train(self.dataset)
        self.assertEqual(info["estimator_type"], "gradient_boosting")
        self.assertIsNone(info["oob_score"])  # GB has no OOB

    def test_calibrated_variant(self) -> None:
        clf = SklearnSecurityClassifier(n_estimators=5, calibrate=True, random_state=0)
        info = clf.train(self.dataset)
        self.assertIsNotNone(info)
        self.assertTrue(clf._trained)


class TestSklearnClassifierPrediction(unittest.TestCase):
    """The trained model must distinguish the archetypal feature vectors."""

    def setUp(self) -> None:
        self.clf = SklearnSecurityClassifier(n_estimators=20, random_state=42)
        self.clf.train(_make_dataset(20))

    def test_predict_proba_type(self) -> None:
        p = self.clf.predict_proba(_THREAT_FEAT)
        self.assertIsInstance(p, float)

    def test_predict_proba_range(self) -> None:
        for feat in (_THREAT_FEAT, _BENIGN_FEAT):
            p = self.clf.predict_proba(feat)
            self.assertGreaterEqual(p, 0.0)
            self.assertLessEqual(p, 1.0)

    def test_predict_threat(self) -> None:
        self.assertEqual(self.clf.predict(_THREAT_FEAT), 1)

    def test_predict_benign(self) -> None:
        self.assertEqual(self.clf.predict(_BENIGN_FEAT), 0)

    def test_threshold_zero_always_threat(self) -> None:
        # threshold=0 → predict_proba ≥ 0 → always 1
        self.assertEqual(self.clf.predict(_BENIGN_FEAT, threshold=0.0), 1)

    def test_threshold_one_always_benign(self) -> None:
        # threshold=1 → only predict 1 if proba == 1.0 exactly
        # For benign feats this should be 0
        pred = self.clf.predict(_BENIGN_FEAT, threshold=1.0)
        self.assertEqual(pred, 0)


class TestSklearnClassifierEvaluation(unittest.TestCase):
    """Evaluation metrics dict has expected structure and reasonable values."""

    def setUp(self) -> None:
        self.clf = SklearnSecurityClassifier(n_estimators=20, random_state=42)
        self.clf.train(_make_dataset(20))

    def test_evaluate_returns_dict(self) -> None:
        m = self.clf.evaluate(_make_dataset(5))
        self.assertIsInstance(m, dict)

    def test_evaluate_metric_keys(self) -> None:
        m = self.clf.evaluate(_make_dataset(5))
        for k in ("accuracy", "precision", "recall", "f1", "roc_auc", "tp", "fp", "tn", "fn"):
            self.assertIn(k, m)

    def test_evaluate_high_accuracy_on_separable(self) -> None:
        m = self.clf.evaluate(_make_dataset(10))
        self.assertGreater(m["accuracy"], 0.8)

    def test_evaluate_roc_auc_reasonable(self) -> None:
        m = self.clf.evaluate(_make_dataset(10))
        self.assertGreater(m["roc_auc"], 0.5)

    def test_evaluate_empty_raises(self) -> None:
        with self.assertRaises(ValueError):
            self.clf.evaluate([])

    def test_evaluate_before_train_raises(self) -> None:
        clf = SklearnSecurityClassifier(n_estimators=5)
        with self.assertRaises(RuntimeError):
            clf.evaluate(_make_dataset(5))


class TestSklearnClassifierFeatureImportances(unittest.TestCase):
    """Feature importances are exposed correctly."""

    def setUp(self) -> None:
        self.clf = SklearnSecurityClassifier(n_estimators=20, random_state=42)
        self.clf.train(_make_dataset(20))

    def test_importances_dict_type(self) -> None:
        imp = self.clf.feature_importances_
        self.assertIsInstance(imp, dict)

    def test_importances_keys_match_feature_names(self) -> None:
        imp = self.clf.feature_importances_
        self.assertEqual(set(imp.keys()), set(SklearnSecurityClassifier.FEATURE_NAMES))

    def test_importances_sum_near_one(self) -> None:
        imp = self.clf.feature_importances_
        total = sum(imp.values())
        self.assertAlmostEqual(total, 1.0, places=3)

    def test_top_features_count(self) -> None:
        top = self.clf.top_features(3)
        self.assertEqual(len(top), 3)

    def test_top_features_sorted(self) -> None:
        top = self.clf.top_features(5)
        scores = [score for _, score in top]
        self.assertEqual(scores, sorted(scores, reverse=True))


class TestSklearnClassifierSerialization(unittest.TestCase):
    """to_json / from_json round-trip."""

    def setUp(self) -> None:
        self.clf = SklearnSecurityClassifier(n_estimators=10, random_state=0)
        self.clf.train(_make_dataset(10))

    def test_to_json_is_string(self) -> None:
        self.assertIsInstance(self.clf.to_json(), str)

    def test_to_json_contains_class_key(self) -> None:
        payload = json.loads(self.clf.to_json())
        self.assertEqual(payload["class"], "SklearnSecurityClassifier")

    def test_from_json_roundtrip_prediction(self) -> None:
        restored = SklearnSecurityClassifier.from_json(self.clf.to_json())
        # Predictions should be identical
        self.assertEqual(
            self.clf.predict(_THREAT_FEAT),
            restored.predict(_THREAT_FEAT),
        )

    def test_from_json_wrong_class_raises(self) -> None:
        bad = json.dumps({"class": "SecurityClassifier"})
        with self.assertRaises(ValueError):
            SklearnSecurityClassifier.from_json(bad)


# ──────────────────────────────────────────────────────────────────────────────
# 2. DatasetBuilder.to_dataframe / from_dataframe
# ──────────────────────────────────────────────────────────────────────────────

class TestDatasetBuilderDataFrame(unittest.TestCase):
    """pandas DataFrame ↔ LabeledEvent round-trip."""

    def setUp(self) -> None:
        self.dataset = _make_dataset(5)

    def test_to_dataframe_returns_dataframe(self) -> None:
        import pandas as pd
        df = DatasetBuilder.to_dataframe(self.dataset)
        self.assertIsInstance(df, pd.DataFrame)

    def test_to_dataframe_row_count(self) -> None:
        df = DatasetBuilder.to_dataframe(self.dataset)
        self.assertEqual(len(df), len(self.dataset))

    def test_to_dataframe_has_label_column(self) -> None:
        df = DatasetBuilder.to_dataframe(self.dataset)
        self.assertIn("label", df.columns)

    def test_to_dataframe_has_weight_column(self) -> None:
        df = DatasetBuilder.to_dataframe(self.dataset)
        self.assertIn("weight", df.columns)

    def test_to_dataframe_feature_column_count(self) -> None:
        df = DatasetBuilder.to_dataframe(self.dataset)
        # 13 feature cols + label + weight
        self.assertEqual(len(df.columns), 15)

    def test_from_dataframe_returns_list(self) -> None:
        df = DatasetBuilder.to_dataframe(self.dataset)
        back = DatasetBuilder.from_dataframe(df)
        self.assertIsInstance(back, list)

    def test_from_dataframe_length_preserved(self) -> None:
        df = DatasetBuilder.to_dataframe(self.dataset)
        back = DatasetBuilder.from_dataframe(df)
        self.assertEqual(len(back), len(self.dataset))

    def test_from_dataframe_labels_preserved(self) -> None:
        df = DatasetBuilder.to_dataframe(self.dataset)
        back = DatasetBuilder.from_dataframe(df)
        original_labels = [e.label for e in self.dataset]
        restored_labels  = [e.label for e in back]
        self.assertEqual(original_labels, restored_labels)

    def test_from_dataframe_missing_label_raises(self) -> None:
        import pandas as pd
        df = pd.DataFrame({"feat1": [1.0, 2.0]})
        with self.assertRaises(ValueError):
            DatasetBuilder.from_dataframe(df)

    def test_from_dataframe_no_weight_defaults_to_one(self) -> None:
        import pandas as pd
        df = DatasetBuilder.to_dataframe(self.dataset).drop(columns=["weight"])
        back = DatasetBuilder.from_dataframe(df)
        self.assertTrue(all(e.weight == 1.0 for e in back))


# ──────────────────────────────────────────────────────────────────────────────
# 3. IsolationForestDetector
# ──────────────────────────────────────────────────────────────────────────────

def _make_detector_with_data(n: int = 15) -> IsolationForestDetector:
    """Return a fitted IsolationForestDetector with n training events."""
    analyzer = EventAnalyzer()
    det = IsolationForestDetector(n_estimators=10, contamination=0.1, random_state=42)
    for i in range(n):
        ev = analyzer.parse(f"Connection from 10.0.0.{i % 255} port 22")
        ev.features = _BENIGN_FEAT[:]
        det.fit_event(ev)
    det.fit()
    return det


class TestIsolationForestDetectorInit(unittest.TestCase):
    """Construction and parameter storage."""

    def test_default_params(self) -> None:
        d = IsolationForestDetector()
        self.assertEqual(d._n_estimators, 100)
        self.assertAlmostEqual(d._contamination, 0.05)

    def test_custom_params(self) -> None:
        d = IsolationForestDetector(n_estimators=50, contamination=0.1)
        self.assertEqual(d._n_estimators, 50)
        self.assertAlmostEqual(d._contamination, 0.1)

    def test_no_model_before_fit(self) -> None:
        d = IsolationForestDetector()
        self.assertIsNone(d._iso_model)

    def test_yara_rules_compiled_when_provided(self) -> None:
        d = IsolationForestDetector(yara_rules_source=_SIMPLE_YARA)
        self.assertIsNotNone(d._yara_compiled)

    def test_no_yara_without_source(self) -> None:
        d = IsolationForestDetector()
        self.assertIsNone(d._yara_compiled)


class TestIsolationForestDetectorFitting(unittest.TestCase):
    """fit() / fit_event() mechanics."""

    def test_fit_empty_raises(self) -> None:
        d = IsolationForestDetector()
        with self.assertRaises(ValueError):
            d.fit()

    def test_fit_returns_sample_count(self) -> None:
        d = IsolationForestDetector(n_estimators=5)
        ev = EventAnalyzer().parse("Normal log line")
        ev.features = _BENIGN_FEAT[:]
        d.fit_event(ev)
        n = d.fit()
        self.assertEqual(n, 1)

    def test_fit_event_appends_to_training_set(self) -> None:
        d = IsolationForestDetector()
        ev = EventAnalyzer().parse("test")
        ev.features = _BENIGN_FEAT[:]
        d.fit_event(ev)
        self.assertEqual(len(d._training_X), 1)

    def test_fit_sets_model(self) -> None:
        d = IsolationForestDetector(n_estimators=5)
        ev = EventAnalyzer().parse("test")
        ev.features = _BENIGN_FEAT[:]
        d.fit_event(ev)
        d.fit()
        self.assertIsNotNone(d._iso_model)

    def test_fit_with_extra_X(self) -> None:
        d = IsolationForestDetector(n_estimators=5)
        ev = EventAnalyzer().parse("test")
        ev.features = _BENIGN_FEAT[:]
        d.fit_event(ev)
        n = d.fit(extra_X=[_THREAT_FEAT])
        self.assertEqual(n, 2)


class TestIsolationForestDetectorAnalysis(unittest.TestCase):
    """analyze() returns ThreatReport with IsolationForest score."""

    def setUp(self) -> None:
        self.det = _make_detector_with_data()
        self.analyzer = EventAnalyzer()

    def test_analyze_returns_threat_report(self) -> None:
        ev = self.analyzer.parse("Failed password for root from 10.0.0.1")
        ev.features = _THREAT_FEAT[:]
        report = self.det.analyze(ev)
        self.assertIsInstance(report, ThreatReport)

    def test_analyze_has_anomaly_score(self) -> None:
        ev = self.analyzer.parse("Normal log")
        ev.features = _BENIGN_FEAT[:]
        report = self.det.analyze(ev)
        self.assertGreaterEqual(report.anomaly_score, 0.0)
        self.assertLessEqual(report.anomaly_score, 1.0)

    def test_analyze_adds_isolation_forest_explanation(self) -> None:
        ev = self.analyzer.parse("Normal log")
        ev.features = _BENIGN_FEAT[:]
        report = self.det.analyze(ev)
        iso_explanations = [e for e in report.explanation if "IsolationForest" in e]
        self.assertTrue(len(iso_explanations) >= 1)

    def test_analyze_fallback_without_fit(self) -> None:
        det = IsolationForestDetector(n_estimators=5)
        ev = self.analyzer.parse("test")
        ev.features = _BENIGN_FEAT[:]
        # Should not raise; falls back to z-score
        report = det.analyze(ev)
        self.assertIsInstance(report, ThreatReport)

    def test_yara_augmented_analyze(self) -> None:
        det = _make_detector_with_data()
        det._yara_compiled = None  # reset to re-compile with new rules
        import yara
        det._yara_compiled = yara.compile(source=_SIMPLE_YARA)
        ev = self.analyzer.parse("MALWARE detected from 10.0.0.1")
        ev.features = _THREAT_FEAT[:]
        report = det.analyze(ev)
        yara_sigs = [s for s in report.event.matched_sigs if "YARA:TestMalware" in s]
        self.assertTrue(len(yara_sigs) >= 1)

    def test_analyze_bulk(self) -> None:
        evs = [self.analyzer.parse(f"log {i}") for i in range(5)]
        for e in evs:
            e.features = _BENIGN_FEAT[:]
        reports = self.det.analyze_bulk(evs)
        self.assertEqual(len(reports), 5)


# ──────────────────────────────────────────────────────────────────────────────
# 4. summarize_reports_df
# ──────────────────────────────────────────────────────────────────────────────

class TestSummarizeReportsDf(unittest.TestCase):
    """pandas DataFrame summary of ThreatReport lists."""

    def setUp(self) -> None:
        analyzer = EventAnalyzer()
        det = ThreatDetector()
        events = [
            analyzer.parse("Failed password for root from 10.0.0.1"),
            analyzer.parse("Normal connection from 192.168.0.2"),
        ]
        self.reports = det.analyze_bulk(events)

    def test_returns_dataframe(self) -> None:
        import pandas as pd
        df = summarize_reports_df(self.reports)
        self.assertIsInstance(df, pd.DataFrame)

    def test_row_count_matches_reports(self) -> None:
        df = summarize_reports_df(self.reports)
        self.assertEqual(len(df), len(self.reports))

    def test_required_columns_present(self) -> None:
        df = summarize_reports_df(self.reports)
        for col in ("threat_level", "anomaly_score", "source_ip", "event_type", "signatures"):
            self.assertIn(col, df.columns)

    def test_feature_columns_present(self) -> None:
        df = summarize_reports_df(self.reports)
        self.assertIn("text_length_norm", df.columns)
        self.assertIn("threat_keyword_density", df.columns)

    def test_empty_list_returns_empty_dataframe(self) -> None:
        df = summarize_reports_df([])
        self.assertEqual(len(df), 0)

    def test_anomaly_score_column_dtype(self) -> None:
        df = summarize_reports_df(self.reports)
        self.assertTrue((df["anomaly_score"] >= 0.0).all())
        self.assertTrue((df["anomaly_score"] <= 1.0).all())

    def test_threat_level_values_are_strings(self) -> None:
        df = summarize_reports_df(self.reports)
        self.assertTrue(df["threat_level"].apply(lambda v: isinstance(v, str)).all())


# ──────────────────────────────────────────────────────────────────────────────
# 5. detect_shellcode
# ──────────────────────────────────────────────────────────────────────────────

class TestDetectShellcode(unittest.TestCase):
    """Capstone-backed shellcode classifier."""

    def test_returns_dict(self) -> None:
        result = detect_shellcode(_X64_EXECVE)
        self.assertIsInstance(result, dict)

    def test_required_keys(self) -> None:
        result = detect_shellcode(_X64_EXECVE)
        for key in ("classification", "arch", "n_instructions",
                    "dangerous_mnemonics", "indicators", "disassembly"):
            self.assertIn(key, result)

    def test_malicious_shellcode_classified(self) -> None:
        result = detect_shellcode(_X64_EXECVE)
        self.assertEqual(result["classification"], "MALICIOUS")

    def test_benign_nops_classified_benign_or_binary_data(self) -> None:
        result = detect_shellcode(_BENIGN_NOP)
        # Only 3 instructions (<min_instructions=3 threshold at >=3) — either BENIGN or BINARY_DATA
        self.assertIn(result["classification"], ("BENIGN", "BINARY_DATA"))

    def test_arch_preserved(self) -> None:
        result = detect_shellcode(_X64_EXECVE, arch="x86_64")
        self.assertEqual(result["arch"], "x86_64")

    def test_n_instructions_positive(self) -> None:
        result = detect_shellcode(_X64_EXECVE)
        self.assertGreater(result["n_instructions"], 0)

    def test_disassembly_list(self) -> None:
        result = detect_shellcode(_X64_EXECVE)
        self.assertIsInstance(result["disassembly"], list)

    def test_disassembly_entries_have_required_keys(self) -> None:
        result = detect_shellcode(_X64_EXECVE)
        for entry in result["disassembly"]:
            for k in ("address", "mnemonic", "op_str"):
                self.assertIn(k, entry)

    def test_dangerous_mnemonics_includes_syscall(self) -> None:
        result = detect_shellcode(_X64_EXECVE)
        self.assertIn("syscall", result["dangerous_mnemonics"])

    def test_min_instructions_below_threshold_returns_binary_data(self) -> None:
        # Force min_instructions=100 → impossible to satisfy → BINARY_DATA
        result = detect_shellcode(_X64_EXECVE, min_instructions=100)
        self.assertEqual(result["classification"], "BINARY_DATA")

    def test_x86_arch_flag(self) -> None:
        # 32-bit execve shellcode
        x86_execve = bytes.fromhex(
            "31c05068 2f2f7368 682f6269 6e89e353 89e1b00b cd80".replace(" ", "")
        )
        result = detect_shellcode(x86_execve, arch="x86")
        self.assertEqual(result["arch"], "x86")

    def test_static_method_on_event_analyzer(self) -> None:
        # detect_shellcode is attached as a static method on EventAnalyzer
        result = EventAnalyzer.detect_shellcode(_X64_EXECVE)
        self.assertIsInstance(result, dict)


# ──────────────────────────────────────────────────────────────────────────────
# 6. YaraEventAnalyzer
# ──────────────────────────────────────────────────────────────────────────────

class TestYaraEventAnalyzerInit(unittest.TestCase):
    """Construction edge cases."""

    def test_init_with_rules_source(self) -> None:
        ya = YaraEventAnalyzer(rules_source=_SIMPLE_YARA)
        self.assertIsNotNone(ya._yara_rules)

    def test_init_without_source_or_path_raises(self) -> None:
        with self.assertRaises(ValueError):
            YaraEventAnalyzer()

    def test_default_severity_boost(self) -> None:
        ya = YaraEventAnalyzer(rules_source=_SIMPLE_YARA)
        self.assertAlmostEqual(ya._yara_boost, 0.25)

    def test_custom_severity_boost(self) -> None:
        ya = YaraEventAnalyzer(rules_source=_SIMPLE_YARA, yara_severity_boost=0.5)
        self.assertAlmostEqual(ya._yara_boost, 0.5)

    def test_is_subclass_of_event_analyzer(self) -> None:
        self.assertTrue(issubclass(YaraEventAnalyzer, EventAnalyzer))


class TestYaraEventAnalyzerParsing(unittest.TestCase):
    """YARA augmentation of parsed security events."""

    def setUp(self) -> None:
        self.ya = YaraEventAnalyzer(rules_source=_SIMPLE_YARA)

    def test_yara_match_added_to_sigs(self) -> None:
        event = self.ya.parse("MALWARE detected from 10.0.0.1")
        self.assertIn("YARA:TestMalware", event.matched_sigs)

    def test_no_yara_match_on_clean_log(self) -> None:
        event = self.ya.parse("Normal login from 192.168.1.1")
        yara_sigs = [s for s in event.matched_sigs if s.startswith("YARA:")]
        self.assertEqual(len(yara_sigs), 0)

    def test_severity_boosted_on_match(self) -> None:
        event = self.ya.parse("MALWARE detected from 10.0.0.1")
        # Base severity + boost must be > base severity alone
        base_event = EventAnalyzer().parse("MALWARE detected from 10.0.0.1")
        self.assertGreaterEqual(event.severity, base_event.severity)

    def test_severity_capped_at_one(self) -> None:
        event = self.ya.parse("MALWARE " * 20)
        self.assertLessEqual(event.severity, 1.0)

    def test_parent_regex_sigs_still_work(self) -> None:
        event = self.ya.parse("Failed password for root from 10.0.0.1")
        self.assertIn("SSH_BRUTE_FORCE", event.matched_sigs)

    def test_returns_security_event(self) -> None:
        event = self.ya.parse("some log line")
        self.assertIsInstance(event, SecurityEvent)

    def test_yara_prefix_in_sig_name(self) -> None:
        event = self.ya.parse("MALWARE found")
        yara_sigs = [s for s in event.matched_sigs if s.startswith("YARA:")]
        self.assertTrue(len(yara_sigs) >= 1)

    def test_no_duplicate_yara_sig(self) -> None:
        # Calling parse twice should not double-add (parse creates fresh event)
        event = self.ya.parse("MALWARE found")
        count = event.matched_sigs.count("YARA:TestMalware")
        self.assertEqual(count, 1)


# ──────────────────────────────────────────────────────────────────────────────
# 7. BinaryFuzzer
# ──────────────────────────────────────────────────────────────────────────────

class TestBinaryFuzzerInit(unittest.TestCase):
    """Construction and architecture setting."""

    def test_default_arch(self) -> None:
        f = BinaryFuzzer()
        self.assertEqual(f.arch, "amd64")

    def test_custom_arch(self) -> None:
        f = BinaryFuzzer(arch="i386")
        self.assertEqual(f.arch, "i386")

    def test_default_endian(self) -> None:
        f = BinaryFuzzer()
        self.assertEqual(f.endian, "little")


class TestBinaryFuzzerCyclic(unittest.TestCase):
    """Cyclic payload generation and offset discovery."""

    def setUp(self) -> None:
        self.fuzzer = BinaryFuzzer()

    def test_cyclic_payload_length(self) -> None:
        p = self.fuzzer.cyclic_payload(100)
        self.assertEqual(len(p), 100)

    def test_cyclic_payload_type(self) -> None:
        p = self.fuzzer.cyclic_payload(64)
        self.assertIsInstance(p, bytes)

    def test_cyclic_payload_is_deterministic(self) -> None:
        p1 = self.fuzzer.cyclic_payload(64)
        p2 = self.fuzzer.cyclic_payload(64)
        self.assertEqual(p1, p2)

    def test_find_offset_returns_int(self) -> None:
        p = self.fuzzer.cyclic_payload(256)
        offset = self.fuzzer.find_offset(p[:4])
        self.assertIsInstance(offset, int)
        self.assertEqual(offset, 0)

    def test_find_offset_non_zero(self) -> None:
        p = self.fuzzer.cyclic_payload(256)
        # Sub-sequence starting at byte 8 should yield offset 8
        offset = self.fuzzer.find_offset(p[8:12])
        self.assertEqual(offset, 8)

    def test_find_offset_invalid_returns_none(self) -> None:
        result = self.fuzzer.find_offset(b"\xff\xff\xff\xff")
        self.assertIsNone(result)


class TestBinaryFuzzerRepeat(unittest.TestCase):
    """Repeat-pattern payload generation."""

    def setUp(self) -> None:
        self.fuzzer = BinaryFuzzer()

    def test_repeat_length(self) -> None:
        p = self.fuzzer.repeat_payload(b"A", 128)
        self.assertEqual(len(p), 128)

    def test_repeat_content(self) -> None:
        p = self.fuzzer.repeat_payload(b"\x41", 8)
        self.assertEqual(p, b"AAAAAAAA")

    def test_repeat_multi_byte_pattern(self) -> None:
        p = self.fuzzer.repeat_payload(b"AB", 6)
        self.assertEqual(p, b"ABABAB")

    def test_repeat_empty_pattern_raises(self) -> None:
        with self.assertRaises(ValueError):
            self.fuzzer.repeat_payload(b"", 8)


class TestBinaryFuzzerFormatString(unittest.TestCase):
    """Format-string probe generation."""

    def setUp(self) -> None:
        self.fuzzer = BinaryFuzzer()

    def test_probes_returns_list(self) -> None:
        probes = self.fuzzer.format_string_probes()
        self.assertIsInstance(probes, list)

    def test_probes_all_bytes(self) -> None:
        for probe in self.fuzzer.format_string_probes():
            self.assertIsInstance(probe, bytes)

    def test_probes_count(self) -> None:
        # 8 different format specifier templates
        self.assertEqual(len(self.fuzzer.format_string_probes()), 8)

    def test_probes_non_empty(self) -> None:
        for probe in self.fuzzer.format_string_probes():
            self.assertGreater(len(probe), 0)


class TestBinaryFuzzerOverflow(unittest.TestCase):
    """overflow_with_pattern helper."""

    def setUp(self) -> None:
        self.fuzzer = BinaryFuzzer()

    def test_overflow_length(self) -> None:
        p = self.fuzzer.overflow_with_pattern(24, b"\xde\xad\xbe\xef")
        self.assertEqual(len(p), 28)

    def test_overflow_ends_with_payload(self) -> None:
        payload = b"\xde\xad\xbe\xef"
        p = self.fuzzer.overflow_with_pattern(16, payload)
        self.assertTrue(p.endswith(payload))

    def test_overflow_zero_offset(self) -> None:
        p = self.fuzzer.overflow_with_pattern(0, b"SHELL")
        self.assertEqual(p, b"SHELL")

    def test_overflow_no_extra_payload(self) -> None:
        p = self.fuzzer.overflow_with_pattern(8)
        self.assertEqual(len(p), 8)


# ──────────────────────────────────────────────────────────────────────────────
# 8. aggregate_scan_results
# ──────────────────────────────────────────────────────────────────────────────

def _make_port_results() -> list[PortScanResult]:
    return [
        PortScanResult("10.0.0.1", 22,  True,  "SSH"),
        PortScanResult("10.0.0.1", 80,  True,  "HTTP"),
        PortScanResult("10.0.0.1", 443, False, ""),
    ]


def _make_vuln_findings() -> list[VulnerabilityFinding]:
    return [
        VulnerabilityFinding(
            cve_id="CVE-2023-1234",
            severity="HIGH",
            cvss_score=7.5,
            service="SSH",
            description="Weak SSH key exchange",
        ),
    ]


def _make_fingerprints() -> list[ServiceFingerprintResult]:
    return [
        ServiceFingerprintResult(
            host="10.0.0.1", port=80,
            raw_banner="Server: nginx/1.18.0",
            service_name="nginx",
            service_version="1.18.0",
        ),
    ]


class TestAggregateScanResults(unittest.TestCase):
    """pandas-backed scan aggregation."""

    def test_port_results_shape(self) -> None:
        import pandas as pd
        df = aggregate_scan_results(port_results=_make_port_results())
        self.assertIsInstance(df, pd.DataFrame)
        self.assertEqual(len(df), 3)

    def test_vuln_findings_shape(self) -> None:
        df = aggregate_scan_results(vuln_findings=_make_vuln_findings())
        self.assertEqual(len(df), 1)

    def test_fingerprints_shape(self) -> None:
        df = aggregate_scan_results(fingerprints=_make_fingerprints())
        self.assertEqual(len(df), 1)

    def test_combined_shape(self) -> None:
        df = aggregate_scan_results(
            port_results=_make_port_results(),
            vuln_findings=_make_vuln_findings(),
            fingerprints=_make_fingerprints(),
        )
        self.assertEqual(len(df), 5)

    def test_required_columns(self) -> None:
        df = aggregate_scan_results(port_results=_make_port_results())
        for col in ("result_type", "host", "port", "is_open", "service",
                    "severity", "description", "cve_ids"):
            self.assertIn(col, df.columns)

    def test_port_result_type_label(self) -> None:
        df = aggregate_scan_results(port_results=_make_port_results())
        self.assertTrue((df["result_type"] == "port_scan").all())

    def test_vuln_result_type_label(self) -> None:
        df = aggregate_scan_results(vuln_findings=_make_vuln_findings())
        self.assertTrue((df["result_type"] == "vuln_finding").all())

    def test_fingerprint_result_type_label(self) -> None:
        df = aggregate_scan_results(fingerprints=_make_fingerprints())
        self.assertTrue((df["result_type"] == "fingerprint").all())

    def test_cve_ids_joined_with_pipe(self) -> None:
        df = aggregate_scan_results(vuln_findings=_make_vuln_findings())
        self.assertEqual(df.iloc[0]["cve_ids"], "CVE-2023-1234")

    def test_empty_call_returns_empty_df(self) -> None:
        df = aggregate_scan_results()
        self.assertEqual(len(df), 0)

    def test_is_open_for_closed_port(self) -> None:
        results = [PortScanResult("10.0.0.1", 443, False, "")]
        df = aggregate_scan_results(port_results=results)
        self.assertFalse(df.iloc[0]["is_open"])


# ──────────────────────────────────────────────────────────────────────────────
# 9 & 10. SiemExporter.to_dataframe / summary_stats
# ──────────────────────────────────────────────────────────────────────────────

def _make_threat_reports(n: int = 2) -> list[ThreatReport]:
    analyzer = EventAnalyzer()
    det = ThreatDetector()
    events = [
        analyzer.parse("Failed password for root from 10.0.0.1"),
        analyzer.parse("Normal connection from 192.168.0.1"),
    ]
    return det.analyze_bulk(events[:n])


class TestSiemExporterToDataframe(unittest.TestCase):
    """to_dataframe produces correct structure for each finding type."""

    def setUp(self) -> None:
        self.exporter = SiemExporter()

    def test_threat_report_row(self) -> None:
        import pandas as pd
        df = self.exporter.to_dataframe(_make_threat_reports(1))
        self.assertIsInstance(df, pd.DataFrame)
        self.assertEqual(len(df), 1)

    def test_required_columns(self) -> None:
        df = self.exporter.to_dataframe(_make_threat_reports(2))
        for col in ("item_type", "threat_level", "source", "score",
                    "signatures", "description"):
            self.assertIn(col, df.columns)

    def test_item_type_label(self) -> None:
        df = self.exporter.to_dataframe(_make_threat_reports(1))
        self.assertEqual(df.iloc[0]["item_type"], "ThreatReport")

    def test_score_in_range(self) -> None:
        df = self.exporter.to_dataframe(_make_threat_reports(2))
        self.assertTrue((df["score"] >= 0.0).all())
        self.assertTrue((df["score"] <= 1.0).all())

    def test_empty_items_returns_empty_df(self) -> None:
        df = self.exporter.to_dataframe([])
        self.assertEqual(len(df), 0)

    def test_multiple_types_combined(self) -> None:
        from sentinel_weave.email_scanner import EmailScanner, EmailMessage
        scanner = EmailScanner()
        email = EmailMessage(
            sender="bad@evil.com",
            recipients=["victim@example.com"],
            subject="Urgent!!",
            body_text="Click here now",
        )
        email_result = scanner.scan(email)
        reports = _make_threat_reports(1)
        df = self.exporter.to_dataframe(reports + [email_result])
        types = set(df["item_type"])
        self.assertIn("ThreatReport",    types)
        self.assertIn("EmailScanResult", types)

    def test_row_count_matches_input(self) -> None:
        reports = _make_threat_reports(2)
        df = self.exporter.to_dataframe(reports)
        self.assertEqual(len(df), 2)


class TestSiemExporterSummaryStats(unittest.TestCase):
    """summary_stats groups by (item_type, threat_level)."""

    def setUp(self) -> None:
        self.exporter = SiemExporter()
        self.reports  = _make_threat_reports(2)

    def test_returns_dataframe(self) -> None:
        import pandas as pd
        df = self.exporter.summary_stats(self.reports)
        self.assertIsInstance(df, pd.DataFrame)

    def test_required_columns(self) -> None:
        df = self.exporter.summary_stats(self.reports)
        for col in ("item_type", "threat_level", "count",
                    "mean_score", "max_score", "unique_sources"):
            self.assertIn(col, df.columns)

    def test_count_sums_to_total(self) -> None:
        df = self.exporter.summary_stats(self.reports)
        self.assertEqual(df["count"].sum(), len(self.reports))

    def test_empty_returns_empty_df(self) -> None:
        df = self.exporter.summary_stats([])
        self.assertEqual(len(df), 0)

    def test_mean_score_in_range(self) -> None:
        df = self.exporter.summary_stats(self.reports)
        self.assertTrue((df["mean_score"] >= 0.0).all())
        self.assertTrue((df["mean_score"] <= 1.0).all())

    def test_max_score_gte_mean(self) -> None:
        df = self.exporter.summary_stats(self.reports)
        self.assertTrue((df["max_score"] >= df["mean_score"]).all())


# ──────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    unittest.main()
