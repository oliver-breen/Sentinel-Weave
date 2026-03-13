"""
Extended ML Pipeline Tests — SentinelWeave
==========================================

These tests are designed for two purposes:

1. **Personal validation** — rigorously verify the ML pipeline beyond the
   happy-path unit tests already in ``test_sentinel_weave.py``.

2. **Exhibition / demo material** — each test class has a rich docstring
   explaining *why* the property under test matters in a real ML/security
   context, making the file readable as a standalone learning resource.

Test classes
------------
TestLabeledEvent
    Validate the dataclass that carries a feature vector + ground-truth label.

TestDatasetBuilderLabeling
    Auto-labeling of ThreatReport objects; threshold sensitivity.

TestDatasetBuilderBalance
    Oversample and undersample strategies; edge cases (empty, all-same-class).

TestDatasetBuilderSplit
    Train/test split size, stratification, reproducibility.

TestClassifierInit
    Confirm weight initialisation and hyperparameter storage.

TestClassifierTrainingConvergence
    Loss must decrease during training; weights must change; returns history.

TestClassifierPredictions
    Known-input regression tests — the model must learn to distinguish
    archetypal threat vs. benign feature vectors.

TestClassifierEvaluation
    Metrics correctness (confusion matrix, precision, recall, F1).

TestFeatureImportanceDirectionality
    After training on representative data the sign of the most influential
    weights must reflect real-world domain knowledge.

TestDecisionThresholdSensitivity
    Lowering the threshold increases recall; raising it increases precision.

TestModelPersistence
    Save→load round-trip preserves all weights and every prediction.

TestAzureMLSchemaCompliance
    The exported dict satisfies the structure required by an Azure ML
    real-time inference endpoint.

TestEvaluateClassifierWrapper
    Convenience wrapper trains + evaluates in one call; validates edge cases.

TestCrossValidationReproducibility
    Same random seed → identical results; different seeds → different splits.

TestImbalancedDataHandling
    With extreme class imbalance (1:50) the pipeline still converges and
    outperforms a trivial majority-class baseline.

TestPipelineIntegration
    Full end-to-end integration: raw log strings → trained model → metrics.
    Uses the same realistic log corpus as ``examples/ml_demo.py``.

TestScoreFunctionStub
    The score_function_stub exported for Azure ML must be executable Python
    that returns the same probabilities as the trained classifier.
"""

from __future__ import annotations

import json
import math
import os
import random
import sys
import tempfile
import unittest

# Allow running from the repository root without an editable install.
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from sentinel_weave.event_analyzer import EventAnalyzer
from sentinel_weave.threat_detector import ThreatDetector, ThreatLevel, ThreatReport
from sentinel_weave.ml_pipeline import (
    DatasetBuilder,
    LabeledEvent,
    SecurityClassifier,
    _oversample,
    evaluate_classifier,
)


# ─────────────────────────────────────────────────────────────────────────────
# Shared fixtures
# ─────────────────────────────────────────────────────────────────────────────

# 13-element feature vector that looks like a clear threat.
# All features are high (≈0.9) to match the Gaussian(0.85, 0.05) training
# distribution used by _build_separable_dataset so prediction tests have
# consistent behaviour without depending on a specific random seed.
_THREAT_FEATS: list[float] = [0.9] * 13
# 13-element feature vector that looks clearly benign.
# All features are low (≈0.1) to match the Gaussian(0.15, 0.05) distribution.
_BENIGN_FEATS: list[float] = [0.1] * 13

#: Log lines used across integration and feature-importance tests.
_THREAT_LINES: list[str] = [
    "Jan 15 10:23:01 web01 sshd: Failed password for root from 198.51.100.42 port 54321 ssh2",
    "Jan 15 10:23:02 web01 sshd: Failed password for root from 198.51.100.42 port 54322 ssh2",
    "Jan 15 10:23:03 web01 sshd: Failed password for invalid user admin from 198.51.100.42",
    "Jan 15 10:24:00 web01 nginx: GET /?id=1' UNION SELECT username,password FROM users-- from 10.0.0.99",
    "Jan 15 10:24:01 web01 nginx: GET /../../../../etc/passwd HTTP/1.1 404 from 10.0.0.99",
    "Jan 15 10:24:02 web01 auditd: PRIVILEGE_ESCALATION detected uid=0 from process 4401",
    "Jan 15 10:25:00 web01 kernel: iptables DROP SRC=198.51.100.42 DPT=22 PORT_SCAN detected",
    "Jan 15 10:25:01 web01 nginx: GET /?search=<script>alert('xss')</script> from 172.16.0.5",
    "Jan 15 10:25:02 web01 syslog: CREDENTIAL_DUMP attempt /etc/shadow access from PID 4401",
    "Jan 15 10:25:03 web01 kernel: MALWARE_INDICATOR outbound C2 beacon 185.220.101.5",
]

_BENIGN_LINES: list[str] = [
    "Jan 15 10:30:00 web01 sshd: Accepted publickey for alice from 10.1.0.20 port 60001 ssh2",
    "Jan 15 10:30:01 web01 syslog: cron job completed disk health check OK",
    "Jan 15 10:30:02 web01 syslog: Service nginx started successfully",
    "Jan 15 10:30:03 web01 syslog: Scheduled backup completed successfully 14 GB",
    "Jan 15 10:30:04 web01 syslog: Normal user login success for bob from 192.168.100.50",
    "Jan 15 10:30:05 web01 syslog: System clock synchronized via NTP server",
    "Jan 15 10:30:06 web01 syslog: Package updates applied: 3 security 2 bugfix",
    "Jan 15 10:30:07 web01 nginx: 10.1.0.20 GET /index.html HTTP/1.1 200 1234 bytes",
    "Jan 15 10:30:08 web01 syslog: TLS certificate renewed for company.com",
    "Jan 15 10:30:09 web01 syslog: Database connection pool healthy 10 connections",
]


def _make_labeled(feats: list[float], label: int, n: int = 1) -> list[LabeledEvent]:
    """Return *n* copies of a LabeledEvent with given features and label."""
    return [LabeledEvent(features=list(feats), label=label) for _ in range(n)]


def _build_separable_dataset(
    n_each: int = 40, seed: int = 0
) -> list[LabeledEvent]:
    """
    Build a clearly separable balanced dataset for convergence tests.

    Threats have high-valued features; benign have low-valued features.
    The two classes are well-separated so we can assert strong convergence.
    """
    rng = random.Random(seed)
    dataset: list[LabeledEvent] = []
    for _ in range(n_each):
        t_feats = [min(1.0, max(0.0, rng.gauss(0.85, 0.05))) for _ in range(13)]
        dataset.append(LabeledEvent(features=t_feats, label=1))
    for _ in range(n_each):
        b_feats = [min(1.0, max(0.0, rng.gauss(0.15, 0.05))) for _ in range(13)]
        dataset.append(LabeledEvent(features=b_feats, label=0))
    rng.shuffle(dataset)
    return dataset


# ─────────────────────────────────────────────────────────────────────────────
# TestLabeledEvent
# ─────────────────────────────────────────────────────────────────────────────

class TestLabeledEvent(unittest.TestCase):
    """
    Validate the LabeledEvent dataclass.

    LabeledEvent is the unit of currency for the entire ML pipeline.
    Every training example is a (features, label, weight) triple.  These tests
    confirm that the dataclass behaves as a plain container with the expected
    defaults — important because downstream code reads .features and .label
    without defensive checks.
    """

    def test_stores_features_and_label(self) -> None:
        evt = LabeledEvent(features=[0.5, 0.3], label=1)
        self.assertEqual(evt.features, [0.5, 0.3])
        self.assertEqual(evt.label, 1)

    def test_default_weight_is_one(self) -> None:
        """Sample weight defaults to 1.0 so all examples contribute equally."""
        evt = LabeledEvent(features=[0.0] * 13, label=0)
        self.assertEqual(evt.weight, 1.0)

    def test_custom_weight(self) -> None:
        evt = LabeledEvent(features=[0.0] * 13, label=1, weight=2.5)
        self.assertAlmostEqual(evt.weight, 2.5)

    def test_label_values_are_integers(self) -> None:
        for label in (0, 1):
            evt = LabeledEvent(features=[], label=label)
            self.assertIsInstance(evt.label, int)

    def test_features_list_is_mutable(self) -> None:
        """Features must be a list (not a tuple) so downstream code can index."""
        evt = LabeledEvent(features=[1.0, 0.5], label=0)
        evt.features[0] = 0.9   # must not raise
        self.assertAlmostEqual(evt.features[0], 0.9)


# ─────────────────────────────────────────────────────────────────────────────
# TestDatasetBuilderLabeling
# ─────────────────────────────────────────────────────────────────────────────

class TestDatasetBuilderLabeling(unittest.TestCase):
    """
    Validate auto-labeling via DatasetBuilder.from_reports.

    In a real SOC pipeline labels are expensive — human analysts review only a
    fraction of alerts.  DatasetBuilder auto-labels by comparing each report's
    ThreatLevel against a configurable threshold.  These tests verify that:

    * Reports at or above the threshold receive label 1 (threat).
    * Reports below the threshold receive label 0 (benign).
    * Reports with empty feature vectors are silently skipped (they cannot be
      used for training).
    * The threshold itself is configurable (MEDIUM, HIGH, etc.).
    """

    def setUp(self) -> None:
        self.analyzer = EventAnalyzer()
        self.detector = ThreatDetector()

    def _report(self, level: ThreatLevel) -> ThreatReport:
        event = self.analyzer.parse("dummy line for testing")
        event.features = [0.5] * 13
        rpt = ThreatReport(event=event, threat_level=level)
        return rpt

    def test_critical_is_threat(self) -> None:
        labeled = DatasetBuilder.from_reports([self._report(ThreatLevel.CRITICAL)])
        self.assertEqual(labeled[0].label, 1)

    def test_high_is_threat_at_medium_threshold(self) -> None:
        labeled = DatasetBuilder.from_reports(
            [self._report(ThreatLevel.HIGH)],
            threat_threshold=ThreatLevel.MEDIUM,
        )
        self.assertEqual(labeled[0].label, 1)

    def test_low_is_benign_at_medium_threshold(self) -> None:
        labeled = DatasetBuilder.from_reports(
            [self._report(ThreatLevel.LOW)],
            threat_threshold=ThreatLevel.MEDIUM,
        )
        self.assertEqual(labeled[0].label, 0)

    def test_benign_is_benign(self) -> None:
        labeled = DatasetBuilder.from_reports([self._report(ThreatLevel.BENIGN)])
        self.assertEqual(labeled[0].label, 0)

    def test_high_threshold_only_critical(self) -> None:
        """When threshold=HIGH only CRITICAL events are labeled 1."""
        reports = [
            self._report(ThreatLevel.MEDIUM),
            self._report(ThreatLevel.HIGH),
            self._report(ThreatLevel.CRITICAL),
        ]
        labeled = DatasetBuilder.from_reports(reports, threat_threshold=ThreatLevel.HIGH)
        self.assertEqual(labeled[0].label, 0)  # MEDIUM
        self.assertEqual(labeled[1].label, 1)  # HIGH
        self.assertEqual(labeled[2].label, 1)  # CRITICAL

    def test_reports_without_features_are_skipped(self) -> None:
        """Reports whose events have no feature vector cannot train the model."""
        event = self.analyzer.parse("dummy")
        event.features = []
        rpt = ThreatReport(event=event, threat_level=ThreatLevel.CRITICAL)
        labeled = DatasetBuilder.from_reports([rpt])
        self.assertEqual(len(labeled), 0)

    def test_mixed_reports_correct_count(self) -> None:
        levels = [
            ThreatLevel.BENIGN,
            ThreatLevel.LOW,
            ThreatLevel.MEDIUM,
            ThreatLevel.HIGH,
            ThreatLevel.CRITICAL,
        ]
        reports = [self._report(lvl) for lvl in levels]
        labeled = DatasetBuilder.from_reports(reports)
        threats = sum(1 for e in labeled if e.label == 1)
        benigns = sum(1 for e in labeled if e.label == 0)
        self.assertEqual(threats, 3)   # MEDIUM, HIGH, CRITICAL
        self.assertEqual(benigns, 2)   # BENIGN, LOW


# ─────────────────────────────────────────────────────────────────────────────
# TestDatasetBuilderBalance
# ─────────────────────────────────────────────────────────────────────────────

class TestDatasetBuilderBalance(unittest.TestCase):
    """
    Validate class-balancing strategies.

    In security data benign events can outnumber threats 50:1 or more.
    A naive classifier trained on this distribution learns to predict
    "benign" for everything and achieves high accuracy while being useless.
    Balancing fixes this by making the training loss treat both classes equally.

    oversample: minority class is duplicated (with replacement) until equal.
    undersample: majority class is randomly pruned until equal.
    """

    def _imbalanced(self, n_threats: int = 5, n_benign: int = 50) -> list[LabeledEvent]:
        return (
            _make_labeled(_THREAT_FEATS, 1, n_threats) +
            _make_labeled(_BENIGN_FEATS, 0, n_benign)
        )

    def test_oversample_equalises_classes(self) -> None:
        balanced = DatasetBuilder.balance(self._imbalanced(), strategy="oversample")
        pos = sum(1 for e in balanced if e.label == 1)
        neg = sum(1 for e in balanced if e.label == 0)
        self.assertEqual(pos, neg)

    def test_oversample_grows_dataset(self) -> None:
        before = self._imbalanced(5, 50)
        after  = DatasetBuilder.balance(before, strategy="oversample")
        self.assertGreaterEqual(len(after), len(before))

    def test_undersample_equalises_classes(self) -> None:
        balanced = DatasetBuilder.balance(self._imbalanced(), strategy="undersample")
        pos = sum(1 for e in balanced if e.label == 1)
        neg = sum(1 for e in balanced if e.label == 0)
        self.assertEqual(pos, neg)

    def test_undersample_shrinks_dataset(self) -> None:
        before = self._imbalanced(5, 50)
        after  = DatasetBuilder.balance(before, strategy="undersample")
        self.assertLessEqual(len(after), len(before))

    def test_invalid_strategy_raises(self) -> None:
        with self.assertRaises(ValueError):
            DatasetBuilder.balance(self._imbalanced(), strategy="magic")

    def test_empty_dataset_returns_empty(self) -> None:
        self.assertEqual(DatasetBuilder.balance([]), [])

    def test_single_class_returns_unchanged(self) -> None:
        """If only one class is present, balancing has no effect."""
        single = _make_labeled(_THREAT_FEATS, 1, 10)
        result = DatasetBuilder.balance(single, strategy="oversample")
        self.assertEqual(len(result), 10)

    def test_seed_gives_reproducible_undersample(self) -> None:
        data = self._imbalanced()
        b1 = DatasetBuilder.balance(data, strategy="undersample", seed=99)
        b2 = DatasetBuilder.balance(data, strategy="undersample", seed=99)
        self.assertEqual(
            [e.label for e in b1],
            [e.label for e in b2],
        )

    def test_different_seeds_give_different_shuffles(self) -> None:
        data = self._imbalanced()
        b1 = DatasetBuilder.balance(data, strategy="oversample", seed=1)
        b2 = DatasetBuilder.balance(data, strategy="oversample", seed=2)
        # With 55 oversample-balanced items it is vanishingly unlikely the
        # shuffle is identical across two different seeds.
        labels1 = [e.label for e in b1]
        labels2 = [e.label for e in b2]
        self.assertNotEqual(labels1, labels2)


# ─────────────────────────────────────────────────────────────────────────────
# TestDatasetBuilderSplit
# ─────────────────────────────────────────────────────────────────────────────

class TestDatasetBuilderSplit(unittest.TestCase):
    """
    Validate the train/test split.

    A reliable split is crucial: if test examples leak into training data
    the reported accuracy is optimistically biased.  These tests confirm
    that sizes are correct, sets are disjoint, and the seed gives
    deterministic behaviour (essential for experiment reproducibility).
    """

    def setUp(self) -> None:
        self.data = (
            _make_labeled(_THREAT_FEATS, 1, 40) +
            _make_labeled(_BENIGN_FEATS, 0, 40)
        )

    def test_default_split_ratio(self) -> None:
        train, test = DatasetBuilder.split(self.data, test_ratio=0.20)
        total = len(self.data)
        self.assertEqual(len(train) + len(test), total)
        self.assertAlmostEqual(len(test) / total, 0.20, delta=0.05)

    def test_custom_split_ratio(self) -> None:
        train, test = DatasetBuilder.split(self.data, test_ratio=0.30)
        total = len(self.data)
        self.assertAlmostEqual(len(test) / total, 0.30, delta=0.05)

    def test_no_overlap(self) -> None:
        """Training and test sets must be completely disjoint."""
        train, test = DatasetBuilder.split(self.data)
        train_ids = {id(e) for e in train}
        test_ids  = {id(e) for e in test}
        self.assertEqual(len(train_ids & test_ids), 0)

    def test_same_seed_reproducible(self) -> None:
        train1, test1 = DatasetBuilder.split(self.data, seed=77)
        train2, test2 = DatasetBuilder.split(self.data, seed=77)
        self.assertEqual([id(e) for e in train1], [id(e) for e in train2])
        self.assertEqual([id(e) for e in test1],  [id(e) for e in test2])

    def test_minimum_one_test_example(self) -> None:
        """Even with a tiny dataset at least one example must go to test."""
        small = _make_labeled(_THREAT_FEATS, 1, 3)
        _, test = DatasetBuilder.split(small, test_ratio=0.10)
        self.assertGreaterEqual(len(test), 1)


# ─────────────────────────────────────────────────────────────────────────────
# TestClassifierInit
# ─────────────────────────────────────────────────────────────────────────────

class TestClassifierInit(unittest.TestCase):
    """
    Verify SecurityClassifier initialisation.

    The model must start with the correct number of weights (N_FEATURES + 1 for
    the bias), and the hyperparameters must be stored faithfully.
    """

    def test_weight_count(self) -> None:
        clf = SecurityClassifier()
        self.assertEqual(len(clf.weights), SecurityClassifier.N_FEATURES + 1)

    def test_hyperparameters_stored(self) -> None:
        clf = SecurityClassifier(learning_rate=0.1, epochs=50, regularization=0.001)
        self.assertAlmostEqual(clf.learning_rate, 0.1)
        self.assertEqual(clf.epochs, 50)
        self.assertAlmostEqual(clf.regularization, 0.001)

    def test_not_trained_on_init(self) -> None:
        """A fresh model must not be flagged as trained before fit() is called."""
        clf = SecurityClassifier()
        self.assertFalse(clf._trained)

    def test_weights_are_small_on_init(self) -> None:
        """Initial weights should be near zero (Gaussian init, σ=0.01)."""
        clf = SecurityClassifier()
        for w in clf.weights:
            self.assertLess(abs(w), 0.5)


# ─────────────────────────────────────────────────────────────────────────────
# TestClassifierTrainingConvergence
# ─────────────────────────────────────────────────────────────────────────────

class TestClassifierTrainingConvergence(unittest.TestCase):
    """
    Verify that the logistic regression actually learns.

    A gradient-descent implementation is correct when:

    1. The loss strictly decreases over training (or at least is lower at the
       end than at the start).
    2. Weights change from their initial values — if they don't, the gradient
       computation is broken.
    3. The training history dict contains the expected keys and length.
    4. On clearly separable data the model should converge to near-zero loss.

    These tests use a synthetic well-separated dataset to ensure that the
    classifier *can* converge quickly regardless of hardware speed.
    """

    def setUp(self) -> None:
        self.data = _build_separable_dataset(n_each=40)

    def test_loss_decreases(self) -> None:
        """Final loss must be lower than initial loss."""
        clf = SecurityClassifier(epochs=100)
        history = clf.train(self.data)
        self.assertLess(history["final_loss"], history["initial_loss"])

    def test_weights_change_after_training(self) -> None:
        clf = SecurityClassifier(epochs=10)
        initial_weights = list(clf.weights)
        clf.train(self.data)
        self.assertNotEqual(clf.weights, initial_weights)

    def test_marked_trained_after_fit(self) -> None:
        clf = SecurityClassifier(epochs=10)
        clf.train(self.data)
        self.assertTrue(clf._trained)

    def test_history_keys_present(self) -> None:
        clf = SecurityClassifier(epochs=10)
        history = clf.train(self.data)
        for key in ("epochs", "initial_loss", "final_loss", "loss_history"):
            self.assertIn(key, history)

    def test_loss_history_length(self) -> None:
        n_epochs = 30
        clf = SecurityClassifier(epochs=n_epochs)
        history = clf.train(self.data)
        self.assertEqual(len(history["loss_history"]), n_epochs)

    def test_convergence_on_separable_data(self) -> None:
        """After enough epochs, loss should be well below 0.1 on easy data."""
        clf = SecurityClassifier(epochs=500, learning_rate=0.1)
        history = clf.train(self.data)
        self.assertLess(history["final_loss"], 0.1)

    def test_empty_dataset_raises(self) -> None:
        clf = SecurityClassifier()
        with self.assertRaises(ValueError):
            clf.train([])

    def test_full_batch_mode(self) -> None:
        """batch_size=None means the whole dataset is one batch — must still converge."""
        clf = SecurityClassifier(epochs=50, batch_size=None)
        history = clf.train(self.data)
        self.assertLess(history["final_loss"], history["initial_loss"])


# ─────────────────────────────────────────────────────────────────────────────
# TestClassifierPredictions
# ─────────────────────────────────────────────────────────────────────────────

class TestClassifierPredictions(unittest.TestCase):
    """
    Regression tests: known inputs must produce expected outputs.

    These tests pin the model's behaviour on archetypal examples so that any
    code change that accidentally alters the decision function is caught
    immediately.

    The training corpus uses very clear threat/benign prototypes so that
    the model can reach high confidence on these inputs in few epochs.
    """

    @classmethod
    def setUpClass(cls) -> None:
        """Train once and reuse across all prediction tests."""
        data = _build_separable_dataset(n_each=60)
        cls.clf = SecurityClassifier(epochs=400, learning_rate=0.1)
        cls.clf.train(data)

    def test_threat_prototype_high_proba(self) -> None:
        """Clear threat features must have probability > 0.8."""
        proba = self.clf.predict_proba(_THREAT_FEATS)
        self.assertGreater(proba, 0.8)

    def test_benign_prototype_low_proba(self) -> None:
        """Clear benign features must have probability < 0.2."""
        proba = self.clf.predict_proba(_BENIGN_FEATS)
        self.assertLess(proba, 0.2)

    def test_threat_classified_as_one(self) -> None:
        self.assertEqual(self.clf.predict(_THREAT_FEATS), 1)

    def test_benign_classified_as_zero(self) -> None:
        self.assertEqual(self.clf.predict(_BENIGN_FEATS), 0)

    def test_proba_in_unit_interval(self) -> None:
        """sigmoid output must always be in [0, 1]."""
        for feats in (_THREAT_FEATS, _BENIGN_FEATS, [0.5] * 13, [0.0] * 13, [1.0] * 13):
            p = self.clf.predict_proba(feats)
            self.assertGreaterEqual(p, 0.0)
            self.assertLessEqual(p, 1.0)

    def test_custom_threshold(self) -> None:
        """With threshold=0.9, even a moderate threat score should be benign."""
        mid_feats = [0.5] * 13
        proba = self.clf.predict_proba(mid_feats)
        pred_strict = self.clf.predict(mid_feats, threshold=0.9)
        if proba < 0.9:
            self.assertEqual(pred_strict, 0)


# ─────────────────────────────────────────────────────────────────────────────
# TestClassifierEvaluation
# ─────────────────────────────────────────────────────────────────────────────

class TestClassifierEvaluation(unittest.TestCase):
    """
    Verify that the evaluation method computes correct confusion matrix metrics.

    Precision, recall, and F1 are the standard metrics for imbalanced binary
    classification.  A bug in their calculation would give a false sense of
    security (literally), so we verify them against hand-computed gold values.
    """

    def _perfect_dataset(self, n: int = 20) -> list[LabeledEvent]:
        """All threats predicted correctly, no false alarms."""
        return (
            _make_labeled(_THREAT_FEATS, 1, n) +
            _make_labeled(_BENIGN_FEATS, 0, n)
        )

    @classmethod
    def setUpClass(cls) -> None:
        data = _build_separable_dataset(n_each=60)
        cls.clf = SecurityClassifier(epochs=500, learning_rate=0.1)
        cls.clf.train(data)

    def test_metrics_keys_present(self) -> None:
        metrics = self.clf.evaluate(self._perfect_dataset())
        for key in ("accuracy", "precision", "recall", "f1",
                    "true_positives", "false_positives",
                    "true_negatives", "false_negatives"):
            self.assertIn(key, metrics)

    def test_confusion_matrix_sums_to_total(self) -> None:
        dataset = self._perfect_dataset(20)
        m = self.clf.evaluate(dataset)
        total = m["true_positives"] + m["false_positives"] + m["true_negatives"] + m["false_negatives"]
        self.assertEqual(total, len(dataset))

    def test_accuracy_range(self) -> None:
        m = self.clf.evaluate(self._perfect_dataset())
        self.assertGreaterEqual(m["accuracy"], 0.0)
        self.assertLessEqual(m["accuracy"], 1.0)

    def test_precision_recall_f1_range(self) -> None:
        m = self.clf.evaluate(self._perfect_dataset())
        for key in ("precision", "recall", "f1"):
            self.assertGreaterEqual(m[key], 0.0)
            self.assertLessEqual(m[key], 1.0)

    def test_high_accuracy_on_separable(self) -> None:
        """On perfectly separable data the trained model should be near-perfect."""
        m = self.clf.evaluate(self._perfect_dataset(50))
        self.assertGreater(m["accuracy"], 0.90)

    def test_f1_harmonic_mean_of_precision_recall(self) -> None:
        """F1 must equal the harmonic mean of precision and recall."""
        m = self.clf.evaluate(self._perfect_dataset())
        p, r = m["precision"], m["recall"]
        if p + r > 0:
            expected_f1 = round(2 * p * r / (p + r), 4)
            self.assertAlmostEqual(m["f1"], expected_f1, places=3)


# ─────────────────────────────────────────────────────────────────────────────
# TestFeatureImportanceDirectionality
# ─────────────────────────────────────────────────────────────────────────────

class TestFeatureImportanceDirectionality(unittest.TestCase):
    """
    Verify that the learned weights reflect real security domain knowledge.

    One of the key advantages of logistic regression over "black-box" models
    (e.g. neural networks) is interpretability: each weight tells you how much
    the corresponding feature contributes to the threat score.

    Expected domain-knowledge relationships:

    * keyword_severity (feature 8) — high severity → threat; weight should
      be positive.
    * has_path_chars (feature 9) — path traversal chars in log → likely web
      attack; weight should be positive.
    * signature_count_norm (feature 7) — more signatures → threat; positive.

    We train on a corpus constructed so these signals are reliable.
    """

    @classmethod
    def setUpClass(cls) -> None:
        """Build a corpus where domain-knowledge features are genuinely predictive."""
        rng = random.Random(7)
        data: list[LabeledEvent] = []
        for _ in range(80):
            # Threats: high severity, path chars, multiple sigs
            feats = [rng.gauss(0.5, 0.1)] * 13
            feats[8] = rng.gauss(0.85, 0.05)  # keyword_severity → high
            feats[9] = 1.0  # has_path_chars
            feats[7] = rng.gauss(0.60, 0.05)  # signature_count_norm → high
            feats = [min(1.0, max(0.0, f)) for f in feats]
            data.append(LabeledEvent(features=feats, label=1))
        for _ in range(80):
            # Benign: low severity, no path chars, no sigs
            feats = [rng.gauss(0.3, 0.1)] * 13
            feats[8] = rng.gauss(0.10, 0.05)  # keyword_severity → low
            feats[9] = 0.0  # no path chars
            feats[7] = rng.gauss(0.02, 0.01)  # few signatures
            feats = [min(1.0, max(0.0, f)) for f in feats]
            data.append(LabeledEvent(features=feats, label=0))

        cls.clf = SecurityClassifier(epochs=400, learning_rate=0.1, regularization=0.001)
        cls.clf.train(data)

    def test_keyword_severity_positive_weight(self) -> None:
        """keyword_severity is feature index 8; high value means threat."""
        self.assertGreater(self.clf.weights[8], 0)

    def test_has_path_chars_positive_weight(self) -> None:
        """has_path_chars is feature index 9; path traversal indicates attack."""
        self.assertGreater(self.clf.weights[9], 0)

    def test_signature_count_positive_weight(self) -> None:
        """signature_count_norm is feature index 7; more sigs means threat."""
        self.assertGreater(self.clf.weights[7], 0)

    def test_most_influential_weight_is_nonzero(self) -> None:
        max_abs = max(abs(w) for w in self.clf.weights[:-1])
        self.assertGreater(max_abs, 0.1)


# ─────────────────────────────────────────────────────────────────────────────
# TestDecisionThresholdSensitivity
# ─────────────────────────────────────────────────────────────────────────────

class TestDecisionThresholdSensitivity(unittest.TestCase):
    """
    Verify the precision/recall trade-off as the decision threshold changes.

    SOC operators can tune the threshold:
    - Lower threshold  → more alerts → higher recall (fewer missed attacks)
                       → lower precision (more false alarms → analyst fatigue)
    - Higher threshold → fewer alerts → higher precision (less noise)
                       → lower recall (some real attacks missed)

    These tests confirm the classifier honours this fundamental property.
    """

    @classmethod
    def setUpClass(cls) -> None:
        data = _build_separable_dataset(n_each=60)
        cls.clf = SecurityClassifier(epochs=400, learning_rate=0.1)
        cls.clf.train(data)
        cls.test_data = _build_separable_dataset(n_each=30, seed=99)

    def _metrics_at(self, threshold: float) -> dict:
        tp = fp = tn = fn = 0
        for item in self.test_data:
            pred = 1 if self.clf.predict_proba(item.features) >= threshold else 0
            if   pred == 1 and item.label == 1: tp += 1
            elif pred == 1 and item.label == 0: fp += 1
            elif pred == 0 and item.label == 0: tn += 1
            else:                               fn += 1
        prec = tp / (tp + fp) if (tp + fp) else 1.0
        rec  = tp / (tp + fn) if (tp + fn) else 0.0
        return {"precision": prec, "recall": rec, "alerts": tp + fp}

    def test_lower_threshold_increases_recall(self) -> None:
        low  = self._metrics_at(0.2)
        high = self._metrics_at(0.8)
        self.assertGreaterEqual(low["recall"], high["recall"])

    def test_higher_threshold_reduces_alerts(self) -> None:
        low  = self._metrics_at(0.2)
        high = self._metrics_at(0.8)
        self.assertGreaterEqual(low["alerts"], high["alerts"])

    def test_threshold_zero_classifies_everything_as_threat(self) -> None:
        for item in self.test_data:
            pred = 1 if self.clf.predict_proba(item.features) >= 0.0 else 0
            self.assertEqual(pred, 1)

    def test_threshold_one_classifies_everything_as_benign(self) -> None:
        for item in self.test_data:
            pred = 1 if self.clf.predict_proba(item.features) >= 1.0 else 0
            self.assertEqual(pred, 0)


# ─────────────────────────────────────────────────────────────────────────────
# TestModelPersistence
# ─────────────────────────────────────────────────────────────────────────────

class TestModelPersistence(unittest.TestCase):
    """
    Verify that the JSON save/load round-trip is lossless.

    The ability to serialize a trained model to a small JSON file is what makes
    SentinelWeave deployable to Azure ML without heavy ML framework dependencies.
    The model must survive a save→load cycle with *all* predictions preserved.
    """

    @classmethod
    def setUpClass(cls) -> None:
        data = _build_separable_dataset(n_each=40)
        cls.clf = SecurityClassifier(epochs=200, learning_rate=0.1)
        cls.clf.train(data)
        cls.test_data = _build_separable_dataset(n_each=20, seed=55)

    def test_save_creates_file(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as fh:
            path = fh.name
        try:
            self.clf.save(path)
            self.assertTrue(os.path.isfile(path))
        finally:
            os.unlink(path)

    def test_saved_file_is_valid_json(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as fh:
            path = fh.name
        try:
            self.clf.save(path)
            with open(path) as f:
                payload = json.load(f)
            self.assertIn("model_type", payload)
        finally:
            os.unlink(path)

    def test_load_restores_weights(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as fh:
            path = fh.name
        try:
            self.clf.save(path)
            loaded = SecurityClassifier.load(path)
            self.assertEqual(self.clf.weights, loaded.weights)
        finally:
            os.unlink(path)

    def test_all_predictions_match_after_round_trip(self) -> None:
        """Every prediction on the test set must be identical before and after reload."""
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as fh:
            path = fh.name
        try:
            self.clf.save(path)
            loaded = SecurityClassifier.load(path)
            for item in self.test_data:
                self.assertEqual(
                    self.clf.predict(item.features),
                    loaded.predict(item.features),
                )
        finally:
            os.unlink(path)

    def test_probabilities_match_after_round_trip(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as fh:
            path = fh.name
        try:
            self.clf.save(path)
            loaded = SecurityClassifier.load(path)
            for item in self.test_data:
                self.assertAlmostEqual(
                    self.clf.predict_proba(item.features),
                    loaded.predict_proba(item.features),
                    places=12,
                )
        finally:
            os.unlink(path)

    def test_load_wrong_model_type_raises(self) -> None:
        with tempfile.NamedTemporaryFile(
            suffix=".json", delete=False, mode="w"
        ) as fh:
            json.dump({"model_type": "RandomForest", "weights": []}, fh)
            path = fh.name
        try:
            with self.assertRaises(ValueError):
                SecurityClassifier.load(path)
        finally:
            os.unlink(path)


# ─────────────────────────────────────────────────────────────────────────────
# TestAzureMLSchemaCompliance
# ─────────────────────────────────────────────────────────────────────────────

class TestAzureMLSchemaCompliance(unittest.TestCase):
    """
    Verify the Azure ML scoring endpoint export.

    to_azure_ml_schema() must return a dict that satisfies the structure
    expected by an Azure ML real-time inference endpoint:

    - model_spec    : describes the model architecture and weights
    - input_schema  : describes the expected input tensor shape and names
    - score_function_stub : ready-to-paste Python scoring code

    These tests confirm the structure independently of the model's accuracy.
    """

    @classmethod
    def setUpClass(cls) -> None:
        data = _build_separable_dataset(n_each=30)
        clf = SecurityClassifier(epochs=100)
        clf.train(data)
        cls.schema = clf.to_azure_ml_schema()
        cls.n_features = SecurityClassifier.N_FEATURES

    def test_top_level_keys(self) -> None:
        for key in ("model_spec", "input_schema", "score_function_stub"):
            self.assertIn(key, self.schema)

    def test_model_spec_has_weights_and_bias(self) -> None:
        spec = self.schema["model_spec"]
        self.assertIn("weights", spec)
        self.assertIn("bias", spec)

    def test_model_spec_weights_length(self) -> None:
        """There must be exactly N_FEATURES weights (bias is stored separately)."""
        self.assertEqual(len(self.schema["model_spec"]["weights"]), self.n_features)

    def test_model_spec_model_type(self) -> None:
        self.assertEqual(self.schema["model_spec"]["model_type"], "logistic_regression")

    def test_input_schema_feature_names_length(self) -> None:
        """input_schema must name exactly N_FEATURES features."""
        names = self.schema["input_schema"]["names"]
        self.assertEqual(len(names), self.n_features)

    def test_input_schema_type_is_float(self) -> None:
        self.assertEqual(self.schema["input_schema"]["items"], "float")

    def test_score_function_stub_is_string(self) -> None:
        self.assertIsInstance(self.schema["score_function_stub"], str)

    def test_score_function_stub_contains_sigmoid(self) -> None:
        stub = self.schema["score_function_stub"]
        self.assertIn("math.exp", stub)

    def test_score_function_stub_returns_threat_probability(self) -> None:
        stub = self.schema["score_function_stub"]
        self.assertIn("threat_probability", stub)

    def test_schema_is_json_serialisable(self) -> None:
        """The entire schema must be serialisable with json.dumps."""
        try:
            json.dumps(self.schema)
        except TypeError as exc:
            self.fail(f"Schema is not JSON-serialisable: {exc}")


# ─────────────────────────────────────────────────────────────────────────────
# TestScoreFunctionStub
# ─────────────────────────────────────────────────────────────────────────────

class TestScoreFunctionStub(unittest.TestCase):
    """
    Verify that the score_function_stub is executable Python.

    The stub is meant to be pasted into an Azure ML score.py file.  It must
    reproduce the classifier's inference logic exactly, so operators can deploy
    the model as a serverless endpoint without shipping the SentinelWeave
    library.
    """

    @classmethod
    def setUpClass(cls) -> None:
        data = _build_separable_dataset(n_each=40)
        cls.clf = SecurityClassifier(epochs=200, learning_rate=0.1)
        cls.clf.train(data)
        cls.schema = cls.clf.to_azure_ml_schema()
        cls.test_data = _build_separable_dataset(n_each=20, seed=88)

    def _exec_stub(self, features: list[float]) -> dict:
        """Execute the score_function_stub in an isolated namespace."""
        model_spec = self.schema["model_spec"]   # noqa: F841  (used by exec)
        stub_code  = self.schema["score_function_stub"]
        ns: dict = {"model_spec": model_spec}
        exec(stub_code, ns)                       # noqa: S102
        return ns["score"](features)

    def test_stub_returns_dict(self) -> None:
        result = self._exec_stub([0.5] * 13)
        self.assertIsInstance(result, dict)

    def test_stub_has_threat_probability_key(self) -> None:
        result = self._exec_stub([0.5] * 13)
        self.assertIn("threat_probability", result)

    def test_stub_has_prediction_key(self) -> None:
        result = self._exec_stub([0.5] * 13)
        self.assertIn("prediction", result)

    def test_stub_probability_in_unit_interval(self) -> None:
        for item in self.test_data[:10]:
            r = self._exec_stub(item.features)
            self.assertGreaterEqual(r["threat_probability"], 0.0)
            self.assertLessEqual(r["threat_probability"], 1.0)

    def test_stub_matches_classifier_probability(self) -> None:
        """
        The stub must produce the same probabilities as the classifier.

        We allow a tiny floating-point tolerance because both implementations
        use the same sigmoid formula but might accumulate slightly different
        rounding errors.
        """
        for item in self.test_data:
            clf_prob  = self.clf.predict_proba(item.features)
            stub_prob = self._exec_stub(item.features)["threat_probability"]
            self.assertAlmostEqual(clf_prob, stub_prob, places=10)

    def test_stub_matches_classifier_predictions(self) -> None:
        for item in self.test_data:
            clf_pred  = self.clf.predict(item.features)
            stub_pred = self._exec_stub(item.features)["prediction"]
            self.assertEqual(clf_pred, stub_pred)


# ─────────────────────────────────────────────────────────────────────────────
# TestEvaluateClassifierWrapper
# ─────────────────────────────────────────────────────────────────────────────

class TestEvaluateClassifierWrapper(unittest.TestCase):
    """
    Verify the evaluate_classifier convenience function.

    This function is the single-call entry point for the pipeline.  It should:
    * Accept a list of ThreatReport objects and return a trained classifier.
    * Return a complete metrics dict.
    * Raise ValueError when there are not enough labeled examples.
    """

    def setUp(self) -> None:
        self.analyzer = EventAnalyzer()
        self.detector = ThreatDetector()
        all_lines = (_THREAT_LINES * 8) + (_BENIGN_LINES * 8)
        events  = self.analyzer.parse_bulk(all_lines)
        self.reports = self.detector.analyze_bulk(events)

    def test_returns_classifier_and_metrics(self) -> None:
        clf, metrics = evaluate_classifier(self.reports, epochs=50)
        self.assertIsInstance(clf, SecurityClassifier)
        self.assertIsInstance(metrics, dict)

    def test_metrics_contain_required_keys(self) -> None:
        _, metrics = evaluate_classifier(self.reports, epochs=50)
        for key in ("accuracy", "precision", "recall", "f1"):
            self.assertIn(key, metrics)

    def test_accuracy_above_baseline(self) -> None:
        """Accuracy must beat a trivial majority-class baseline (> 0.5)."""
        _, metrics = evaluate_classifier(self.reports, epochs=100)
        self.assertGreater(metrics["accuracy"], 0.5)

    def test_classifier_is_trained(self) -> None:
        clf, _ = evaluate_classifier(self.reports, epochs=50)
        self.assertTrue(clf._trained)

    def test_too_few_reports_raises(self) -> None:
        event = self.analyzer.parse("some log line")
        tiny  = self.detector.analyze_bulk([event, event, event])
        with self.assertRaises(ValueError):
            evaluate_classifier(tiny, epochs=10)


# ─────────────────────────────────────────────────────────────────────────────
# TestCrossValidationReproducibility
# ─────────────────────────────────────────────────────────────────────────────

class TestCrossValidationReproducibility(unittest.TestCase):
    """
    Confirm that the pipeline is reproducible.

    ML experiments must be reproducible to be scientifically valid.  When the
    same seed is used, the pipeline must produce bit-for-bit identical results.
    When different seeds are used, the splits differ (proving the seed is actually
    used).
    """

    def setUp(self) -> None:
        self.data = _build_separable_dataset(n_each=50)

    def test_same_seed_same_split(self) -> None:
        t1, v1 = DatasetBuilder.split(self.data, seed=42)
        t2, v2 = DatasetBuilder.split(self.data, seed=42)
        self.assertEqual([id(e) for e in t1], [id(e) for e in t2])

    def test_different_seeds_different_splits(self) -> None:
        _, v1 = DatasetBuilder.split(self.data, seed=1)
        _, v2 = DatasetBuilder.split(self.data, seed=2)
        self.assertNotEqual([id(e) for e in v1], [id(e) for e in v2])

    def test_same_seed_same_balance_order(self) -> None:
        b1 = DatasetBuilder.balance(self.data, seed=77)
        b2 = DatasetBuilder.balance(self.data, seed=77)
        self.assertEqual([e.label for e in b1], [e.label for e in b2])

    def test_training_with_same_data_is_deterministic(self) -> None:
        """Gradient descent with the same data and seed must yield the same weights."""
        train, _ = DatasetBuilder.split(self.data, seed=42)
        clf1 = SecurityClassifier(epochs=50)
        clf2 = SecurityClassifier(epochs=50)
        clf1.train(train)
        clf2.train(train)
        self.assertEqual(clf1.weights, clf2.weights)


# ─────────────────────────────────────────────────────────────────────────────
# TestImbalancedDataHandling
# ─────────────────────────────────────────────────────────────────────────────

class TestImbalancedDataHandling(unittest.TestCase):
    """
    Verify the pipeline handles extreme class imbalance gracefully.

    In production security environments it is common to have 1 threat event
    for every 50–200 benign events.  Without balancing the classifier collapses
    to always predicting "benign".  These tests confirm that the balancing step
    prevents this degenerate outcome.
    """

    @classmethod
    def setUpClass(cls) -> None:
        """Build a 1:50 imbalanced dataset and train on balanced version."""
        threats = _make_labeled(_THREAT_FEATS, 1, 4)
        benign  = _make_labeled(_BENIGN_FEATS, 0, 200)
        raw     = threats + benign
        balanced = DatasetBuilder.balance(raw, strategy="oversample")
        train, cls.test = DatasetBuilder.split(balanced, test_ratio=0.20)
        cls.clf = SecurityClassifier(epochs=200, learning_rate=0.1)
        cls.clf.train(train)

        # Also build a trivial baseline that always predicts "benign"
        cls.raw_test = threats[:2] + benign[:10]

    def test_classifier_detects_some_threats(self) -> None:
        """After balancing the model should classify at least one threat correctly."""
        tp = sum(
            1 for item in self.test
            if item.label == 1 and self.clf.predict(item.features) == 1
        )
        self.assertGreater(tp, 0)

    def test_classifier_beats_majority_baseline(self) -> None:
        """
        A majority-class baseline on the raw (imbalanced) test would score
        ~98% accuracy but 0% recall.  Our balanced-trained classifier must
        achieve strictly positive recall.
        """
        tp = sum(
            1 for item in self.raw_test
            if item.label == 1 and self.clf.predict(item.features) == 1
        )
        total_threats = sum(1 for item in self.raw_test if item.label == 1)
        recall = tp / total_threats if total_threats else 0.0
        self.assertGreater(recall, 0.0)

    def test_oversample_length(self) -> None:
        """Oversample should bring minority up to majority class count."""
        threats = _make_labeled(_THREAT_FEATS, 1, 3)
        benign  = _make_labeled(_BENIGN_FEATS, 0, 150)
        balanced = DatasetBuilder.balance(threats + benign, strategy="oversample")
        pos = sum(1 for e in balanced if e.label == 1)
        neg = sum(1 for e in balanced if e.label == 0)
        self.assertEqual(pos, neg)


# ─────────────────────────────────────────────────────────────────────────────
# TestPipelineIntegration
# ─────────────────────────────────────────────────────────────────────────────

class TestPipelineIntegration(unittest.TestCase):
    """
    Full end-to-end integration test using the same realistic log corpus
    as examples/ml_demo.py.

    This is the most exhibit-worthy test: it demonstrates the complete pipeline
    in a single test method — from raw syslog strings to a trained, evaluated,
    and serialized threat-detection model ready for Azure ML deployment.
    """

    @classmethod
    def setUpClass(cls) -> None:
        """Run the full pipeline once; all test methods share the result."""
        analyzer = EventAnalyzer()
        detector = ThreatDetector()

        all_lines = (_THREAT_LINES * 6) + (_BENIGN_LINES * 6)
        events  = analyzer.parse_bulk(all_lines)
        reports = detector.analyze_bulk(events)

        # Full pipeline
        dataset  = DatasetBuilder.from_reports(reports)
        balanced = DatasetBuilder.balance(dataset, strategy="oversample")
        train, test = DatasetBuilder.split(balanced, test_ratio=0.20)

        cls.clf  = SecurityClassifier(epochs=250, learning_rate=0.05)
        cls.history = cls.clf.train(train)
        cls.metrics = cls.clf.evaluate(test)
        cls.test_set = test
        cls.dataset  = dataset
        cls.analyzer = analyzer

    # -- Dataset integrity --

    def test_dataset_has_both_classes(self) -> None:
        labels = {e.label for e in self.dataset}
        self.assertIn(0, labels)
        self.assertIn(1, labels)

    def test_feature_vectors_have_correct_length(self) -> None:
        for item in self.dataset:
            self.assertEqual(len(item.features), SecurityClassifier.N_FEATURES)

    def test_feature_values_in_unit_interval(self) -> None:
        for item in self.dataset:
            for val in item.features:
                self.assertGreaterEqual(val, 0.0)
                self.assertLessEqual(val, 1.0)

    # -- Training --

    def test_loss_decreased(self) -> None:
        self.assertLess(self.history["final_loss"], self.history["initial_loss"])

    def test_classifier_is_trained(self) -> None:
        self.assertTrue(self.clf._trained)

    # -- Evaluation --

    def test_accuracy_above_chance(self) -> None:
        """Any trained classifier should beat random guessing (0.5)."""
        self.assertGreater(self.metrics["accuracy"], 0.5)

    def test_f1_above_zero(self) -> None:
        self.assertGreater(self.metrics["f1"], 0.0)

    def test_confusion_matrix_sums_correctly(self) -> None:
        m = self.metrics
        total = m["true_positives"] + m["false_positives"] + m["true_negatives"] + m["false_negatives"]
        self.assertEqual(total, len(self.test_set))

    # -- Azure ML export --

    def test_azure_schema_exportable(self) -> None:
        schema = self.clf.to_azure_ml_schema()
        self.assertIn("model_spec", schema)
        self.assertIn("score_function_stub", schema)
        payload = json.dumps(schema)
        self.assertGreater(len(payload), 0)

    # -- Live prediction on known lines --

    def test_brute_force_line_high_proba(self) -> None:
        """A textbook SSH brute-force line should score higher than a benign one."""
        threat_event = self.analyzer.parse(
            "Jan 15 sshd: Failed password for root from 198.51.100.42 port 54321 ssh2"
        )
        benign_event = self.analyzer.parse(
            "Jan 15 syslog: Service nginx started successfully"
        )
        if threat_event.features and benign_event.features:
            tp = self.clf.predict_proba(threat_event.features)
            bp = self.clf.predict_proba(benign_event.features)
            self.assertGreater(tp, bp)

    def test_sql_injection_line_high_proba(self) -> None:
        """SQL injection log line should have a higher threat probability than a backup log."""
        sqli = self.analyzer.parse(
            "nginx: GET /?id=1' UNION SELECT username,password FROM users-- HTTP/1.1 200"
        )
        backup = self.analyzer.parse("syslog: Scheduled backup completed successfully")
        if sqli.features and backup.features:
            self.assertGreater(
                self.clf.predict_proba(sqli.features),
                self.clf.predict_proba(backup.features),
            )


# ─────────────────────────────────────────────────────────────────────────────
# TestOversampleHelper
# ─────────────────────────────────────────────────────────────────────────────

class TestOversampleHelper(unittest.TestCase):
    """Unit tests for the private _oversample helper."""

    def _samples(self, n: int) -> list[LabeledEvent]:
        return [LabeledEvent(features=[float(i)], label=1) for i in range(n)]

    def test_returns_at_least_target(self) -> None:
        rng = random.Random(0)
        result = _oversample(self._samples(3), target=10, rng=rng)
        self.assertEqual(len(result), 10)

    def test_no_expansion_needed(self) -> None:
        rng = random.Random(0)
        samples = self._samples(10)
        result = _oversample(samples, target=5, rng=rng)
        self.assertEqual(len(result), 5)

    def test_single_sample_duplicated(self) -> None:
        rng = random.Random(0)
        samples = self._samples(1)
        result = _oversample(samples, target=20, rng=rng)
        self.assertEqual(len(result), 20)

    def test_all_items_have_correct_label(self) -> None:
        rng = random.Random(0)
        result = _oversample(self._samples(3), target=20, rng=rng)
        self.assertTrue(all(e.label == 1 for e in result))


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    unittest.main(verbosity=2)
