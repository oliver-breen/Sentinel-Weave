"""
ML Pipeline — SentinelWeave

Lightweight supervised learning pipeline for binary threat classification.

Trains a logistic regression classifier on the 13-element feature vectors
produced by :class:`~sentinel_weave.event_analyzer.EventAnalyzer`.  No
external ML libraries are required; the implementation uses only the Python
standard library.

Why logistic regression?
------------------------
* **Interpretable** — each weight directly reveals how much a given feature
  contributes to the threat score, making the model auditable (important in
  security contexts).
* **Fast** — converges in milliseconds on typical log volumes.
* **Portable** — the entire model is 14 floats (13 weights + 1 bias) stored
  as JSON, trivial to deploy to an Azure ML real-time inference endpoint.
* **Educational** — implementing gradient descent from scratch deepens
  understanding of the mathematics behind every ML framework.

Architecture
------------
1. :class:`DatasetBuilder` — auto-labels :class:`ThreatReport` objects,
   balances class imbalance via oversampling or undersampling, and splits
   into stratified train/test sets.
2. :class:`SecurityClassifier` — mini-batch gradient descent logistic
   regression with L2 regularization; serializes to / from JSON; exports in
   Azure ML scoring format.
3. :func:`evaluate_classifier` — convenience wrapper that trains, evaluates,
   and prints a metrics table.

Azure ML integration
--------------------
:meth:`SecurityClassifier.to_azure_ml_schema` returns a dict that can be
``json.dump()``-ed directly into an Azure ML ``MLmodel`` artifact or used as
the scoring payload returned by a ``score.py`` endpoint script.  The
``score_function_stub`` key contains ready-to-paste Python code for a
serverless inference function.
"""

from __future__ import annotations

import json
import math
import random
from dataclasses import dataclass
from typing import Optional

from .threat_detector import ThreatReport, ThreatLevel


# ---------------------------------------------------------------------------
# Labeled event
# ---------------------------------------------------------------------------

@dataclass
class LabeledEvent:
    """
    A feature vector paired with a ground-truth binary label.

    Attributes:
        features: 13-element float list from
                  :attr:`~sentinel_weave.event_analyzer.SecurityEvent.features`.
        label:    0 = benign, 1 = threat.
        weight:   Sample weight used during training (default 1.0).
    """

    features: list[float]
    label: int           # 0 = benign, 1 = threat
    weight: float = 1.0


# ---------------------------------------------------------------------------
# Dataset builder
# ---------------------------------------------------------------------------

class DatasetBuilder:
    """
    Converts :class:`ThreatReport` objects into labeled training datasets.

    All methods are static so the class acts as a namespace for dataset
    utilities; no instance state is needed.

    Example
    -------
    ::

        reports = detector.analyze_bulk(events)
        dataset = DatasetBuilder.from_reports(reports)
        balanced = DatasetBuilder.balance(dataset)
        train, test = DatasetBuilder.split(balanced)
    """

    @staticmethod
    def from_reports(
        reports: list[ThreatReport],
        threat_threshold: ThreatLevel = ThreatLevel.MEDIUM,
    ) -> list[LabeledEvent]:
        """
        Auto-label reports as threat (1) or benign (0).

        A report is labeled 1 if its
        :attr:`~sentinel_weave.threat_detector.ThreatReport.threat_level` is
        greater than or equal to *threat_threshold*.  Reports whose events
        carry no feature vector are skipped.

        Args:
            reports:          Threat reports from :class:`ThreatDetector`.
            threat_threshold: Minimum level to be considered a positive
                              (threat) example.  Default: ``MEDIUM``.

        Returns:
            List of :class:`LabeledEvent` objects.
        """
        order         = list(ThreatLevel)
        threshold_idx = order.index(threat_threshold)
        labeled: list[LabeledEvent] = []
        for r in reports:
            if not r.event.features:
                continue
            label = 1 if order.index(r.threat_level) >= threshold_idx else 0
            labeled.append(LabeledEvent(features=r.event.features, label=label))
        return labeled

    @staticmethod
    def balance(
        dataset: list[LabeledEvent],
        strategy: str = "oversample",
        seed: int = 42,
    ) -> list[LabeledEvent]:
        """
        Balance class distribution to address label imbalance.

        In real-world security logs, benign events vastly outnumber threats.
        Without balancing, a classifier can achieve high accuracy simply by
        predicting "benign" for everything.  This method compensates by
        duplicating minority-class samples (*oversample*) or trimming the
        majority class (*undersample*).

        Args:
            dataset:  Labeled dataset to balance.
            strategy: ``"oversample"`` (repeat minority samples) or
                      ``"undersample"`` (randomly drop majority samples).
            seed:     Random seed for reproducibility.

        Returns:
            A new, balanced dataset (original list is not modified).

        Raises:
            ValueError: If *strategy* is not ``"oversample"`` or
                        ``"undersample"``.
        """
        rng       = random.Random(seed)
        positives = [e for e in dataset if e.label == 1]
        negatives = [e for e in dataset if e.label == 0]

        if not positives or not negatives:
            return list(dataset)

        if strategy == "oversample":
            if len(positives) < len(negatives):
                positives = _oversample(positives, len(negatives), rng)
            else:
                negatives = _oversample(negatives, len(positives), rng)
        elif strategy == "undersample":
            target    = min(len(positives), len(negatives))
            positives = rng.sample(positives, target)
            negatives = rng.sample(negatives, target)
        else:
            raise ValueError(f"Unknown balancing strategy: {strategy!r}")

        combined = positives + negatives
        rng.shuffle(combined)
        return combined

    @staticmethod
    def split(
        dataset: list[LabeledEvent],
        test_ratio: float = 0.20,
        seed: int = 42,
    ) -> tuple[list[LabeledEvent], list[LabeledEvent]]:
        """
        Randomly split a dataset into train and test subsets.

        Args:
            dataset:    Full labeled dataset.
            test_ratio: Fraction reserved for testing (default 0.20).
            seed:       Random seed.

        Returns:
            Tuple of ``(train_set, test_set)``.
        """
        rng      = random.Random(seed)
        shuffled = list(dataset)
        rng.shuffle(shuffled)
        n_test   = max(1, int(len(shuffled) * test_ratio))
        return shuffled[n_test:], shuffled[:n_test]


# ---------------------------------------------------------------------------
# Logistic regression classifier
# ---------------------------------------------------------------------------

class SecurityClassifier:
    """
    Binary logistic regression classifier for security event threat detection.

    Trained on the 13-element feature vectors extracted by
    :class:`~sentinel_weave.event_analyzer.EventAnalyzer`.

    Parameters
    ----------
    learning_rate:
        Gradient descent step size.  Default 0.05.
    epochs:
        Training passes over the full dataset.  Default 200.
    regularization:
        L2 regularization coefficient (prevents overfitting).  Default 0.01.
    batch_size:
        Mini-batch size.  ``None`` uses the full dataset per step.
        Default 32.

    Example
    -------
    ::

        clf     = SecurityClassifier()
        history = clf.train(train_set)
        print(f"Final loss: {history['final_loss']:.4f}")

        proba = clf.predict_proba(event.features)   # 0.0–1.0
        label = clf.predict(event.features)          # 0 or 1
        print(clf.evaluate(test_set))
    """

    N_FEATURES: int = 13

    def __init__(
        self,
        learning_rate: float = 0.05,
        epochs: int = 200,
        regularization: float = 0.01,
        batch_size: Optional[int] = 32,
    ) -> None:
        self.learning_rate  = learning_rate
        self.epochs         = epochs
        self.regularization = regularization
        self.batch_size     = batch_size
        self._trained       = False

        # Weights: indices 0..N_FEATURES-1 are feature weights; last is bias
        rng = random.Random(0)
        self.weights: list[float] = [
            rng.gauss(0, 0.01) for _ in range(self.N_FEATURES + 1)
        ]

    # ------------------------------------------------------------------
    # Training
    # ------------------------------------------------------------------

    def train(self, dataset: list[LabeledEvent]) -> dict:
        """
        Train the classifier using mini-batch gradient descent.

        The loss function is binary cross-entropy with L2 regularization on
        the feature weights (the bias is not regularized, which is standard
        practice).

        Args:
            dataset: Labeled training examples.

        Returns:
            Training history dict:
            ``{"epochs", "initial_loss", "final_loss", "loss_history"}``.

        Raises:
            ValueError: If *dataset* is empty.
        """
        if not dataset:
            raise ValueError("Cannot train on an empty dataset.")

        rng          = random.Random(42)
        loss_history: list[float] = []

        for _ in range(self.epochs):
            samples = list(dataset)
            rng.shuffle(samples)

            batches = (
                [samples[i : i + self.batch_size]
                 for i in range(0, len(samples), self.batch_size)]
                if self.batch_size else [samples]
            )

            epoch_loss = 0.0
            for batch in batches:
                grads      = [0.0] * len(self.weights)
                batch_loss = 0.0
                n          = len(batch)

                for item in batch:
                    p   = self._sigmoid(self._dot(item.features))
                    err = (p - item.label) * item.weight
                    for j, fval in enumerate(item.features):
                        grads[j] += err * fval
                    grads[-1] += err  # bias gradient

                    # Binary cross-entropy contribution
                    p_clip = max(1e-12, min(1 - 1e-12, p))
                    batch_loss -= (
                        math.log(p_clip) if item.label == 1
                        else math.log(1 - p_clip)
                    )

                lr  = self.learning_rate
                lam = self.regularization
                # Update feature weights (with L2 regularization)
                for j in range(len(self.weights) - 1):
                    self.weights[j] -= lr * (grads[j] / n + lam * self.weights[j])
                # Update bias (no regularization)
                self.weights[-1] -= lr * (grads[-1] / n)

                epoch_loss += batch_loss / n

            loss_history.append(round(epoch_loss / len(batches), 6))

        self._trained = True
        return {
            "epochs":       self.epochs,
            "initial_loss": loss_history[0]  if loss_history else 0.0,
            "final_loss":   loss_history[-1] if loss_history else 0.0,
            "loss_history": loss_history,
        }

    # ------------------------------------------------------------------
    # Inference
    # ------------------------------------------------------------------

    def predict_proba(self, features: list[float]) -> float:
        """
        Estimate the probability that *features* represent a threat.

        Args:
            features: 13-element feature vector.

        Returns:
            Float in [0.0, 1.0] (higher means more likely a threat).
        """
        return self._sigmoid(self._dot(features))

    def predict(self, features: list[float], threshold: float = 0.5) -> int:
        """
        Classify *features* as benign (0) or threat (1).

        Args:
            features:  13-element feature vector.
            threshold: Decision boundary (default 0.5).

        Returns:
            0 (benign) or 1 (threat).
        """
        return 1 if self.predict_proba(features) >= threshold else 0

    # ------------------------------------------------------------------
    # Evaluation
    # ------------------------------------------------------------------

    def evaluate(self, dataset: list[LabeledEvent]) -> dict:
        """
        Compute binary classification metrics on *dataset*.

        Args:
            dataset: Labeled examples with ground-truth labels.

        Returns:
            Dict with keys ``accuracy``, ``precision``, ``recall``,
            ``f1``, ``true_positives``, ``false_positives``,
            ``true_negatives``, ``false_negatives``.
        """
        tp = fp = tn = fn = 0
        for item in dataset:
            pred = self.predict(item.features)
            if   pred == 1 and item.label == 1: tp += 1
            elif pred == 1 and item.label == 0: fp += 1
            elif pred == 0 and item.label == 0: tn += 1
            else:                               fn += 1

        total     = tp + fp + tn + fn
        accuracy  = (tp + tn) / total          if total           else 0.0
        precision = tp        / (tp + fp)      if (tp + fp)       else 0.0
        recall    = tp        / (tp + fn)      if (tp + fn)       else 0.0
        f1        = (2 * precision * recall / (precision + recall)
                     if (precision + recall) else 0.0)

        return {
            "accuracy":        round(accuracy,  4),
            "precision":       round(precision, 4),
            "recall":          round(recall,    4),
            "f1":              round(f1,        4),
            "true_positives":  tp,
            "false_positives": fp,
            "true_negatives":  tn,
            "false_negatives": fn,
        }

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def save(self, path: str) -> None:
        """
        Serialize the trained model to a JSON file.

        Args:
            path: Destination file path (e.g. ``"model.json"``).
        """
        payload = {
            "model_type":     "SecurityClassifier",
            "n_features":     self.N_FEATURES,
            "weights":        self.weights,
            "learning_rate":  self.learning_rate,
            "regularization": self.regularization,
            "epochs":         self.epochs,
            "trained":        self._trained,
        }
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)

    @classmethod
    def load(cls, path: str) -> "SecurityClassifier":
        """
        Load a serialized model from a JSON file.

        Args:
            path: Source file path produced by :meth:`save`.

        Returns:
            A restored :class:`SecurityClassifier` instance.

        Raises:
            FileNotFoundError: If *path* does not exist.
            ValueError:        If the file does not contain a valid model.
        """
        with open(path, encoding="utf-8") as fh:
            payload = json.load(fh)
        if payload.get("model_type") != "SecurityClassifier":
            raise ValueError(f"Not a SecurityClassifier model file: {path!r}")
        obj = cls(
            learning_rate  = payload.get("learning_rate",  0.05),
            regularization = payload.get("regularization", 0.01),
            epochs         = payload.get("epochs",         200),
        )
        obj.weights  = payload["weights"]
        obj._trained = payload.get("trained", False)
        return obj

    def to_azure_ml_schema(self) -> dict:
        """
        Export the model in Azure ML real-time inference endpoint format.

        The returned dict can be ``json.dump()``-ed to an ``MLmodel``
        artifact or returned verbatim from a ``score.py`` scoring script.

        Returns:
            Dict with keys ``model_spec``, ``input_schema``, and
            ``score_function_stub`` (ready-to-paste Python code).
        """
        feature_names = [
            "text_length_norm",
            "digit_ratio",
            "special_char_ratio",
            "uppercase_ratio",
            "has_source_ip",
            "has_timestamp",
            "event_type_encoded",
            "signature_count_norm",
            "keyword_severity",
            "has_path_chars",
            "text_entropy",
            "ip_count_norm",
            "threat_keyword_density",
        ]
        return {
            "model_spec": {
                "model_type":     "logistic_regression",
                "n_features":     self.N_FEATURES,
                "weights":        self.weights[:-1],
                "bias":           self.weights[-1],
                "learning_rate":  self.learning_rate,
                "regularization": self.regularization,
            },
            "input_schema": {
                "type":   "array",
                "items":  "float",
                "length": self.N_FEATURES,
                "names":  feature_names,
            },
            "score_function_stub": (
                "def score(data):\n"
                "    import math\n"
                "    weights = model_spec['weights']\n"
                "    bias    = model_spec['bias']\n"
                "    z    = sum(w * x for w, x in zip(weights, data)) + bias\n"
                "    prob = 1.0 / (1.0 + math.exp(-z))\n"
                "    return {'threat_probability': prob,\n"
                "            'prediction': int(prob >= 0.5)}\n"
            ),
        }

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _dot(self, features: list[float]) -> float:
        """Compute the weighted sum  w·x + bias."""
        total = self.weights[-1]          # bias
        for w, x in zip(self.weights, features):
            total += w * x
        return total

    @staticmethod
    def _sigmoid(z: float) -> float:
        """Numerically stable sigmoid (avoids overflow for large |z|)."""
        if z >= 0:
            return 1.0 / (1.0 + math.exp(-z))
        e = math.exp(z)
        return e / (1.0 + e)


# ---------------------------------------------------------------------------
# Convenience wrapper
# ---------------------------------------------------------------------------

def evaluate_classifier(
    reports: list[ThreatReport],
    threat_threshold: ThreatLevel = ThreatLevel.MEDIUM,
    epochs: int = 200,
    test_ratio: float = 0.25,
    seed: int = 42,
) -> tuple["SecurityClassifier", dict]:
    """
    Build a dataset from *reports*, train a :class:`SecurityClassifier`, and
    return the trained model together with its test-set evaluation metrics.

    This is the quickest path from raw reports to a trained classifier::

        clf, metrics = evaluate_classifier(reports)
        print(metrics)

    Args:
        reports:          Threat reports from :class:`ThreatDetector`.
        threat_threshold: Label threshold passed to :meth:`DatasetBuilder.from_reports`.
        epochs:           Training epochs for the classifier.
        test_ratio:       Fraction of data held out for evaluation.
        seed:             Random seed.

    Returns:
        Tuple of ``(trained_classifier, metrics_dict)``.

    Raises:
        ValueError: If fewer than 4 labeled examples are available.
    """
    dataset = DatasetBuilder.from_reports(reports, threat_threshold)
    if len(dataset) < 4:
        raise ValueError(
            f"Need at least 4 labeled events, got {len(dataset)}.  "
            "Pass more reports or lower the threat_threshold."
        )

    balanced        = DatasetBuilder.balance(dataset, seed=seed)
    train_set, test = DatasetBuilder.split(balanced, test_ratio=test_ratio, seed=seed)

    clf     = SecurityClassifier(epochs=epochs)
    clf.train(train_set)
    metrics = clf.evaluate(test)
    return clf, metrics


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _oversample(
    samples: list[LabeledEvent],
    target: int,
    rng: random.Random,
) -> list[LabeledEvent]:
    """Duplicate *samples* (with replacement) until *target* items are reached."""
    if len(samples) >= target:
        return samples[:target]
    extras = rng.choices(samples, k=target - len(samples))
    return list(samples) + extras
