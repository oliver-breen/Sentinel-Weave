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
   Azure ML scoring format.  New capabilities beyond baseline training:

   * **Early stopping** (``patience`` parameter) — halts training when the
     loss stops improving, preventing wasted compute and overfitting.
   * **Online / incremental learning** (:meth:`partial_fit`) — updates the
     model from new labeled events without resetting weights; ideal for
     streaming log-ingestion pipelines.
   * **ROC-AUC** — :meth:`evaluate` now returns ``roc_auc``, the area under
     the receiver-operating-characteristic curve — the gold-standard metric
     for imbalanced binary classifiers.
   * **Explainability** (:meth:`explain`) — breaks any prediction into
     per-feature contributions (weight × feature value), surfacing the top
     threat-driving and benign-driving factors in plain English.

3. :func:`evaluate_classifier` — convenience wrapper that trains, evaluates,
   and prints a metrics table.
4. :func:`k_fold_cross_validate` — stratified k-fold cross-validation
   returning mean ± std of every metric across folds.

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
        Maximum training passes over the full dataset.  Default 200.
    regularization:
        L2 regularization coefficient (prevents overfitting).  Default 0.01.
    batch_size:
        Mini-batch size.  ``None`` uses the full dataset per step.
        Default 32.
    patience:
        Early-stopping patience.  Training halts when the per-epoch loss has
        not improved by more than ``1e-6`` for *patience* consecutive epochs.
        ``0`` (default) disables early stopping so training always runs for
        exactly *epochs* passes.

    Example
    -------
    ::

        clf     = SecurityClassifier(patience=10)
        history = clf.train(train_set)
        print(f"Ran {history['epochs_trained']} / {history['epochs']} epochs")
        print(f"Final loss: {history['final_loss']:.4f}")

        proba = clf.predict_proba(event.features)   # 0.0–1.0
        label = clf.predict(event.features)          # 0 or 1
        metrics = clf.evaluate(test_set)
        print(f"ROC-AUC: {metrics['roc_auc']:.4f}")

        breakdown = clf.explain(event.features)
        print(f"Top threat factor: {breakdown['top_threat_factor']}")
    """

    N_FEATURES: int = 13

    #: Human-readable names for the 13 feature dimensions (same order as
    #: :meth:`~sentinel_weave.event_analyzer.EventAnalyzer._build_features`).
    FEATURE_NAMES: list[str] = [
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

    def __init__(
        self,
        learning_rate: float = 0.05,
        epochs: int = 200,
        regularization: float = 0.01,
        batch_size: Optional[int] = 32,
        patience: int = 0,
    ) -> None:
        self.learning_rate  = learning_rate
        self.epochs         = epochs
        self.regularization = regularization
        self.batch_size     = batch_size
        self.patience       = patience
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

        When *patience* is greater than zero the training loop applies early
        stopping: if the per-epoch loss does not improve by more than ``1e-6``
        for *patience* consecutive epochs, training halts before reaching
        *epochs* passes.

        Args:
            dataset: Labeled training examples.

        Returns:
            Training history dict:
            ``{"epochs", "epochs_trained", "initial_loss", "final_loss",
            "loss_history"}``.
            ``epochs_trained`` reflects the actual number of passes completed
            (may be less than ``epochs`` when early stopping fires).

        Raises:
            ValueError: If *dataset* is empty.
        """
        if not dataset:
            raise ValueError("Cannot train on an empty dataset.")

        rng          = random.Random(42)
        loss_history: list[float] = []
        best_loss    = math.inf
        no_improve   = 0

        for _ in range(self.epochs):
            epoch_loss = self._run_epoch(dataset, rng)
            loss_history.append(round(epoch_loss, 6))

            if self.patience > 0:
                if epoch_loss < best_loss - 1e-6:
                    best_loss  = epoch_loss
                    no_improve = 0
                else:
                    no_improve += 1
                    if no_improve >= self.patience:
                        break

        self._trained = True
        return {
            "epochs":        self.epochs,
            "epochs_trained": len(loss_history),
            "initial_loss":  loss_history[0]  if loss_history else 0.0,
            "final_loss":    loss_history[-1] if loss_history else 0.0,
            "loss_history":  loss_history,
        }

    def partial_fit(
        self,
        dataset: list[LabeledEvent],
        epochs: int = 1,
        seed: int = 0,
    ) -> dict:
        """
        Update the model incrementally from new labeled examples.

        Unlike :meth:`train`, ``partial_fit`` does **not** reset the weights —
        it continues gradient descent from the current state.  This makes it
        ideal for streaming security-log pipelines where newly labeled events
        arrive continuously and a full re-train would be too expensive.

        Calling ``partial_fit`` on an untrained model is valid; it simply
        performs a few gradient steps from the randomly initialised weights.

        Args:
            dataset: New labeled examples to incorporate.
            epochs:  Number of gradient-descent passes over *dataset*.
                     Default 1 (one online update step).
            seed:    Random seed used for mini-batch shuffling.

        Returns:
            Dict ``{"loss": <final_epoch_loss>}`` — the cross-entropy loss
            after the last pass.

        Raises:
            ValueError: If *dataset* is empty.
        """
        if not dataset:
            raise ValueError("Cannot partial_fit on an empty dataset.")

        rng    = random.Random(seed)
        losses = [self._run_epoch(dataset, rng) for _ in range(epochs)]
        self._trained = True
        return {"loss": round(losses[-1], 6) if losses else 0.0}

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
            ``f1``, ``roc_auc``, ``true_positives``, ``false_positives``,
            ``true_negatives``, ``false_negatives``.

            ``roc_auc`` is the area under the receiver-operating-characteristic
            curve, computed via the trapezoidal rule.  It equals 1.0 for a
            perfect classifier and 0.5 for a random one — a more reliable
            summary metric than accuracy when classes are imbalanced.
        """
        tp = fp = tn = fn = 0
        proba_label: list[tuple[float, int]] = []
        for item in dataset:
            prob = self.predict_proba(item.features)
            proba_label.append((prob, item.label))
            pred = 1 if prob >= 0.5 else 0
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
            "roc_auc":         round(_roc_auc(proba_label), 4),
            "true_positives":  tp,
            "false_positives": fp,
            "true_negatives":  tn,
            "false_negatives": fn,
        }

    def explain(self, features: list[float]) -> dict:
        """
        Break down a prediction into per-feature contributions.

        For logistic regression the decision boundary is a linear function of
        the input features.  The contribution of feature *i* is simply
        ``weight[i] × feature[i]``: positive values push the model towards
        predicting *threat*; negative values push it towards *benign*.  This
        makes the classifier fully auditable — a security analyst can see
        exactly which signals triggered an alert.

        Args:
            features: 13-element feature vector (as returned by
                      :meth:`~sentinel_weave.event_analyzer.EventAnalyzer.parse`).

        Returns:
            Dict with keys:

            ``"contributions"``
                ``{feature_name: contribution_float}`` — contribution of each
                feature to the raw linear score.
            ``"bias"``
                The model's bias term (intercept).
            ``"raw_score"``
                Linear combination ``w · x + bias`` (before sigmoid).
            ``"probability"``
                Threat probability — sigmoid of ``raw_score``.
            ``"top_threat_factor"``
                Name of the feature contributing most towards *threat*
                (highest positive contribution), or ``None`` if no feature
                has a positive contribution.
            ``"top_benign_factor"``
                Name of the feature contributing most towards *benign*
                (lowest / most negative contribution), or ``None`` if no
                feature has a negative contribution.
        """
        contributions = {
            name: round(self.weights[i] * features[i], 6)
            for i, name in enumerate(self.FEATURE_NAMES)
        }

        bias      = self.weights[-1]
        raw_score = sum(contributions.values()) + bias
        prob      = self._sigmoid(raw_score)

        sorted_contribs = sorted(contributions.items(), key=lambda kv: kv[1])
        top_benign = (sorted_contribs[0][0]  if sorted_contribs and sorted_contribs[0][1]  < 0
                      else None)
        top_threat = (sorted_contribs[-1][0] if sorted_contribs and sorted_contribs[-1][1] > 0
                      else None)

        return {
            "contributions":    contributions,
            "bias":             round(bias,      6),
            "raw_score":        round(raw_score, 6),
            "probability":      round(prob,      6),
            "top_threat_factor": top_threat,
            "top_benign_factor": top_benign,
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

    def _run_epoch(self, dataset: list[LabeledEvent], rng: random.Random) -> float:
        """Run one epoch of mini-batch gradient descent.  Returns mean epoch loss."""
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

        return epoch_loss / len(batches)

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


def k_fold_cross_validate(
    dataset: list[LabeledEvent],
    k: int = 5,
    epochs: int = 200,
    seed: int = 42,
) -> dict:
    """
    Run stratified k-fold cross-validation and return mean ± std of all metrics.

    The dataset is split into *k* equally-sized stratified folds (positives
    and negatives are distributed evenly across folds).  For each fold, a
    fresh :class:`SecurityClassifier` is trained on the other *k−1* folds and
    evaluated on the held-out fold.  The final result aggregates the per-fold
    metrics into means and standard deviations.

    Why cross-validation?
    ---------------------
    A single train/test split gives a noisy performance estimate that depends
    heavily on which examples land in the test set.  K-fold CV is the standard
    way to obtain a statistically robust estimate of how well a model is
    expected to generalise to new data.

    Args:
        dataset: Labeled dataset — should already be balanced if desired.
        k:       Number of folds (default 5).  Must be ≥ 2.
        epochs:  Training epochs per fold (default 200).
        seed:    Random seed for reproducibility.

    Returns:
        Dict with:

        ``"k"``
            Number of folds used.
        ``"mean_{metric}"`` / ``"std_{metric}"``
            Per-metric mean and standard deviation across all folds, for
            ``accuracy``, ``precision``, ``recall``, ``f1``, ``roc_auc``.
        ``"folds"``
            List of per-fold metric dicts (one entry per fold).

    Raises:
        ValueError: If *k* < 2 or *dataset* has fewer than *k* examples.
    """
    if k < 2:
        raise ValueError(f"k must be at least 2, got {k}.")
    if len(dataset) < k:
        raise ValueError(
            f"Dataset has {len(dataset)} examples but k={k}; need at least k examples."
        )

    rng      = random.Random(seed)
    shuffled = list(dataset)
    rng.shuffle(shuffled)

    # Stratified fold construction — distribute positives and negatives evenly
    positives = [e for e in shuffled if e.label == 1]
    negatives = [e for e in shuffled if e.label == 0]

    def _make_folds(items: list[LabeledEvent]) -> list[list[LabeledEvent]]:
        size = max(1, len(items) // k)
        folds_ = [items[i * size : (i + 1) * size] for i in range(k - 1)]
        folds_.append(items[(k - 1) * size :])  # last fold gets any remainder
        return folds_

    pos_folds = _make_folds(positives)
    neg_folds = _make_folds(negatives)
    folds = [pos_folds[i] + neg_folds[i] for i in range(k)]

    metric_keys = ("accuracy", "precision", "recall", "f1", "roc_auc")
    all_metrics: dict[str, list[float]] = {key: [] for key in metric_keys}
    fold_results: list[dict] = []

    for i in range(k):
        test_fold  = folds[i]
        train_fold = [e for j, fold in enumerate(folds) for e in fold if j != i]
        if not train_fold or not test_fold:
            continue
        clf = SecurityClassifier(epochs=epochs)
        clf.train(train_fold)
        m = clf.evaluate(test_fold)
        for key in metric_keys:
            all_metrics[key].append(m.get(key, 0.0))
        fold_results.append({key: round(m.get(key, 0.0), 4) for key in metric_keys})

    result: dict = {"k": k}
    for key in metric_keys:
        values = all_metrics[key]
        if len(values) > 1:
            mean_v = sum(values) / len(values)
            # Sample standard deviation (Bessel's correction, N-1 denominator)
            std_v  = math.sqrt(sum((v - mean_v) ** 2 for v in values) / (len(values) - 1))
        elif len(values) == 1:
            mean_v = values[0]
            std_v  = 0.0
        else:
            mean_v = std_v = 0.0
        result[f"mean_{key}"] = round(mean_v, 4)
        result[f"std_{key}"]  = round(std_v,  4)
    result["folds"] = fold_results
    return result


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _roc_auc(proba_label: list[tuple[float, int]]) -> float:
    """
    Compute ROC AUC via the trapezoidal rule over a full threshold sweep.

    Operates in O(n log n) time.  Returns 0.0 for an empty list.  Returns 0.5
    when only one class is present in *proba_label* (degenerate edge case
    where AUC is mathematically undefined — 0.5 signals "no better than random"
    as a safe fallback; callers should ensure both classes are represented when
    a precise AUC is required).
    """
    if not proba_label:
        return 0.0
    n_pos = sum(1 for _, y in proba_label if y == 1)
    n_neg = sum(1 for _, y in proba_label if y == 0)
    if n_pos == 0 or n_neg == 0:
        return 0.5

    # Sort by descending predicted probability (sweep threshold from high → low)
    sorted_pairs = sorted(proba_label, key=lambda pv: pv[0], reverse=True)

    tpr_pts: list[float] = [0.0]
    fpr_pts: list[float] = [0.0]
    tp = fp = 0
    for prob, label in sorted_pairs:
        if label == 1:
            tp += 1
        else:
            fp += 1
        tpr_pts.append(tp / n_pos)
        fpr_pts.append(fp / n_neg)
    tpr_pts.append(1.0)
    fpr_pts.append(1.0)

    # Trapezoidal integration
    auc = sum(
        (fpr_pts[i] - fpr_pts[i - 1]) * (tpr_pts[i] + tpr_pts[i - 1]) / 2.0
        for i in range(1, len(fpr_pts))
    )
    return auc

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
