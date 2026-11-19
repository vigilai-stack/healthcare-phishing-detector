"""Precision, recall, F1, and confusion matrices. No silent averaging tricks."""

from __future__ import annotations

import numpy as np
from sklearn.metrics import confusion_matrix, precision_recall_fscore_support


def binary_report(y_true, y_pred, y_prob=None) -> dict:
    y_true = np.asarray(y_true, dtype=int)
    y_pred = np.asarray(y_pred, dtype=int)
    precision, recall, f1, _support = precision_recall_fscore_support(
        y_true, y_pred, average="binary", pos_label=1, zero_division=0
    )
    matrix = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = (int(value) for value in matrix.ravel())
    report = {
        "precision": round(float(precision), 4),
        "recall": round(float(recall), 4),
        "f1": round(float(f1), 4),
        "support_legitimate": int((y_true == 0).sum()),
        "support_unwanted": int((y_true == 1).sum()),
        "confusion_matrix": {
            "labels": ["legitimate", "unwanted"],
            "matrix": [[tn, fp], [fn, tp]],
            "tn": tn,
            "fp": fp,
            "fn": fn,
            "tp": tp,
        },
    }
    if y_prob is not None and len(y_true):
        report["mean_probability"] = round(float(np.mean(y_prob)), 4)
    return report


def best_f1_threshold(y_true, y_prob, low: float = 0.2, high: float = 0.8, steps: int = 61) -> dict:
    y_true = np.asarray(y_true, dtype=int)
    y_prob = np.asarray(y_prob, dtype=float)
    if len(y_true) == 0 or len(set(y_true.tolist())) < 2:
        return {"threshold": 0.5, "f1": 0.0}
    grid = np.linspace(low, high, steps)
    best = {"threshold": 0.5, "f1": -1.0}
    for threshold in grid:
        pred = (y_prob >= threshold).astype(int)
        _p, _r, f1, _s = precision_recall_fscore_support(
            y_true, pred, average="binary", pos_label=1, zero_division=0
        )
        # Prefer the threshold closer to 0.5 when F1 ties, so we don't pick an extreme cut.
        better = f1 > best["f1"] + 1e-12
        tie = abs(f1 - best["f1"]) <= 1e-12 and abs(threshold - 0.5) < abs(best["threshold"] - 0.5)
        if better or tie:
            best = {"threshold": round(float(threshold), 4), "f1": round(float(f1), 4)}
    return best


def rate(y_true, y_pred, *, positive: int) -> dict:
    """Recall when positive=1, false-positive rate when positive=0 (share predicted 1)."""
    y_true = np.asarray(y_true, dtype=int)
    y_pred = np.asarray(y_pred, dtype=int)
    mask = y_true == positive
    total = int(mask.sum())
    if total == 0:
        return {"count": 0, "rate": None}
    if positive == 1:
        hit = int(((y_pred == 1) & mask).sum())
        return {"count": total, "recall": round(hit / total, 4)}
    false_alarms = int(((y_pred == 1) & mask).sum())
    return {"count": total, "false_positive_rate": round(false_alarms / total, 4)}
