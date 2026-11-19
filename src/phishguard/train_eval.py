"""Train both models, pick one on validation data, and score the held-out test split once."""

from __future__ import annotations

import json
from pathlib import Path

import numpy as np

from phishguard.dataset import read_jsonl, split_rows, texts_and_labels
from phishguard.detector import Detector
from phishguard.metrics import best_f1_threshold, binary_report, rate
from phishguard.modeling import (
    fit_embedding,
    fit_tfidf,
    positive_proba_embedding,
    positive_proba_pipeline,
)
from phishguard.parse import parsed_from_record
from phishguard.paths import metrics_path, model_path, processed_path


def _subset_report(rows: list[dict], proba: np.ndarray, threshold: float, predicate) -> dict | None:
    indices = [i for i, row in enumerate(rows) if predicate(row)]
    if not indices:
        return None
    y_true = np.asarray([rows[i]["label"] for i in indices])
    y_prob = np.asarray(proba)[indices]
    if len(set(y_true.tolist())) < 2:
        return {
            "count": int(len(y_true)),
            "positives": int(y_true.sum()),
            "mean_probability": round(float(y_prob.mean()), 4),
        }
    predicted = (y_prob >= threshold).astype(int)
    report = binary_report(y_true, predicted, y_prob)
    report["threshold"] = threshold
    return report


def _fit_pair(train_rows: list[dict]):
    texts, labels, weights = texts_and_labels(train_rows)
    print(f"fitting TF-IDF logistic regression on {len(texts)} messages")
    tfidf = fit_tfidf(texts, labels, weights)
    print("fitting subword embedding model")
    embedding = fit_embedding(texts, labels, weights)
    return tfidf, embedding


def _probabilities(tfidf, embedding, rows: list[dict]) -> dict[str, np.ndarray]:
    texts, _labels, _weights = texts_and_labels(rows)
    return {
        "tfidf_logreg": np.asarray(positive_proba_pipeline(tfidf, texts), dtype=float),
        "subword_embedding": np.asarray(positive_proba_embedding(embedding, texts), dtype=float),
    }


def _slice_f1(report: dict | None) -> float | None:
    if not report or "f1" not in report:
        return None
    return float(report["f1"])


def _selection_score(synthetic_f1: float | None, public_f1: float | None) -> float:
    parts = [value for value in (synthetic_f1, public_f1) if value is not None]
    if not parts:
        return -1.0
    return float(sum(parts) / len(parts))


def _model_block(rows_val, rows_test, proba_val, proba_test) -> dict:
    y_val = [row["label"] for row in rows_val]
    tuned = best_f1_threshold(y_val, proba_val)
    threshold = float(tuned["threshold"])
    block = {
        "threshold_selected_on": "validation",
        "validation_threshold": threshold,
        "validation_f1_at_threshold": tuned["f1"],
        "validation": {
            "at_0.5": _subset_report(rows_val, proba_val, 0.5, lambda _row: True),
            "at_tuned_threshold": _subset_report(rows_val, proba_val, threshold, lambda _row: True),
            "synthetic": _subset_report(
                rows_val, proba_val, threshold, lambda row: row.get("source") == "synthetic"
            ),
            "public": _subset_report(
                rows_val, proba_val, threshold, lambda row: row.get("source") != "synthetic"
            ),
        },
        "test": {
            "at_0.5": _subset_report(rows_test, proba_test, 0.5, lambda _row: True),
            "at_tuned_threshold": _subset_report(
                rows_test, proba_test, threshold, lambda _row: True
            ),
            "synthetic": _subset_report(
                rows_test, proba_test, threshold, lambda row: row.get("source") == "synthetic"
            ),
            "public": _subset_report(
                rows_test, proba_test, threshold, lambda row: row.get("source") != "synthetic"
            ),
        },
    }
    ham_idx = [
        i
        for i, row in enumerate(rows_test)
        if row.get("source") == "spamassassin" and row["label"] == 0
    ]
    phish_idx = [i for i, row in enumerate(rows_test) if row.get("category") == "phishing"]
    syn_phish = [
        i
        for i, row in enumerate(rows_test)
        if row.get("category") == "healthcare_phish"
    ]
    syn_legit = [
        i
        for i, row in enumerate(rows_test)
        if row.get("category") == "healthcare_legit"
    ]
    pred = (proba_test >= threshold).astype(int)

    def _take(indices: list[int], positive: int) -> dict:
        if not indices:
            return {"count": 0}
        return rate(
            [rows_test[i]["label"] for i in indices],
            pred[indices],
            positive=positive,
        )

    block["test"]["spamassassin_ham_false_positive_rate"] = _take(ham_idx, 0)
    block["test"]["nazario_phishing_recall"] = _take(phish_idx, 1)
    block["test"]["synthetic_phish_recall"] = _take(syn_phish, 1)
    block["test"]["synthetic_legit_false_positive_rate"] = _take(syn_legit, 0)
    return block


def _transfer(train_rows: list[dict], test_rows: list[dict], name: str) -> dict:
    if not train_rows or not test_rows:
        return {"name": name, "skipped": True}
    texts, labels, weights = texts_and_labels(train_rows)
    # One weight per row. Transfer runs are single-source, so weights stay 1.
    weights = [1.0] * len(train_rows)
    print(f"transfer experiment: {name} ({len(train_rows)} train, {len(test_rows)} test)")
    model = fit_tfidf(texts, labels, weights)
    proba = positive_proba_pipeline(model, [row.get("text") or "" for row in test_rows])
    y_true = [row["label"] for row in test_rows]
    # Threshold 0.5. Tuning it on this test slice would leak the result we are reporting.
    predicted = (np.asarray(proba) >= 0.5).astype(int)
    report = binary_report(y_true, predicted, proba)
    report["threshold"] = 0.5
    report["model"] = "tfidf_logreg"
    report["name"] = name
    return report


def _risk_rows(bundle: dict, rows: list[dict], cutoff: int = 60) -> list[dict]:
    detector = Detector(bundle)
    scored = []
    for row in rows:
        report = detector.score_email(parsed_from_record(row))
        scored.append(
            {
                "label": int(row["label"]),
                "pred": 1 if report.risk >= cutoff else 0,
                "risk": report.risk,
                "category": row.get("category") or row.get("source") or "unknown",
            }
        )
    return scored


def _summarize_risk(scored: list[dict], cutoff: int) -> dict:
    if not scored:
        return {"count": 0, "cutoff": cutoff}
    y_true = [item["label"] for item in scored]
    y_pred = [item["pred"] for item in scored]
    risks = [item["risk"] for item in scored]
    # binary_report needs both classes. Category slices are sometimes one class.
    if len(set(y_true)) < 2:
        summary = {
            "count": len(scored),
            "positives": int(sum(y_true)),
            "flagged": int(sum(y_pred)),
        }
    else:
        summary = binary_report(y_true, y_pred)
    summary["rule"] = f"risk >= {cutoff} counts as unwanted"
    summary["cutoff"] = cutoff
    summary["mean_risk"] = round(float(np.mean(risks)), 2)
    summary["share_at_least_30"] = round(float(np.mean([risk >= 30 for risk in risks])), 4)
    summary["share_at_least_60"] = round(float(np.mean([risk >= 60 for risk in risks])), 4)
    summary["share_at_least_80"] = round(float(np.mean([risk >= 80 for risk in risks])), 4)
    return summary


def _risk_report(bundle: dict, rows: list[dict], cutoff: int = 60) -> dict:
    return _summarize_risk(_risk_rows(bundle, rows, cutoff), cutoff)


def train_and_evaluate(dataset: Path | None = None) -> dict:
    import joblib

    dataset = dataset or processed_path()
    if not dataset.exists():
        raise FileNotFoundError(
            f"No dataset at {dataset}. Run scripts/download_public.py and scripts/build_dataset.py."
        )
    rows = read_jsonl(dataset)
    train_rows = split_rows(rows, "train")
    val_rows = split_rows(rows, "val")
    test_rows = split_rows(rows, "test")
    if not train_rows or not val_rows or not test_rows:
        raise RuntimeError("Dataset is missing a train, validation, or test split.")

    tfidf, embedding = _fit_pair(train_rows)
    val_proba = _probabilities(tfidf, embedding, val_rows)
    test_proba = _probabilities(tfidf, embedding, test_rows)

    models = {}
    scores = {}
    for name in ("tfidf_logreg", "subword_embedding"):
        print(f"scoring {name}")
        models[name] = _model_block(val_rows, test_rows, val_proba[name], test_proba[name])
        synthetic_f1 = _slice_f1(models[name]["validation"]["synthetic"])
        public_f1 = _slice_f1(models[name]["validation"]["public"])
        scores[name] = _selection_score(synthetic_f1, public_f1)
        models[name]["validation_selection_score"] = round(scores[name], 4)

    # Ties go to the linear model. The test split is not part of this choice.
    if scores["subword_embedding"] > scores["tfidf_logreg"] + 1e-9:
        selected = "subword_embedding"
    else:
        selected = "tfidf_logreg"

    bundle = {
        "version": 1,
        "selected_model": selected,
        "selection_scores": scores,
        "thresholds": {
            name: models[name]["validation_threshold"] for name in models
        },
        "tfidf": tfidf,
        "embedding": embedding,
    }
    print("scoring held-out mail with the blended risk score")
    scored_test = _risk_rows(bundle, test_rows)
    by_category = {}
    for category in sorted({item["category"] for item in scored_test}):
        by_category[category] = _summarize_risk(
            [item for item in scored_test if item["category"] == category], 60
        )
    risk = {
        "all_test": _summarize_risk(scored_test, 60),
        "synthetic_test": _summarize_risk(
            [
                item
                for item, row in zip(scored_test, test_rows)
                if row.get("source") == "synthetic"
            ],
            60,
        ),
        "public_test": _summarize_risk(
            [
                item
                for item, row in zip(scored_test, test_rows)
                if row.get("source") != "synthetic"
            ],
            60,
        ),
        "by_category": by_category,
    }
    transfer = {
        "public_train_to_synthetic_test": _transfer(
            [row for row in train_rows if row.get("source") != "synthetic"],
            [row for row in test_rows if row.get("source") == "synthetic"],
            "public_train_to_synthetic_test",
        ),
        "synthetic_train_to_public_test": _transfer(
            [row for row in train_rows if row.get("source") == "synthetic"],
            [row for row in test_rows if row.get("source") != "synthetic"],
            "synthetic_train_to_public_test",
        ),
    }
    counts = {
        "train": len(train_rows),
        "validation": len(val_rows),
        "test": len(test_rows),
        "by_source": {},
    }
    for row in rows:
        key = row.get("source", "unknown")
        counts["by_source"][key] = counts["by_source"].get(key, 0) + 1

    report = {
        "task": (
            "Binary classification of unwanted mail (spam or phishing, label 1) "
            "versus legitimate mail (label 0). The healthcare rows are synthetic."
        ),
        "selected_model": selected,
        "selection_rule": (
            "Each model gets one threshold chosen to maximize F1 on the mixed validation "
            "split. The deployed language model is the one with the higher average of "
            "synthetic-validation F1 and public-validation F1 at that threshold. "
            "Ties go to TF-IDF logistic regression. The test split is not used to choose "
            "the model or the threshold."
        ),
        "counts": counts,
        "models": models,
        "risk_score_on_test": risk,
        "domain_transfer_tfidf_at_0.5": transfer,
        "limitations": [
            "Synthetic healthcare messages were written for this project. Held-out synthetic scores are not a real-world detection rate.",
            "SpamAssassin mail is mostly 2002-2005 newsletter and spam text. A spam label is not the same thing as a phishing label.",
            "The Nazario corpus is real historical phishing, labeled by the corpus author, and it is not a healthcare collection.",
            "Public message text is not shipped in this repository. Retraining downloads it.",
            "The risk score caps wording-only hits when the header and link checks are quiet. It is a screening aid, not a calibrated probability.",
        ],
    }
    model_file = model_path()
    model_file.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(bundle, model_file, compress=3)
    metrics_file = metrics_path()
    metrics_file.parent.mkdir(parents=True, exist_ok=True)
    metrics_file.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"selected model: {selected}")
    print(f"wrote {model_file}")
    print(f"wrote {metrics_file}")
    return report


def print_saved_metrics() -> None:
    path = metrics_path()
    if not path.exists():
        raise FileNotFoundError(f"No metrics at {path}. Train first.")
    report = json.loads(path.read_text(encoding="utf-8"))
    print(json.dumps(report, indent=2))
