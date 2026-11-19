"""Assemble the synthetic set and the local public sample into one JSONL file."""

from __future__ import annotations

import json
from pathlib import Path

import numpy as np
from sklearn.model_selection import train_test_split

from phishguard.public_corpus import write_public_jsonl
from phishguard.synthetic import all_records


def read_jsonl(path: Path) -> list[dict]:
    rows = []
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=True) + "\n")


def assign_public_splits(rows: list[dict], seed: int = 42) -> list[dict]:
    """70% train, 10% validation, 20% test, stratified by source and label."""
    if not rows:
        return rows
    labels = [f"{row['source']}:{row['label']}" for row in rows]
    indices = np.arange(len(rows))
    # Some source/label pairs can be small. Fall back to label-only if a stratum has < 3 rows.
    unique, counts = np.unique(labels, return_counts=True)
    stratify = labels if counts.min() >= 3 else [row["label"] for row in rows]
    trainval, test = train_test_split(
        indices, test_size=0.20, random_state=seed, stratify=stratify
    )
    trainval_labels = [stratify[i] for i in trainval]
    unique, counts = np.unique(trainval_labels, return_counts=True)
    stratify_tv = trainval_labels if counts.min() >= 2 else [rows[i]["label"] for i in trainval]
    train, val = train_test_split(
        trainval, test_size=0.125, random_state=seed, stratify=stratify_tv
    )
    for index in train:
        rows[index]["split"] = "train"
    for index in val:
        rows[index]["split"] = "val"
    for index in test:
        rows[index]["split"] = "test"
    return rows


def build_dataset(raw_dir: Path, public_jsonl: Path, synthetic_rows: list[dict] | None = None) -> list[dict]:
    if not public_jsonl.exists():
        write_public_jsonl(raw_dir, public_jsonl)
    public_rows = assign_public_splits(read_jsonl(public_jsonl))
    synthetic = synthetic_rows if synthetic_rows is not None else all_records()
    return synthetic + public_rows


def split_rows(rows: list[dict], name: str) -> list[dict]:
    return [row for row in rows if row.get("split") == name]


def texts_and_labels(rows: list[dict]) -> tuple[list[str], list[int], list[float]]:
    texts = [row.get("text") or "" for row in rows]
    labels = [int(row["label"]) for row in rows]
    weights = [3.0 if row.get("source") == "synthetic" else 1.0 for row in rows]
    return texts, labels, weights
