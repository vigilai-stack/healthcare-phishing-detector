"""Locate repo data and model files without assuming the process cwd."""

from __future__ import annotations

import os
from pathlib import Path


def repo_root() -> Path:
    override = os.environ.get("PHISHGUARD_HOME")
    if override:
        return Path(override).expanduser().resolve()
    return Path(__file__).resolve().parents[2]


def data_dir() -> Path:
    return repo_root() / "data"


def synthetic_path() -> Path:
    return data_dir() / "synthetic" / "healthcare.jsonl"


def raw_dir() -> Path:
    return data_dir() / "raw"


def processed_path() -> Path:
    return data_dir() / "processed" / "dataset.jsonl"


def model_path() -> Path:
    return repo_root() / "models" / "phishguard.joblib"


def metrics_path() -> Path:
    return repo_root() / "reports" / "metrics.json"


def examples_dir() -> Path:
    return repo_root() / "examples"
