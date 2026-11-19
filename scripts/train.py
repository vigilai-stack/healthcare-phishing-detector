#!/usr/bin/env python3
"""Train both models and write models/phishguard.joblib plus reports/metrics.json."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from phishguard.train_eval import train_and_evaluate


if __name__ == "__main__":
    train_and_evaluate()
