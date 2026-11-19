#!/usr/bin/env python3
"""Merge the synthetic JSONL with a local sample of the public corpora."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from phishguard.dataset import build_dataset, write_jsonl
from phishguard.paths import processed_path, raw_dir
from phishguard.synthetic import write_examples, write_jsonl as write_synthetic
from phishguard.paths import examples_dir, synthetic_path


def main() -> None:
    count = write_synthetic(synthetic_path())
    print(f"synthetic messages: {count}")
    for path in write_examples(examples_dir()):
        print(f"example: {path}")
    public_jsonl = raw_dir() / "public.jsonl"
    rows = build_dataset(raw_dir(), public_jsonl)
    write_jsonl(processed_path(), rows)
    print(f"wrote {len(rows)} rows to {processed_path()}")


if __name__ == "__main__":
    main()
