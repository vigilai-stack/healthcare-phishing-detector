#!/usr/bin/env python3
"""Download SpamAssassin and Nazario files into data/raw. Does not commit them."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from phishguard.paths import raw_dir
from phishguard.public_corpus import download_corpora


def main() -> None:
    download_corpora(raw_dir())


if __name__ == "__main__":
    main()
