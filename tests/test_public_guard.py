from pathlib import Path

import pytest

from phishguard.public_corpus import _fetch_corpus


def test_corpus_download_rejects_unexpected_urls(tmp_path: Path):
    with pytest.raises(ValueError):
        _fetch_corpus("https://example.com/mail.mbox", tmp_path / "x")
    with pytest.raises(ValueError):
        _fetch_corpus("http://spamassassin.apache.org/old/publiccorpus/readme.html", tmp_path / "x")
    with pytest.raises(ValueError):
        _fetch_corpus("file:///etc/passwd", tmp_path / "x")
