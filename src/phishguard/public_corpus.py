"""Download and parse the public corpora used for training.

Message text from these corpora is kept under data/raw and data/processed,
which are gitignored. This module does not redistribute those messages.
"""

from __future__ import annotations

import hashlib
import json
import mailbox
import tarfile
from pathlib import Path

from phishguard.parse import parse_bytes, render_for_model

SPAMASSASSIN_BASE = "https://spamassassin.apache.org/old/publiccorpus/"
SPAMASSASSIN_FILES = (
    "20030228_easy_ham.tar.bz2",
    "20030228_easy_ham_2.tar.bz2",
    "20030228_hard_ham.tar.bz2",
    "20030228_spam.tar.bz2",
    "20030228_spam_2.tar.bz2",
    "20050311_spam_2.tar.bz2",
)
NAZARIO_FILES = (
    ("nazario-20051114.mbox", "https://monkey.org/~jose/phishing/20051114.mbox"),
    ("nazario-2017.mbox", "https://monkey.org/~jose/phishing/phishing-2017"),
    ("nazario-2019.mbox", "https://monkey.org/~jose/phishing/phishing-2019"),
)

# Caps keep training on a laptop CPU. Sampling is deterministic.
HAM_CAP = 2000
SPAM_CAP = 1600
PHISH_CAP = 1200
MIN_BODY = 40


ALLOWED_DOWNLOAD_HOSTS = {"spamassassin.apache.org", "monkey.org"}


def _fetch_corpus(url: str, dest: Path) -> None:
    """Download one corpus file. The URL is from this module, not from an email."""
    import urllib.parse
    import urllib.request

    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https" or parsed.hostname not in ALLOWED_DOWNLOAD_HOSTS:
        raise ValueError(f"Refusing to download {url}")
    request = urllib.request.Request(url, headers={"User-Agent": "phishguard-dataset/1.0"})
    # Scheme and host are allowlisted above. Bandit still flags urlopen itself.
    with urllib.request.urlopen(request, timeout=180) as response, dest.open("wb") as handle:  # nosec B310
        while True:
            chunk = response.read(1024 * 256)
            if not chunk:
                break
            handle.write(chunk)


def download_corpora(raw_dir: Path) -> None:
    raw_dir.mkdir(parents=True, exist_ok=True)
    jobs = [(raw_dir / name, SPAMASSASSIN_BASE + name) for name in SPAMASSASSIN_FILES]
    jobs.extend((raw_dir / name, url) for name, url in NAZARIO_FILES)
    for dest, url in jobs:
        if dest.exists() and dest.stat().st_size > 0:
            print(f"already have {dest.name}")
            continue
        print(f"downloading {url}")
        _fetch_corpus(url, dest)
        print(f"saved {dest.name} ({dest.stat().st_size} bytes)")


def _record_from_raw(raw: bytes, *, source: str, category: str, subset: str, license_name: str) -> dict | None:
    try:
        email = parse_bytes(raw)
    except Exception:
        return None
    body = (email.body_text or "").strip()
    if len(body) < MIN_BODY and len(email.subject) < 8:
        return None
    if len(body) > 8000:
        email.body_text = body[:8000]
        body = email.body_text
    digest = hashlib.sha256(raw).hexdigest()[:20]
    label = 0 if category == "ham" else 1
    return {
        "id": f"{source}-{digest}",
        "label": label,
        "source": source,
        "category": category,
        "subset": subset,
        "theme": "",
        "template_id": "",
        "subject": email.subject,
        "from": email.from_header,
        "reply_to": email.reply_to,
        "body": body,
        "attachments": [
            {"filename": item.filename, "content_type": item.content_type}
            for item in email.attachments
        ],
        "links": [{"href": item.href, "text": item.text} for item in email.links],
        "license": license_name,
        "synthetic": False,
        "text": render_for_model(email),
    }


def parse_spamassassin(raw_dir: Path) -> list[dict]:
    records = []
    for name in SPAMASSASSIN_FILES:
        path = raw_dir / name
        if not path.exists():
            raise FileNotFoundError(f"Missing {path}. Run the download step first.")
        subset = name.replace(".tar.bz2", "")
        category = "ham" if "ham" in name else "spam"
        with tarfile.open(path, "r:bz2") as archive:
            for member in archive.getmembers():
                if not member.isfile():
                    continue
                extracted = archive.extractfile(member)
                if extracted is None:
                    continue
                raw = extracted.read()
                record = _record_from_raw(
                    raw,
                    source="spamassassin",
                    category=category,
                    subset=subset,
                    license_name="spamassassin-public-corpus-copyright-remains-with-senders",
                )
                if record:
                    records.append(record)
        print(f"parsed {name}: running total {len(records)}")
    return records


def _message_bytes(message) -> bytes | None:
    try:
        return message.as_bytes()
    except Exception:
        return None


def parse_nazario(raw_dir: Path) -> list[dict]:
    records = []
    for name, _url in NAZARIO_FILES:
        path = raw_dir / name
        if not path.exists():
            raise FileNotFoundError(f"Missing {path}. Run the download step first.")
        box = mailbox.mbox(path)
        try:
            for message in box:
                raw = _message_bytes(message)
                if raw is None:
                    continue
                record = _record_from_raw(
                    raw,
                    source="nazario",
                    category="phishing",
                    subset=name,
                    license_name="CC-BY-4.0",
                )
                if record:
                    records.append(record)
        finally:
            box.close()
        print(f"parsed {name}: running total {len(records)}")
    return records


def _dedupe(records: list[dict]) -> list[dict]:
    seen: set[str] = set()
    kept = []
    for record in records:
        key = " ".join((record.get("body") or "").lower().split())[:2500]
        digest = hashlib.sha256(key.encode()).hexdigest()
        if digest in seen:
            continue
        seen.add(digest)
        kept.append(record)
    return kept


def _sample(records: list[dict], cap: int, seed: str) -> list[dict]:
    if len(records) <= cap:
        return records
    import random

    # Deterministic sample of the corpus. Not used for secrets or tokens.
    rng = random.Random(seed)  # nosec B311
    picked = rng.sample(records, cap)
    picked.sort(key=lambda record: record["id"])
    return picked


def load_public_records(raw_dir: Path) -> list[dict]:
    parsed = _dedupe(parse_spamassassin(raw_dir) + parse_nazario(raw_dir))
    ham = _sample([row for row in parsed if row["category"] == "ham"], HAM_CAP, "ham")
    spam = _sample([row for row in parsed if row["category"] == "spam"], SPAM_CAP, "spam")
    phishing = _sample(
        [row for row in parsed if row["category"] == "phishing"], PHISH_CAP, "phishing"
    )
    print(
        f"public sample ham={len(ham)} spam={len(spam)} phishing={len(phishing)} "
        f"from {len(parsed)} unique messages"
    )
    return ham + spam + phishing


def write_public_jsonl(raw_dir: Path, dest: Path) -> int:
    records = load_public_records(raw_dir)
    dest.parent.mkdir(parents=True, exist_ok=True)
    with dest.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, ensure_ascii=True) + "\n")
    return len(records)
