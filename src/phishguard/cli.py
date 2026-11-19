"""Command line for scanning a message, serving the local page, and training."""

from __future__ import annotations

import argparse
import json
import sys

from phishguard import __version__
from phishguard.detector import Detector
from phishguard.explain import plain_summary
from phishguard.parse import parse_bytes, parse_text


def _scan(args, detector: Detector) -> int:
    if args.eml:
        raw = open(args.eml, "rb").read()
        email = parse_bytes(raw)
    elif args.text_file:
        email = parse_text(open(args.text_file, encoding="utf-8", errors="replace").read())
    elif args.text is not None:
        email = parse_text(args.text)
    else:
        email = parse_text(sys.stdin.read())
    report = detector.score_email(email)
    if args.json:
        payload = report.to_dict()
        payload["subject"] = email.subject
        payload["from"] = email.from_header
        payload["reply_to"] = email.reply_to
        print(json.dumps(payload, indent=2))
    else:
        print(plain_summary(report, email))
    if args.fail_over is not None and report.risk >= args.fail_over:
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="phishguard",
        description=(
            "Screen a healthcare-themed email for phishing signs. "
            "Runs locally. Does not open links."
        ),
    )
    parser.add_argument("--version", action="version", version=f"phishguard {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Score one pasted message or .eml file")
    scan.add_argument("--eml", help="Path to a .eml file")
    scan.add_argument("--text", help="Message text. Headers are parsed when present.")
    scan.add_argument("--text-file", help="UTF-8 file containing the message")
    scan.add_argument("--json", action="store_true", help="Print a JSON report")
    scan.add_argument(
        "--fail-over",
        type=int,
        default=None,
        help="Exit 1 when the risk score is at least this number",
    )

    serve = sub.add_parser("serve", help="Run the local web page")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8000)

    sub.add_parser("train", help="Train on data/processed/dataset.jsonl and write models/ and reports/")
    sub.add_parser("evaluate", help="Print the saved held-out metrics")

    args = parser.parse_args(argv)
    if args.command == "scan":
        return _scan(args, Detector.load())
    if args.command == "serve":
        from phishguard.webapp import create_app

        app = create_app()
        print(f"Phish Check is at http://{args.host}:{args.port}")
        app.run(host=args.host, port=args.port, debug=False)
        return 0
    if args.command == "train":
        from phishguard.train_eval import train_and_evaluate

        train_and_evaluate()
        return 0
    if args.command == "evaluate":
        from phishguard.train_eval import print_saved_metrics

        print_saved_metrics()
        return 0
    parser.error(f"Unknown command {args.command}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
