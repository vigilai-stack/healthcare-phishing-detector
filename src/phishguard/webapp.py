"""Small local page for pasting a message or uploading a .eml file."""

from __future__ import annotations

from pathlib import Path

from flask import Flask, abort, render_template, request

from phishguard.detector import Detector
from phishguard.parse import parse_bytes, parse_text
from phishguard.paths import examples_dir

MAX_BYTES = 1_000_000
EXAMPLES = {
    "phishing_lure.eml": "Synthetic phishing example (held out of training)",
    "legitimate_notice.eml": "Synthetic legitimate example (held out of training)",
}


def create_app(detector: Detector | None = None) -> Flask:
    folder = Path(__file__).resolve().parent / "templates"
    app = Flask(__name__, template_folder=str(folder))
    app.config["MAX_CONTENT_LENGTH"] = MAX_BYTES
    app.config["detector"] = detector if detector is not None else Detector.load()

    @app.get("/health")
    def health():
        loaded = app.config["detector"]
        return {"ok": True, "model_loaded": bool(loaded.ready)}

    @app.route("/", methods=["GET", "POST"])
    def index():
        email_text = ""
        report = None
        email = None
        error = ""
        example_note = ""
        if request.method == "POST":
            try:
                raw, email_text, example_note = _read_submission()
                email = parse_bytes(raw) if raw is not None else parse_text(email_text)
                if raw is not None:
                    email_text = raw.decode("utf-8", errors="replace")
                report = app.config["detector"].score_email(email)
            except ValueError as exc:
                error = str(exc)
            except Exception:
                error = "That file could not be read as an email. Paste the text instead."
        return render_template(
            "index.html",
            email_text=email_text,
            report=report,
            email=email,
            error=error,
            example_note=example_note,
            model_loaded=app.config["detector"].ready,
        )

    def _read_submission() -> tuple[bytes | None, str, str]:
        example = request.form.get("example", "").strip()
        if example:
            if example not in EXAMPLES:
                raise ValueError("Unknown example.")
            path = examples_dir() / example
            if not path.is_file():
                raise ValueError("Example file is missing. Regenerate the synthetic set.")
            return path.read_bytes()[:MAX_BYTES], "", EXAMPLES[example]
        upload = request.files.get("eml")
        if upload and upload.filename:
            data = upload.read(MAX_BYTES + 1)
            if len(data) > MAX_BYTES:
                raise ValueError("File is larger than 1 MB. Paste the text instead.")
            if not data:
                raise ValueError("That file was empty.")
            return data, "", ""
        text = request.form.get("email_text", "")
        if not text.strip():
            raise ValueError("Paste a message or choose a .eml file.")
        if len(text.encode("utf-8", errors="replace")) > MAX_BYTES:
            raise ValueError("That paste is larger than 1 MB.")
        return None, text, ""

    @app.post("/api/scan")
    def api_scan():
        payload = request.get_json(silent=True) or {}
        text = payload.get("text", "")
        if not isinstance(text, str) or not text.strip():
            abort(400)
        if len(text.encode("utf-8", errors="replace")) > MAX_BYTES:
            abort(413)
        report = app.config["detector"].score_email(parse_text(text))
        return report.to_dict()

    return app
