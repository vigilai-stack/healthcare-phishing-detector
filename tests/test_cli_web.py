import json

from phishguard.cli import main
from phishguard.detector import Detector
from phishguard.webapp import create_app

PHISH = """From: Lumen Health Plan <alerts@lumenhealthplan.secure-login.example>
Reply-To: appeals@gmail.com
Subject: Account will be suspended
Content-Type: text/plain; charset=utf-8

Verify your identity immediately or the account will be suspended.
https://lumenhealthplan.secure-login.example/appeal
"""

LEGIT = """From: Lumen Health Plan <notices@lumenhealthplan.example>
Reply-To: notices@lumenhealthplan.example
Subject: Your EOB is ready
Content-Type: text/plain; charset=utf-8

Claim CLM-204918 now has an explanation of benefits. This is not a bill.
Read it here: https://member.lumenhealthplan.example/claims/CLM-204918
"""


def test_cli_json_and_threshold(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("PHISHGUARD_HOME", str(tmp_path))
    phish_path = tmp_path / "phish.eml"
    legit_path = tmp_path / "legit.eml"
    phish_path.write_text(PHISH, encoding="utf-8")
    legit_path.write_text(LEGIT, encoding="utf-8")
    assert main(["scan", "--eml", str(phish_path), "--json", "--fail-over", "60"]) == 1
    phish_report = json.loads(capsys.readouterr().out)
    assert phish_report["risk"] >= 60
    assert phish_report["findings"]
    assert main(["scan", "--eml", str(legit_path), "--json", "--fail-over", "60"]) == 0
    legit_report = json.loads(capsys.readouterr().out)
    assert legit_report["risk"] < phish_report["risk"]
    assert legit_report["risk"] < 60


def test_web_escapes_message_text():
    app = create_app(Detector(None))
    client = app.test_client()
    hostile = "<script>alert(1)</script>\nFrom: Clinic <a@northwindclinic.example>\n\nHello"
    response = client.post("/", data={"email_text": hostile})
    assert response.status_code == 200
    page = response.get_data(as_text=True)
    assert "<script>alert(1)</script>" not in page
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page


def test_web_rejects_empty_submit():
    app = create_app(Detector(None))
    client = app.test_client()
    response = client.post("/", data={"email_text": "   "})
    assert b"Paste a message" in response.data


def test_health():
    app = create_app(Detector(None))
    response = app.test_client().get("/health")
    assert response.get_json()["ok"] is True
    assert response.get_json()["model_loaded"] is False
