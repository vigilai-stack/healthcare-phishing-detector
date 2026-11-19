from phishguard.detector import Detector
from phishguard.parse import parse_bytes
from phishguard.paths import examples_dir, model_path
from phishguard.webapp import create_app


def test_shipped_examples_separate_and_the_page_shows_them():
    assert model_path().is_file()
    detector = Detector.load()
    phish = detector.score_bytes((examples_dir() / "phishing_lure.eml").read_bytes())
    legit = detector.score_bytes((examples_dir() / "legitimate_notice.eml").read_bytes())
    assert phish.risk >= 80
    assert legit.risk < 30
    assert phish.risk > legit.risk
    codes = {item.code for item in phish.findings}
    assert "href_mismatch" in codes or "homoglyph_domain" in codes

    app = create_app(detector)
    client = app.test_client()
    phish_page = client.post("/", data={"example": "phishing_lure.eml"})
    legit_page = client.post("/", data={"example": "legitimate_notice.eml"})
    assert phish_page.status_code == 200
    assert b'<h2 style="margin: 0;">High risk</h2>' in phish_page.data
    assert b'<h2 style="margin: 0;">Low</h2>' in legit_page.data
    # The pasted message is escaped. A tag in the body must not run.
    hostile = client.post(
        "/",
        data={"email_text": "<img src=x onerror=alert(1)>\nHello from the front desk"},
    )
    assert b"<img src=x" not in hostile.data
    assert b"&lt;img src=x onerror=alert(1)&gt;" in hostile.data


def test_shipped_eml_keeps_the_deceptive_href():
    parsed = parse_bytes((examples_dir() / "phishing_lure.eml").read_bytes())
    assert any("1umenhealthplan.example" in link.href for link in parsed.links)
