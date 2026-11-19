from phishguard.features import extract_findings, lookalike_reason, rule_score
from phishguard.parse import Attachment, Link, ParsedEmail


def _mail(**kwargs) -> ParsedEmail:
    defaults = dict(subject="", from_header="", reply_to="", body_text="", links=[], attachments=[])
    defaults.update(kwargs)
    return ParsedEmail(**defaults)


def test_exact_brand_domain_is_not_a_lookalike():
    assert lookalike_reason("member.lumenhealthplan.example") is None
    assert lookalike_reason("login.halcyonehr.example") is None


def test_homoglyph_and_extra_words_are_lookalikes():
    homoglyph = lookalike_reason("member.1umenhealthplan.example")
    assert homoglyph is not None
    assert homoglyph.code == "homoglyph_domain"
    extra = lookalike_reason("halcyonehr-reset.example")
    assert extra is not None
    borrowed = lookalike_reason("lumenhealthplan.secure-login.example")
    assert borrowed is not None
    assert borrowed.severity == "high"


def test_reply_to_freemail_and_urgency_and_html_file():
    email = _mail(
        subject="Account will be suspended",
        from_header="Lumen Health Plan <alerts@lumenhealthplan.secure-login.example>",
        reply_to="appeals@gmail.com",
        body_text="Verify your identity immediately or the account will be suspended.",
        links=[Link(href="https://lumenhealthplan.secure-login.example/appeal", text="")],
        attachments=[Attachment(filename="EOB.html", content_type="text/html")],
    )
    findings = extract_findings(email)
    codes = {item.code for item in findings}
    assert "reply_to_mismatch" in codes
    assert "urgency" in codes
    assert "html_attachment" in codes
    assert "credential_request" in codes
    assert rule_score(findings) >= 0.5


def test_matching_clinic_mail_stays_quiet():
    email = _mail(
        subject="Your EOB for claim CLM-204918 is ready",
        from_header="Lumen Health Plan <notices@lumenhealthplan.example>",
        reply_to="notices@lumenhealthplan.example",
        body_text=(
            "Claim CLM-204918 now has an explanation of benefits. This is not a bill. "
            "Read it here: https://member.lumenhealthplan.example/claims/CLM-204918"
        ),
        links=[Link(href="https://member.lumenhealthplan.example/claims/CLM-204918", text="")],
        attachments=[Attachment(filename="EOB.pdf", content_type="application/pdf")],
    )
    findings = extract_findings(email)
    assert findings == [] or all(item.severity != "high" and item.weight < 0.2 for item in findings)
    assert rule_score(findings) < 0.2


def test_href_text_does_not_match_destination():
    email = _mail(
        from_header="Records <records@riverbendmg.example>",
        reply_to="records@riverbendmg.example",
        links=[
            Link(
                href="https://riverbendmg.secure-docs.example/r/1",
                text="https://referrals.riverbendmg.example/r/1",
            )
        ],
    )
    codes = {item.code for item in extract_findings(email)}
    assert "href_mismatch" in codes


def test_double_extension():
    email = _mail(
        attachments=[Attachment(filename="Visit_summary.pdf.exe", content_type="application/octet-stream")]
    )
    codes = {item.code for item in extract_findings(email)}
    assert "double_extension" in codes
