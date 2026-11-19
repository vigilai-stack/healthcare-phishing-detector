from email.message import EmailMessage

from phishguard.parse import parse_bytes, parse_text, render_for_model


def _sample_eml() -> bytes:
    message = EmailMessage()
    message["Subject"] = "Explanation of benefits"
    message["From"] = "Lumen Health Plan <notices@lumenhealthplan.example>"
    message["Reply-To"] = "other.desk@gmail.com"
    message["To"] = "front.desk@northwindclinic.example"
    message.set_content("See https://member.lumenhealthplan.example/claims/CLM-1 for the EOB.")
    message.add_attachment(
        b"not a real file\n",
        maintype="text",
        subtype="html",
        filename="EOB.html",
    )
    return message.as_bytes()


def test_eml_extracts_headers_links_and_attachment_name():
    parsed = parse_bytes(_sample_eml())
    assert parsed.subject == "Explanation of benefits"
    assert parsed.from_addr == "notices@lumenhealthplan.example"
    assert parsed.reply_addr == "other.desk@gmail.com"
    assert any(link.href.startswith("https://member.lumenhealthplan.example/") for link in parsed.links)
    assert parsed.attachments[0].filename == "EOB.html"
    rendered = render_for_model(parsed)
    assert "Subject: Explanation of benefits" in rendered
    assert "EOB.html" in rendered
    assert "not a real file" not in rendered


def test_paste_without_headers_is_a_body():
    parsed = parse_text("Please review the visit notes when you have time.")
    assert parsed.subject == ""
    assert "visit notes" in parsed.body_text


def test_deceptive_link_survives_eml_roundtrip():
    from phishguard.parse import Link, ParsedEmail, to_eml_bytes

    email = ParsedEmail(
        subject="Appeal",
        from_header="Lumen Health Plan <alerts@member.lumenhealthplan.example>",
        reply_to="alerts@gmail.com",
        body_text="Open https://member.lumenhealthplan.example/appeal/CLM-1 today.",
        links=[
            Link(
                href="https://member.1umenhealthplan.example/appeal/CLM-1",
                text="https://member.lumenhealthplan.example/appeal/CLM-1",
            )
        ],
    )
    parsed = parse_bytes(to_eml_bytes(email))
    assert any("1umenhealthplan.example" in link.href for link in parsed.links)
    assert any("lumenhealthplan.example" in link.text for link in parsed.links)


def test_html_href_and_visible_text():
    raw = (
        b"From: Lab <lab@cedarlabpartners.example>\r\n"
        b"Subject: Results\r\n"
        b"Content-Type: text/html\r\n"
        b"\r\n"
        b"<p>Open <a href='https://results.cedarlab-partners.example/x'>"
        b"https://results.cedarlabpartners.example/x</a></p>"
    )
    parsed = parse_bytes(raw)
    assert "Open" in parsed.body_text
    assert parsed.links[0].href.startswith("https://results.cedarlab-partners.example/")
    assert "cedarlabpartners.example" in parsed.links[0].text
