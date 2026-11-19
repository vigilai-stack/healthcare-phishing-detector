"""Parse pasted text or .eml bytes into a small, explicit email record.

Nothing in this module contacts the network. Links are strings, not fetches.
Attachment bytes are discarded after the filename and content type are read.
"""

from __future__ import annotations

import html
import re
from dataclasses import dataclass, field
from email import policy
from email.message import EmailMessage, Message
from email.parser import BytesParser
from email.utils import parseaddr
from html.parser import HTMLParser
from typing import Iterable

URL_RE = re.compile(r"https?://[^\s<>\"')\]]+", re.IGNORECASE)
MAILTO_RE = re.compile(r"^mailto:", re.IGNORECASE)
TRAILING_PUNCT = ".,;:)>]\"'"


@dataclass
class Attachment:
    filename: str
    content_type: str


@dataclass
class Link:
    href: str
    text: str = ""


@dataclass
class ParsedEmail:
    subject: str = ""
    from_header: str = ""
    reply_to: str = ""
    to_header: str = ""
    body_text: str = ""
    links: list[Link] = field(default_factory=list)
    attachments: list[Attachment] = field(default_factory=list)

    @property
    def from_name(self) -> str:
        name, _addr = parseaddr(self.from_header)
        return name.strip().strip('"')

    @property
    def from_addr(self) -> str:
        _name, addr = parseaddr(self.from_header)
        return addr.strip().lower()

    @property
    def reply_addr(self) -> str:
        _name, addr = parseaddr(self.reply_to)
        return addr.strip().lower()


class _HTMLText(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self.links: list[Link] = []
        self._href: str | None = None
        self._buf: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr = {k.lower(): (v or "") for k, v in attrs}
        if tag.lower() == "a":
            self._href = attr.get("href", "")
            self._buf = []
        if tag.lower() == "br":
            self.parts.append("\n")

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "a" and self._href is not None:
            self.links.append(Link(href=self._href, text="".join(self._buf).strip()))
            self._href = None
            self._buf = []
        if tag.lower() in {"p", "div", "tr", "li", "h1", "h2", "h3", "table"}:
            self.parts.append("\n")

    def handle_data(self, data: str) -> None:
        self.parts.append(data)
        if self._href is not None:
            self._buf.append(data)


def _clean_url(url: str) -> str:
    url = url.strip().strip(TRAILING_PUNCT)
    if not url or MAILTO_RE.match(url):
        return ""
    if url.lower().startswith(("cid:", "javascript:", "data:")):
        return ""
    return url


def urls_in_text(text: str) -> list[str]:
    found = []
    for match in URL_RE.findall(text or ""):
        cleaned = _clean_url(match)
        if cleaned:
            found.append(cleaned)
    return found


def html_to_text_and_links(html: str) -> tuple[str, list[Link]]:
    parser = _HTMLText()
    try:
        parser.feed(html or "")
        parser.close()
    except Exception:
        # Broken markup should not hide the rest of the message.
        plain = re.sub(r"<[^>]+>", " ", html or "")
        return re.sub(r"\s+", " ", plain).strip(), []
    text = re.sub(r"[ \t]+\n", "\n", "".join(parser.parts))
    text = re.sub(r"\n{3,}", "\n\n", text).strip()
    links = []
    for link in parser.links:
        href = _clean_url(link.href)
        if href:
            links.append(Link(href=href, text=link.text))
    return text, links


def _decode_part(part: Message) -> str:
    payload = part.get_payload(decode=True)
    if payload is None:
        raw = part.get_payload()
        return raw if isinstance(raw, str) else ""
    if not isinstance(payload, (bytes, bytearray)):
        return str(payload)
    charset = part.get_content_charset() or "utf-8"
    try:
        return bytes(payload).decode(charset, errors="replace")
    except LookupError:
        return bytes(payload).decode("utf-8", errors="replace")


def _strip_mbox_from_line(raw: bytes) -> bytes:
    if raw.startswith(b"From "):
        _, _, rest = raw.partition(b"\n")
        return rest
    return raw


def parse_bytes(raw: bytes) -> ParsedEmail:
    """Parse a single RFC822 message. Leading mbox 'From ' lines are ignored."""
    message = BytesParser(policy=policy.default).parsebytes(_strip_mbox_from_line(raw))
    return _from_message(message)


def parse_text(text: str) -> ParsedEmail:
    """Parse a paste. Full messages with headers are parsed as email; otherwise the paste is the body."""
    stripped = text.lstrip("\ufeff").lstrip()
    looks_like_message = bool(
        re.match(r"(?is)^(from|received|return-path|subject|mime-version)\s*:", stripped)
    )
    if looks_like_message or "\nFrom:" in text or text.startswith("From:"):
        return parse_bytes(text.encode("utf-8", errors="replace"))
    links = [Link(href=url, text="") for url in urls_in_text(text)]
    return ParsedEmail(body_text=text.strip(), links=_dedupe_links(links))


def _from_message(message: Message) -> ParsedEmail:
    subject = str(message.get("subject", "") or "")
    from_header = str(message.get("from", "") or "")
    reply_to = str(message.get("reply-to", "") or "")
    to_header = str(message.get("to", "") or "")

    plain_parts: list[str] = []
    html_parts: list[str] = []
    attachments: list[Attachment] = []

    parts: Iterable[Message]
    if message.is_multipart():
        parts = message.walk()
    else:
        parts = [message]

    for part in parts:
        if part.is_multipart():
            continue
        disposition = (part.get_content_disposition() or "").lower()
        filename = part.get_filename()
        content_type = part.get_content_type().lower()
        if filename or disposition == "attachment":
            attachments.append(
                Attachment(
                    filename=filename or "attachment",
                    content_type=content_type or "application/octet-stream",
                )
            )
            continue
        if content_type == "text/plain":
            plain_parts.append(_decode_part(part))
        elif content_type == "text/html":
            html_parts.append(_decode_part(part))
        elif filename:
            attachments.append(Attachment(filename=filename, content_type=content_type))

    links: list[Link] = []
    html_text_chunks: list[str] = []
    for html in html_parts:
        text, html_links = html_to_text_and_links(html)
        if text:
            html_text_chunks.append(text)
        links.extend(html_links)

    body = "\n\n".join(chunk.strip() for chunk in plain_parts if chunk.strip())
    if not body:
        body = "\n\n".join(html_text_chunks)
    for url in urls_in_text(body):
        links.append(Link(href=url, text=""))
    for url in urls_in_text(subject):
        links.append(Link(href=url, text=""))

    return ParsedEmail(
        subject=_unfold(subject),
        from_header=_unfold(from_header),
        reply_to=_unfold(reply_to),
        to_header=_unfold(to_header),
        body_text=body.strip(),
        links=_dedupe_links(links),
        attachments=attachments,
    )


def _unfold(value: str) -> str:
    return re.sub(r"\s+", " ", value or "").strip()


def _dedupe_links(links: list[Link]) -> list[Link]:
    seen: set[tuple[str, str]] = set()
    out: list[Link] = []
    for link in links:
        key = (link.href, link.text)
        if not link.href or key in seen:
            continue
        seen.add(key)
        out.append(link)
    return out


def render_for_model(email: ParsedEmail, body_limit: int = 6000) -> str:
    """The text both classifiers see. Same fields at train time and at scan time."""
    if email.attachments:
        rendered_attachments = ", ".join(
            f"{item.filename} ({item.content_type})" for item in email.attachments
        )
    else:
        rendered_attachments = "(none)"
    body = (email.body_text or "").strip()
    if len(body) > body_limit:
        body = body[:body_limit]
    return (
        f"Subject: {email.subject}\n"
        f"From: {email.from_header}\n"
        f"Reply-To: {email.reply_to or '(none)'}\n"
        f"Attachments: {rendered_attachments}\n\n"
        f"{body}"
    )


def parsed_from_record(record: dict) -> ParsedEmail:
    """Build a parsed message from dataset fields. Explicit links win over body URLs."""
    if "links" in record:
        links = [
            Link(href=str(item.get("href", "")), text=str(item.get("text", "")))
            for item in record.get("links") or []
        ]
    else:
        links = [Link(href=url, text="") for url in urls_in_text(record.get("body", ""))]
        links.extend(Link(href=url, text="") for url in urls_in_text(record.get("subject", "")))
    attachments = [
        Attachment(
            filename=str(item.get("filename") or "attachment"),
            content_type=str(item.get("content_type") or "application/octet-stream"),
        )
        for item in record.get("attachments") or []
    ]
    return ParsedEmail(
        subject=str(record.get("subject") or ""),
        from_header=str(record.get("from") or ""),
        reply_to=str(record.get("reply_to") or ""),
        body_text=str(record.get("body") or ""),
        links=_dedupe_links(links),
        attachments=attachments,
    )


def to_eml_bytes(email: ParsedEmail, placeholder: bytes | None = None) -> bytes:
    """Build a harmless .eml. Attachment bodies are plain-text placeholders, not documents."""
    message = EmailMessage()
    message["Subject"] = email.subject
    message["From"] = email.from_header or "noreply@example.invalid"
    message["To"] = email.to_header or "front.desk@northwindclinic.example"
    if email.reply_to:
        message["Reply-To"] = email.reply_to
    message["Date"] = "Tue, 17 Mar 2026 14:05:00 +0000"
    plain = email.body_text or ""
    message.set_content(plain)
    deceptive = [
        link
        for link in email.links
        if link.href and link.text and link.text.strip() and link.text.strip() != link.href.strip()
    ]
    if deceptive:
        html_body = html.escape(plain)
        for link in deceptive:
            visible = html.escape(link.text)
            anchor = f'<a href="{html.escape(link.href, quote=True)}">{visible}</a>'
            if visible in html_body:
                html_body = html_body.replace(visible, anchor, 1)
            else:
                html_body += f"<p>{anchor}</p>"
        html_body = html_body.replace("\n", "<br>\n")
        message.add_alternative(
            f"<!DOCTYPE html><html><body>{html_body}</body></html>",
            subtype="html",
        )
    payload = placeholder or (
        b"Synthetic placeholder. This is not a real document and does not contain a program.\n"
    )
    for attachment in email.attachments:
        maintype, _, subtype = (attachment.content_type or "application/octet-stream").partition("/")
        if not subtype:
            maintype, subtype = "application", "octet-stream"
        message.add_attachment(
            payload,
            maintype=maintype,
            subtype=subtype,
            filename=attachment.filename,
        )
    return message.as_bytes()
