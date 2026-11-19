"""Header, link, language, and attachment checks with plain-language reasons.

Weights are fixed heuristics. They are not probabilities, and they were not
fit on the held-out test set. A weight is how many points that warning
contributes to the rule score before it is capped at 1.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlparse

from phishguard.parse import ParsedEmail

# Real portals people in clinics actually see, plus the fictional organizations
# used in the synthetic set. A hit means "this string is being imitated," not
# "this organization sent mail."
BRAND_DOMAINS: tuple[str, ...] = (
    "mychart.com",
    "epic.com",
    "anthem.com",
    "cigna.com",
    "uhc.com",
    "aetna.com",
    "medicare.gov",
    "medicaid.gov",
    "kaiserpermanente.org",
    "labcorp.com",
    "questdiagnostics.com",
    "bcbs.com",
    "optum.com",
    "changehealthcare.com",
    "availity.com",
    "cms.gov",
    "hhs.gov",
    "adp.com",
    "workday.com",
    "paychex.com",
    "docusign.com",
    "docusign.net",
    "northwindclinic.example",
    "lumenhealthplan.example",
    "cedarlabpartners.example",
    "halcyonehr.example",
    "marigoldbenefits.example",
    "pikestreetbilling.example",
    "riverbendmg.example",
    "westbridgemed.example",
)

FREEMAIL_DOMAINS = {
    "gmail.com",
    "googlemail.com",
    "yahoo.com",
    "ymail.com",
    "hotmail.com",
    "outlook.com",
    "live.com",
    "aol.com",
    "icloud.com",
    "me.com",
    "proton.me",
    "protonmail.com",
    "gmx.com",
    "mail.com",
    "zoho.com",
}

SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "cutt.ly",
    "rb.gy",
    "shorturl.at",
    "tiny.cc",
    "buff.ly",
}

MULTI_PART_SUFFIXES = {
    "co.uk",
    "org.uk",
    "ac.uk",
    "gov.uk",
    "com.au",
    "net.au",
    "co.nz",
    "com.br",
}

HOMOGLYPHS = str.maketrans(
    {
        "0": "o",
        "1": "l",
        "3": "e",
        "4": "a",
        "5": "s",
        "7": "t",
        "@": "a",
        "$": "s",
    }
)

ORG_PHRASES = (
    "health plan",
    "health insurance",
    "medical group",
    "medical center",
    "community clinic",
    "billing department",
    "patient accounts",
    "medical records",
    "human resources",
    "payroll department",
    "laboratory",
    "lab results",
    "benefits team",
    "explanation of benefits",
)

URGENCY_PATTERNS = (
    r"\bimmediately\b",
    r"\burgent\b",
    r"\basap\b",
    r"\bright away\b",
    r"\bact now\b",
    r"\bwithin \d+ hours?\b",
    r"\bwithin \d+ minutes?\b",
    r"\bexpires? (today|tonight|in \d+)\b",
    r"\baccount (will be |has been )?(suspended|closed|locked|terminated|disabled)\b",
    r"\bfinal notice\b",
    r"\blast warning\b",
    r"\bfailure to (respond|comply|verify)\b",
    r"\bavoid (a )?(service )?(interruption|hold)\b",
    r"\bcoverage (will )?(end|terminate|lapse)\b",
    r"\bpayroll will be delayed\b",
    r"\bdo not ignore\b",
    r"\brecord will be deleted\b",
    r"\bfull (balance|amount) will be billed\b",
)

CREDENTIAL_PATTERNS = (
    r"\bpassword\b",
    r"\bone[- ]time (code|password|pin)\b",
    r"\bverify your (identity|account|email)\b",
    r"\bconfirm your (identity|account)\b",
    r"\b(sign|log)[\s-]?in\b",
    r"\bsocial security\b",
    r"\brouting number\b",
)

PAYMENT_PATTERNS = (
    r"\b(updated|new|changed) (bank|routing|payment)\b",
    r"\bbank (details|account|information).{0,40}(changed|updated|confirm)",
    r"\bwire transfer\b",
    r"\bpast due\b",
    r"\bremit today\b",
    r"\bdirect deposit (failed|change|update)\b",
    r"\bconfirm your banking\b",
)

EXECUTABLE_EXTENSIONS = {
    ".exe",
    ".scr",
    ".js",
    ".jse",
    ".vbs",
    ".vbe",
    ".bat",
    ".cmd",
    ".ps1",
    ".msi",
    ".iso",
    ".img",
    ".lnk",
    ".hta",
    ".svg",
    ".jar",
    ".dll",
}
HTML_EXTENSIONS = {".html", ".htm", ".shtml"}
MACRO_EXTENSIONS = {".docm", ".xlsm", ".pptm", ".dotm", ".xlam", ".xlsb"}
ARCHIVE_EXTENSIONS = {".zip", ".rar", ".7z"}
DOUBLE_EXT_RE = re.compile(
    r"\.(pdf|docx?|xlsx?|txt|jpg|jpeg|png)\.(exe|js|jse|vbs|bat|cmd|scr|html?|iso|lnk)$",
    re.IGNORECASE,
)

SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3}


@dataclass(frozen=True)
class Finding:
    code: str
    severity: str
    weight: float
    text: str


def domain_of(address: str) -> str:
    if "@" not in address:
        return ""
    return address.rsplit("@", 1)[-1].strip().lower().rstrip(".")


def host_of(url: str) -> str:
    candidate = url.strip()
    if "://" not in candidate:
        candidate = "http://" + candidate
    try:
        host = urlparse(candidate).hostname
    except ValueError:
        return ""
    return (host or "").lower().rstrip(".")


def registrable_domain(host: str) -> str:
    labels = [label for label in host.split(".") if label]
    if len(labels) < 2:
        return host
    last_two = ".".join(labels[-2:])
    if last_two in MULTI_PART_SUFFIXES and len(labels) >= 3:
        return ".".join(labels[-3:])
    return last_two


def sld(host: str) -> str:
    registered = registrable_domain(host)
    return registered.split(".", 1)[0] if registered else ""


def levenshtein(left: str, right: str) -> int:
    if left == right:
        return 0
    if not left:
        return len(right)
    if not right:
        return len(left)
    previous = list(range(len(right) + 1))
    for i, lch in enumerate(left, start=1):
        current = [i]
        for j, rch in enumerate(right, start=1):
            insert = current[j - 1] + 1
            delete = previous[j] + 1
            replace = previous[j - 1] + (lch != rch)
            current.append(min(insert, delete, replace))
        previous = current
    return previous[-1]


def dehomoglyph(value: str) -> str:
    collapsed = value.translate(HOMOGLYPHS)
    collapsed = collapsed.replace("rn", "m")
    collapsed = collapsed.replace("vv", "w")
    return collapsed


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _brand_slds() -> list[tuple[str, str]]:
    pairs = []
    for domain in BRAND_DOMAINS:
        pairs.append((sld(domain), domain))
    return pairs


def lookalike_reason(host: str) -> Finding | None:
    """Return one lookalike finding for a host, if any."""
    if not host or _is_ip(host):
        return None
    registered = registrable_domain(host)
    if registered in BRAND_DOMAINS or host in BRAND_DOMAINS:
        return None
    host_sld = sld(host)
    labels = host.split(".")
    folded_sld = dehomoglyph(host_sld)

    for brand_sld, brand_domain in _brand_slds():
        if not brand_sld:
            continue
        # mychart.secure-login.example — the brand is a label on someone else's site.
        if brand_sld in labels[:-2] or (
            len(labels) > 2 and brand_sld in labels[:-1] and registered != brand_domain
        ):
            # The registrable-domain check above already skipped exact brand hosts.
            if brand_sld in labels and registered != brand_domain:
                return Finding(
                    code="brand_on_other_domain",
                    severity="high",
                    weight=0.55,
                    text=(
                        f"A link puts “{brand_sld}” on {registered}, which is not "
                        f"{brand_domain}. The real name is being used as a costume for a different site."
                    ),
                )
        if host_sld != brand_sld and folded_sld == brand_sld and len(brand_sld) >= 5:
            return Finding(
                code="homoglyph_domain",
                severity="high",
                weight=0.55,
                text=(
                    f"A link uses {host}, which swaps letters or digits to look like "
                    f"{brand_domain}. Check the spelling before you trust it."
                ),
            )
        if len(brand_sld) >= 6 and host_sld != brand_sld:
            distance = levenshtein(host_sld, brand_sld)
            if 0 < distance <= 2 and abs(len(host_sld) - len(brand_sld)) <= 2:
                return Finding(
                    code="lookalike_domain",
                    severity="high",
                    weight=0.55,
                    text=(
                        f"A link uses {registered}, which is spelled almost like {brand_domain} "
                        "but is not that site."
                    ),
                )
        parts = host_sld.split("-")
        if len(brand_sld) >= 5 and brand_sld in parts and host_sld != brand_sld:
            return Finding(
                code="brand_plus_extra_words",
                severity="high",
                weight=0.5,
                text=(
                    f"A link uses {registered}. It borrows the name “{brand_sld}” "
                    "and adds extra words. That is not the organization's own site."
                ),
            )
    return None


def _extension(filename: str) -> str:
    name = filename.lower().strip()
    if "." not in name:
        return ""
    return "." + name.rsplit(".", 1)[-1]


def attachment_findings(email: ParsedEmail) -> list[Finding]:
    findings: list[Finding] = []
    for item in email.attachments:
        name = item.filename or "attachment"
        lowered = name.lower()
        if DOUBLE_EXT_RE.search(lowered):
            findings.append(
                Finding(
                    code="double_extension",
                    severity="high",
                    weight=0.5,
                    text=(
                        f"The file “{name}” has a misleading name. The last part of the name "
                        "is the kind of file that can run or open a fake page. Do not open it."
                    ),
                )
            )
            continue
        ext = _extension(name)
        if ext in EXECUTABLE_EXTENSIONS:
            findings.append(
                Finding(
                    code="executable_attachment",
                    severity="high",
                    weight=0.5,
                    text=(
                        f"The file “{name}” is a type that can run a program. "
                        "Clinic mail should not ask you to open that. Do not open it."
                    ),
                )
            )
        elif ext in HTML_EXTENSIONS or item.content_type in {"text/html", "application/html"}:
            findings.append(
                Finding(
                    code="html_attachment",
                    severity="high",
                    weight=0.36,
                    text=(
                        f"The file “{name}” is a web page saved as a file. "
                        "Those are often used as a fake sign-in screen. Do not open it."
                    ),
                )
            )
        elif ext in MACRO_EXTENSIONS:
            findings.append(
                Finding(
                    code="macro_attachment",
                    severity="high",
                    weight=0.4,
                    text=(
                        f"The file “{name}” can contain macros. Do not enable editing or macros, "
                        "and do not open it unless IT has already told you to expect this exact file."
                    ),
                )
            )
        elif ext in ARCHIVE_EXTENSIONS:
            findings.append(
                Finding(
                    code="archive_attachment",
                    severity="low",
                    weight=0.12,
                    text=(
                        f"The file “{name}” is a compressed archive. Open it only if you already "
                        "expected an archive from this sender, and ask IT if you did not."
                    ),
                )
            )
    return findings


def _count_patterns(text: str, patterns: tuple[str, ...]) -> int:
    return sum(1 for pattern in patterns if re.search(pattern, text, flags=re.IGNORECASE))


def language_findings(email: ParsedEmail) -> list[Finding]:
    text = f"{email.subject}\n{email.body_text}"
    findings: list[Finding] = []
    urgency_hits = _count_patterns(text, URGENCY_PATTERNS)
    if urgency_hits:
        weight = min(0.16, 0.08 + 0.03 * (urgency_hits - 1))
        findings.append(
            Finding(
                code="urgency",
                severity="medium" if urgency_hits >= 2 else "low",
                weight=weight,
                text=(
                    "The message pushes you to act quickly or threatens a shut-off, a lockout, "
                    "or a deleted record. A real clinic or health plan usually gives you another "
                    "way to follow up that does not depend on this email."
                ),
            )
        )
    if _count_patterns(text, CREDENTIAL_PATTERNS):
        findings.append(
            Finding(
                code="credential_request",
                severity="low",
                weight=0.1,
                text=(
                    "It asks for a password, a sign-in, or an identity check. "
                    "Do that only on a site you opened yourself, not from a link in the mail."
                ),
            )
        )
    if _count_patterns(text, PAYMENT_PATTERNS):
        findings.append(
            Finding(
                code="payment_change",
                severity="medium",
                weight=0.16,
                text=(
                    "It talks about a payment, a past-due balance, or a bank-detail change. "
                    "Confirm any change with the phone number you already have on file, "
                    "not a number printed in this email."
                ),
            )
        )
    return findings


def header_findings(email: ParsedEmail) -> list[Finding]:
    findings: list[Finding] = []
    from_domain = domain_of(email.from_addr)
    reply_domain = domain_of(email.reply_addr)
    if reply_domain and from_domain and reply_domain != from_domain:
        suspicious = reply_domain in FREEMAIL_DOMAINS or lookalike_reason(reply_domain) is not None
        if suspicious:
            findings.append(
                Finding(
                    code="reply_to_mismatch",
                    severity="medium",
                    weight=0.3,
                    text=(
                        f"If you hit reply, the answer goes to {reply_domain}, not to "
                        f"{from_domain}, where the message claims to be from."
                    ),
                )
            )
        else:
            findings.append(
                Finding(
                    code="reply_to_mismatch_mild",
                    severity="low",
                    weight=0.08,
                    text=(
                        f"The reply address ({reply_domain}) is different from the from address "
                        f"({from_domain}). That happens on some newsletters, but it is also how "
                        "a fake message hides where replies go. Treat it as a question, not proof."
                    ),
                )
            )
    display = email.from_name.lower()
    brand_in_name = any(sld(domain) and sld(domain) in display for domain in BRAND_DOMAINS)
    phrase_in_name = any(phrase in display for phrase in ORG_PHRASES)
    if from_domain in FREEMAIL_DOMAINS and (brand_in_name or phrase_in_name):
        shown = email.from_name or "an organization"
        findings.append(
            Finding(
                code="freemail_impersonation",
                severity="high",
                weight=0.36,
                text=(
                    f"The sender name says “{shown},” but the mailbox is {from_domain}, "
                    "a free personal email service. A health plan, clinic, or payroll office "
                    "usually writes from its own site."
                ),
            )
        )
    from_lookalike = lookalike_reason(from_domain) if from_domain else None
    if from_lookalike is not None:
        findings.append(
            Finding(
                code="from_lookalike",
                severity="high",
                weight=0.45,
                text=(
                    f"The sender address uses {from_domain}. "
                    + from_lookalike.text[0].lower()
                    + from_lookalike.text[1:]
                ),
            )
        )
    return findings


def link_findings(email: ParsedEmail) -> list[Finding]:
    findings: list[Finding] = []
    saw_lookalike = False
    saw_short = False
    saw_ip = False
    saw_puny = False
    saw_at = False
    saw_http = False
    saw_mismatch = False
    saw_deep = False

    for link in email.links:
        host = host_of(link.href)
        if not host:
            continue
        if not saw_ip and _is_ip(host):
            saw_ip = True
            findings.append(
                Finding(
                    code="ip_url",
                    severity="high",
                    weight=0.4,
                    text=(
                        f"A link goes to the numeric address {host} instead of a normal site name. "
                        "Do not follow it."
                    ),
                )
            )
        if not saw_puny and "xn--" in host:
            saw_puny = True
            findings.append(
                Finding(
                    code="punycode",
                    severity="high",
                    weight=0.4,
                    text=(
                        "A link uses an internationalized name (xn--). Those names can hide "
                        "letters that only look familiar. Do not follow it from this email."
                    ),
                )
            )
        if not saw_at and "@" in link.href.split("://", 1)[-1].split("/", 1)[0]:
            saw_at = True
            findings.append(
                Finding(
                    code="at_in_url",
                    severity="high",
                    weight=0.35,
                    text=(
                        "A link hides the real destination behind an @ sign. "
                        "The site that actually opens is the part after the @."
                    ),
                )
            )
        if not saw_short and (host in SHORTENERS or registrable_domain(host) in SHORTENERS):
            saw_short = True
            findings.append(
                Finding(
                    code="shortened_url",
                    severity="medium",
                    weight=0.18,
                    text=(
                        f"A link hides the destination behind a shortener ({host}). "
                        "You cannot see where it goes from the message."
                    ),
                )
            )
        if not saw_lookalike:
            lookalike = lookalike_reason(host)
            if lookalike is not None:
                saw_lookalike = True
                findings.append(lookalike)
        if not saw_deep and host.count(".") >= 4:
            saw_deep = True
            findings.append(
                Finding(
                    code="deep_subdomain",
                    severity="low",
                    weight=0.1,
                    text=(
                        f"A link uses a long chain of names ({host}). "
                        "Extra words in front of a site are a common place to hide a fake page."
                    ),
                )
            )
        if not saw_http and link.href.lower().startswith("http://"):
            path = link.href.lower()
            if re.search(r"login|password|verify|account|reset|claim|pay|invoice|secure", path):
                saw_http = True
                findings.append(
                    Finding(
                        code="insecure_login_link",
                        severity="low",
                        weight=0.12,
                        text=(
                            "A link that mentions a sign-in or a payment does not use https. "
                            "Do not type a password there."
                        ),
                    )
                )
        if not saw_mismatch and link.text:
            shown_hosts = []
            for shown in urls_in_visible_text(link.text):
                shown_host = host_of(shown)
                if shown_host:
                    shown_hosts.append(shown_host)
            # Also catch bare domains in the anchor, such as lumenhealthplan.example.
            for match in re.findall(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", link.text.lower()):
                shown_hosts.append(match)
            for shown_host in shown_hosts:
                if registrable_domain(shown_host) != registrable_domain(host):
                    saw_mismatch = True
                    findings.append(
                        Finding(
                            code="href_mismatch",
                            severity="high",
                            weight=0.45,
                            text=(
                                f"The link text shows {shown_host}, but the link actually goes to {host}."
                            ),
                        )
                    )
                    break
    return findings


def urls_in_visible_text(text: str) -> list[str]:
    return re.findall(r"https?://[^\s<>\"']+", text or "", flags=re.IGNORECASE)


def extract_findings(email: ParsedEmail) -> list[Finding]:
    findings = []
    findings.extend(header_findings(email))
    findings.extend(link_findings(email))
    findings.extend(attachment_findings(email))
    findings.extend(language_findings(email))
    # Stable order: stronger warnings first, then the order they were found.
    findings.sort(key=lambda item: (-SEVERITY_RANK[item.severity], -item.weight, item.code))
    return findings


def rule_score(findings: list[Finding]) -> float:
    total = sum(max(0.0, item.weight) for item in findings)
    return max(0.0, min(1.0, total))
