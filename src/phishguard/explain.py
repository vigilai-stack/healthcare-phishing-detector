"""Turn model probabilities and rule findings into a score a front desk can use."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from phishguard.features import Finding, extract_findings, rule_score
from phishguard.parse import ParsedEmail

WORDING_STOP = {
    "that",
    "this",
    "with",
    "from",
    "your",
    "have",
    "will",
    "about",
    "please",
    "thanks",
    "thank",
    "email",
    "message",
    "hello",
    "dear",
    "regards",
    "sincerely",
    "attached",
    "attachment",
    "subject",
    "none",
    "http",
    "https",
    "com",
    "www",
}


@dataclass
class Report:
    risk: int
    band: str
    band_label: str
    action: str
    findings: list[Finding]
    rule_score: float
    text_probability: float | None
    selected_model: str
    model_probabilities: dict[str, float]
    wording_cues: list[str] = field(default_factory=list)
    model_note: str = ""
    blend: str = ""

    def to_dict(self) -> dict:
        return {
            "risk": self.risk,
            "band": self.band,
            "band_label": self.band_label,
            "action": self.action,
            "rule_score": round(self.rule_score, 4),
            "text_probability": None
            if self.text_probability is None
            else round(self.text_probability, 4),
            "selected_model": self.selected_model,
            "model_probabilities": {
                name: round(value, 4) for name, value in self.model_probabilities.items()
            },
            "wording_cues": list(self.wording_cues),
            "model_note": self.model_note,
            "blend": self.blend,
            "findings": [
                {
                    "code": item.code,
                    "severity": item.severity,
                    "weight": item.weight,
                    "text": item.text,
                }
                for item in self.findings
            ],
        }


def combine_scores(text_probability: float | None, rules: float) -> tuple[float, str]:
    """Blend a text-model probability with the capped rule score.

    When the header, link, and file checks are quiet, wording similarity is
    capped. A familiar healthcare topic should not, by itself, read as a
    high-risk phish. A concrete warning can stand even if the wording score
    is low.
    """
    rules = min(1.0, max(0.0, rules))
    if text_probability is None:
        return rules, "rules-only"
    text_probability = min(1.0, max(0.0, float(text_probability)))
    if rules < 0.2:
        text_used = min(text_probability, 0.45)
        mode = "wording-capped"
    else:
        text_used = text_probability
        mode = "combined"
    combined = 1.0 - (1.0 - text_used) * (1.0 - rules)
    return combined, mode


def risk_points(combined: float) -> int:
    return max(0, min(100, int(combined * 100 + 0.5)))


def band_for(risk: int) -> tuple[str, str, str]:
    if risk >= 80:
        return (
            "high",
            "High risk",
            "Treat this as phishing. Do not click, open files, reply, or forward "
            "patient information. Report it to IT through your clinic's normal process.",
        )
    if risk >= 60:
        return (
            "suspicious",
            "Suspicious",
            "Do not click links, open files, or reply. Forward it to your IT or "
            "security contact using the process you already have.",
        )
    if risk >= 30:
        return (
            "review",
            "Needs a closer look",
            "Check this before you act. Use a phone number you already have on a "
            "card, a statement, or the clinic site. Do not use a number from this email.",
        )
    return (
        "low",
        "Low",
        "No strong warning sign stood out. If you were not expecting this, still "
        "avoid links and call with a number you already know.",
    )


def wording_cues_from_pipeline(pipeline, text: str, limit: int = 6) -> list[str]:
    """Words that pushed the linear model up. Char n-grams are left out on purpose."""
    import numpy as np

    features = pipeline.named_steps["features"]
    clf = pipeline.named_steps["clf"]
    row = features.transform([text])
    coef = clf.coef_[0]
    names = features.get_feature_names_out()
    csr = row.tocsr()
    indices = csr.indices
    data = csr.data
    if len(indices) == 0:
        return []
    scores = coef[indices] * data
    order = np.argsort(scores)[::-1]
    cues: list[str] = []
    seen: set[str] = set()
    for position in order:
        if scores[position] <= 0:
            break
        name = str(names[indices[position]])
        if not name.startswith("word__"):
            continue
        token = name.split("__", 1)[1].lower()
        if " " in token or not token.isalpha():
            continue
        if not 4 <= len(token) <= 16 or token in WORDING_STOP or token in seen:
            continue
        seen.add(token)
        cues.append(token)
        if len(cues) >= limit:
            break
    return cues


def build_report(
    email: ParsedEmail,
    *,
    text_probability: float | None,
    model_probabilities: dict[str, float] | None = None,
    selected_model: str = "",
    wording_cues: list[str] | None = None,
    model_note: str = "",
) -> Report:
    findings = extract_findings(email)
    rules = rule_score(findings)
    combined, mode = combine_scores(text_probability, rules)
    risk = risk_points(combined)
    band, label, action = band_for(risk)
    note = model_note
    if text_probability is not None and rules < 0.2 and text_probability >= 0.45:
        extra = (
            "The wording resembles mail the language model was trained to treat as "
            "unwanted, but the address and link checks did not find a specific warning. "
            "Ask IT or a supervisor before you click or reply."
        )
        if not any(item.code == "wording_only" for item in findings):
            findings = list(findings) + [
                Finding(code="wording_only", severity="low", weight=0.0, text=extra)
            ]
    return Report(
        risk=risk,
        band=band,
        band_label=label,
        action=action,
        findings=findings,
        rule_score=rules,
        text_probability=text_probability,
        selected_model=selected_model,
        model_probabilities=dict(model_probabilities or {}),
        wording_cues=list(wording_cues or []),
        model_note=note,
        blend=mode,
    )


def plain_summary(report: Report, email: ParsedEmail) -> str:
    lines = [
        f"Risk score: {report.risk} / 100 ({report.band_label})",
        report.action,
        "",
    ]
    if report.model_note:
        lines.append(report.model_note)
        lines.append("")
    if report.findings:
        lines.append("Why:")
        for item in report.findings:
            lines.append(f"- [{item.severity}] {item.text}")
    else:
        lines.append("Why: no header, link, attachment, or urgency warning fired.")
    if report.wording_cues:
        lines.append("")
        lines.append(
            "Words that raised the language-model score: " + ", ".join(report.wording_cues)
        )
    if report.model_probabilities:
        lines.append("")
        bits = [
            f"{name.replace('_', ' ')} {value * 100:.0f}%"
            for name, value in report.model_probabilities.items()
        ]
        lines.append("Language model scores (chance the text is unwanted mail): " + "; ".join(bits))
        if report.selected_model:
            lines.append(f"Score uses: {report.selected_model.replace('_', ' ')}.")
    lines.append("")
    lines.append(f"From: {email.from_header or '(not set)'}")
    lines.append(f"Reply-To: {email.reply_to or '(not set)'}")
    if email.attachments:
        names = ", ".join(item.filename for item in email.attachments)
        lines.append(f"Attachments: {names}")
    link_hosts = []
    for link in email.links[:8]:
        host = re.sub(r"^https?://", "", link.href).split("/")[0]
        link_hosts.append(host)
    if link_hosts:
        lines.append("Link hosts: " + ", ".join(link_hosts))
    lines.append("")
    lines.append(
        "This is a screening aid. It does not open links, and it is not a substitute "
        "for your clinic's security process."
    )
    return "\n".join(lines)
