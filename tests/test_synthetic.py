import re
from collections import defaultdict

from phishguard.features import extract_findings, rule_score
from phishguard.parse import parsed_from_record
from phishguard.synthetic import all_records

URL_HOST = re.compile(r"https?://([^/\s]+)", re.IGNORECASE)


def test_synthetic_set_is_balanced_and_split_by_template():
    rows = all_records()
    assert len(rows) == 600
    labels = {0: 0, 1: 0}
    templates = defaultdict(set)
    for row in rows:
        labels[row["label"]] += 1
        templates[row["template_id"]].add(row["split"])
        assert row["synthetic"] is True
        assert row["license"] == "MIT"
        assert row["source"] == "synthetic"
    assert labels[0] == 300 and labels[1] == 300
    # A template belongs to one split, so wording from that template cannot leak into another.
    assert all(len(splits) == 1 for splits in templates.values())
    demo = [row for row in rows if row["demo"]]
    assert {row["label"] for row in demo} == {0, 1}
    assert all(row["split"] == "test" for row in demo)


def test_synthetic_links_use_reserved_domains():
    for row in all_records():
        blob = " ".join(
            [row["body"], row["subject"]]
            + [item["href"] for item in row.get("links") or []]
        )
        for host in URL_HOST.findall(blob):
            host = host.split("@")[-1].lower().rstrip(".")
            assert host.endswith((".example", ".test", ".invalid", ".localhost")), host


def test_phish_templates_have_a_signal_and_legit_templates_do_not_look_high():
    seen = set()
    for row in all_records():
        if not row["id"].endswith("-00"):
            continue
        seen.add(row["template_id"])
        findings = extract_findings(parsed_from_record(row))
        score = rule_score(findings)
        if row["label"] == 0:
            assert all(item.severity != "high" for item in findings), row["template_id"]
            assert score < 0.25, (row["template_id"], score, [item.code for item in findings])
        else:
            assert findings, row["template_id"]
            assert score >= 0.15, (row["template_id"], score)
    assert len(seen) == 60
