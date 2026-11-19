from phishguard.explain import band_for, combine_scores, risk_points


def test_quiet_wording_is_capped():
    combined, mode = combine_scores(0.99, 0.0)
    assert mode == "wording-capped"
    assert abs(combined - 0.45) < 1e-9
    assert risk_points(combined) == 45
    assert band_for(45)[0] == "review"


def test_concrete_warning_can_stand_alone():
    combined, mode = combine_scores(0.1, 0.8)
    assert mode == "combined"
    assert combined > 0.8
    assert band_for(risk_points(combined))[0] == "high"


def test_clean_message_stays_low():
    combined, _mode = combine_scores(0.12, 0.0)
    assert band_for(risk_points(combined))[0] == "low"


def test_rules_only_when_model_missing():
    combined, mode = combine_scores(None, 0.55)
    assert mode == "rules-only"
    assert abs(combined - 0.55) < 1e-9
