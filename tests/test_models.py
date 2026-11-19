from phishguard.embedding import SubwordEmbeddingClassifier
from phishguard.metrics import best_f1_threshold, binary_report
from phishguard.modeling import fit_tfidf, positive_proba_pipeline


def test_embedding_ranks_easy_text():
    phish = ["urgent verify password suspended click account locked"] * 12
    legit = ["tuesday standup notes and the lunch order for the team"] * 12
    labels = [1] * 12 + [0] * 12
    model = SubwordEmbeddingClassifier(epochs=8, max_features=400, min_count=1, seed=1)
    model.fit(phish + legit, labels)
    phish_mean = model.predict_proba(phish)[:, 1].mean()
    legit_mean = model.predict_proba(legit)[:, 1].mean()
    assert phish_mean > legit_mean


def test_tfidf_ranks_easy_text():
    phish = [f"verify your password now claim suspended {i}" for i in range(8)]
    legit = [f"staff meeting notes room schedule {i}" for i in range(8)]
    # min_df=2 in the real pipeline, so repeat each line with the label kept beside it.
    texts = phish + legit + phish + legit
    y = [1] * 8 + [0] * 8 + [1] * 8 + [0] * 8
    model = fit_tfidf(texts, y, [1.0] * len(texts))
    phish_mean = positive_proba_pipeline(model, phish).mean()
    legit_mean = positive_proba_pipeline(model, legit).mean()
    assert phish_mean > legit_mean


def test_metrics_confusion_matrix_orientation():
    report = binary_report([0, 0, 1, 1], [0, 1, 1, 0], [0.1, 0.6, 0.8, 0.4])
    assert report["confusion_matrix"]["tn"] == 1
    assert report["confusion_matrix"]["fp"] == 1
    assert report["confusion_matrix"]["fn"] == 1
    assert report["confusion_matrix"]["tp"] == 1
    tuned = best_f1_threshold([0, 0, 1, 1], [0.1, 0.2, 0.8, 0.9])
    assert 0.2 <= tuned["threshold"] <= 0.8
    assert tuned["f1"] == 1.0
