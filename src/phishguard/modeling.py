"""TF-IDF logistic regression and the subword embedding model."""

from __future__ import annotations

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import FeatureUnion, Pipeline

from phishguard.embedding import SubwordEmbeddingClassifier


def build_tfidf_logreg() -> Pipeline:
    word = TfidfVectorizer(
        analyzer="word",
        ngram_range=(1, 2),
        min_df=2,
        max_features=30000,
        sublinear_tf=True,
        strip_accents="unicode",
        lowercase=True,
    )
    char = TfidfVectorizer(
        analyzer="char_wb",
        ngram_range=(3, 5),
        min_df=2,
        max_features=20000,
        sublinear_tf=True,
        lowercase=True,
    )
    return Pipeline(
        [
            ("features", FeatureUnion([("word", word), ("char", char)])),
            (
                "clf",
                LogisticRegression(
                    C=4.0,
                    class_weight="balanced",
                    solver="liblinear",
                    max_iter=500,
                    random_state=42,
                ),
            ),
        ]
    )


def fit_tfidf(texts: list[str], y, sample_weight) -> Pipeline:
    pipeline = build_tfidf_logreg()
    pipeline.fit(texts, y, clf__sample_weight=sample_weight)
    return pipeline


def positive_proba_pipeline(pipeline: Pipeline, texts: list[str]):
    probabilities = pipeline.predict_proba(texts)
    classes = list(pipeline.named_steps["clf"].classes_)
    index = classes.index(1)
    return probabilities[:, index]


def fit_embedding(texts: list[str], y, sample_weight) -> SubwordEmbeddingClassifier:
    model = SubwordEmbeddingClassifier()
    model.fit(texts, y, sample_weight=sample_weight)
    return model


def positive_proba_embedding(model: SubwordEmbeddingClassifier, texts: list[str]):
    return model.predict_proba(texts)[:, 1]
