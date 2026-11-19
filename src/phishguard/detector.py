"""Load the saved models and score one message."""

from __future__ import annotations

from pathlib import Path

import joblib

from phishguard.explain import Report, build_report, wording_cues_from_pipeline
from phishguard.modeling import positive_proba_embedding, positive_proba_pipeline
from phishguard.parse import ParsedEmail, parse_bytes, parse_text, render_for_model
from phishguard.paths import model_path


class Detector:
    def __init__(self, bundle: dict | None = None):
        self.bundle = bundle or {}

    @classmethod
    def load(cls, path: Path | None = None) -> "Detector":
        location = path or model_path()
        if not location.exists():
            return cls(None)
        return cls(joblib.load(location))

    @property
    def ready(self) -> bool:
        return bool(self.bundle) and "selected_model" in self.bundle

    def score_email(self, email: ParsedEmail) -> Report:
        text = render_for_model(email)
        probabilities: dict[str, float] = {}
        note = ""
        selected = ""
        text_probability = None
        cues: list[str] = []
        if self.ready:
            selected = self.bundle["selected_model"]
            tfidf = self.bundle.get("tfidf")
            embedding = self.bundle.get("embedding")
            if tfidf is not None:
                probabilities["tfidf_logreg"] = float(positive_proba_pipeline(tfidf, [text])[0])
                if probabilities["tfidf_logreg"] >= 0.5:
                    cues = wording_cues_from_pipeline(tfidf, text)
            if embedding is not None:
                probabilities["subword_embedding"] = float(
                    positive_proba_embedding(embedding, [text])[0]
                )
            if selected in probabilities:
                text_probability = probabilities[selected]
            elif probabilities:
                selected, text_probability = next(iter(probabilities.items()))
        else:
            note = (
                "Language models are not loaded, so this score uses the header, "
                "link, and attachment checks only. Train the models to add the wording score."
            )
        return build_report(
            email,
            text_probability=text_probability,
            model_probabilities=probabilities,
            selected_model=selected,
            wording_cues=cues,
            model_note=note,
        )

    def score_text(self, text: str) -> Report:
        return self.score_email(parse_text(text))

    def score_bytes(self, raw: bytes) -> Report:
        return self.score_email(parse_bytes(raw))
