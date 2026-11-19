"""Small subword embedding classifier trained with numpy on CPU.

Each word is split into character n-grams, the same idea fastText uses.
A document is the average of those embeddings. A linear layer turns that
average into a phishing probability. There is no pretrained transformer
and no download.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

import numpy as np

TOKEN_RE = re.compile(r"[a-z0-9']+")


def _ngrams(text: str, limit_words: int = 350) -> list[str]:
    words = TOKEN_RE.findall(text.lower())[:limit_words]
    grams: list[str] = []
    for word in words:
        grams.append(word)
        padded = f"<{word}>"
        for size in (3, 4, 5):
            if len(padded) < size:
                continue
            grams.extend(padded[i : i + size] for i in range(len(padded) - size + 1))
        if len(grams) >= 900:
            break
    return grams


@dataclass
class SubwordEmbeddingClassifier:
    """Mean-pooled subword embeddings plus a logistic layer.

    The object is joblib-friendly: after fit(), only numpy arrays and a dict remain.
    """

    dim: int = 48
    max_features: int = 12000
    min_count: int = 2
    epochs: int = 6
    lr: float = 0.35
    l2: float = 1e-4
    seed: int = 42

    def fit(self, texts: list[str], y, sample_weight=None) -> "SubwordEmbeddingClassifier":
        labels = np.asarray(y, dtype=np.float64)
        if sample_weight is None:
            weights = np.ones(len(labels), dtype=np.float64)
        else:
            weights = np.asarray(sample_weight, dtype=np.float64)
        documents = [_ngrams(text) for text in texts]
        counts: dict[str, int] = {}
        for grams in documents:
            for gram in set(grams):
                counts[gram] = counts.get(gram, 0) + 1
        ranked = [gram for gram, count in counts.items() if count >= self.min_count]
        ranked.sort(key=lambda gram: (-counts[gram], gram))
        ranked = ranked[: self.max_features]
        self.vocab_ = {gram: index for index, gram in enumerate(ranked)}
        vocab_size = len(self.vocab_)
        rng = np.random.default_rng(self.seed)
        self.embeddings_ = rng.normal(0.0, 0.02, size=(vocab_size, self.dim)).astype(np.float64)
        self.weights_ = np.zeros(self.dim, dtype=np.float64)
        self.bias_ = 0.0
        encoded = [self._encode(grams) for grams in documents]
        order = np.arange(len(encoded))
        learning_rate = self.lr
        for _epoch in range(self.epochs):
            rng.shuffle(order)
            for index in order:
                ids, gram_counts = encoded[index]
                if len(ids) == 0:
                    continue
                total = float(gram_counts.sum())
                pooled = (self.embeddings_[ids] * gram_counts[:, None]).sum(axis=0) / total
                logit = float(pooled @ self.weights_ + self.bias_)
                probability = 1.0 / (1.0 + np.exp(-np.clip(logit, -20, 20)))
                error = (probability - labels[index]) * weights[index]
                # Embedding gradient uses the weights from before this step.
                previous_weights = self.weights_.copy()
                grad = error * pooled + self.l2 * self.weights_
                self.weights_ -= learning_rate * grad
                self.bias_ -= learning_rate * error
                token_grad = (gram_counts / total)[:, None] * (error * previous_weights)
                self.embeddings_[ids] -= learning_rate * token_grad
            learning_rate *= 0.85
        return self

    def _encode(self, grams: list[str]) -> tuple[np.ndarray, np.ndarray]:
        ids: list[int] = []
        for gram in grams:
            index = self.vocab_.get(gram)
            if index is not None:
                ids.append(index)
        if not ids:
            return np.zeros(0, dtype=np.int64), np.zeros(0, dtype=np.float64)
        array = np.asarray(ids, dtype=np.int64)
        unique, gram_counts = np.unique(array, return_counts=True)
        return unique, gram_counts.astype(np.float64)

    def predict_proba(self, texts: list[str]) -> np.ndarray:
        if not hasattr(self, "vocab_"):
            raise RuntimeError("Embedding model is not trained.")
        positives = np.zeros(len(texts), dtype=np.float64)
        for row, text in enumerate(texts):
            ids, gram_counts = self._encode(_ngrams(text))
            if len(ids) == 0:
                logit = self.bias_
            else:
                total = float(gram_counts.sum())
                pooled = (self.embeddings_[ids] * gram_counts[:, None]).sum(axis=0) / total
                logit = float(pooled @ self.weights_ + self.bias_)
            positives[row] = 1.0 / (1.0 + np.exp(-np.clip(logit, -20, 20)))
        return np.column_stack([1.0 - positives, positives])

    def predict(self, texts: list[str], threshold: float = 0.5) -> np.ndarray:
        return (self.predict_proba(texts)[:, 1] >= threshold).astype(int)
