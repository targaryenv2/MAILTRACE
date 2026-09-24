"""TF-IDF vectoriser written out by hand.

Not because scikit-learn is unavailable on a normal machine, but because the
demo must run on a machine with nothing installed, and because a judge asking
"what does 3.2 mean" deserves an answer that is visible in this file.

Formulas (identical to scikit-learn's ``TfidfVectorizer`` with
``smooth_idf=True, sublinear_tf=True, norm='l2'``):

    tf(t, d)  = 1 + ln(count(t, d))            for count > 0
    idf(t)    = ln((1 + N) / (1 + df(t))) + 1
    w(t, d)   = tf * idf,   then  d <- d / ||d||_2

Smoothing the idf denominator keeps a term that appears in every document at
weight 1 rather than 0, and the +1 prevents division by zero for unseen terms.
Sublinear tf stops a spam message that repeats "urgent" forty times from
swamping every other term. The L2 normalisation makes the score independent of
message length, which matters because phishing mail is usually short.

Engineered indicators from ``features.meta`` are appended *after* normalisation
and multiplied by ``meta_scale``, so a header fact keeps a stable magnitude
instead of shrinking as the body gets longer.
"""

from __future__ import annotations

import math
from collections import Counter
from typing import Dict, List, Tuple

from .features import META_KEYS, meta, tokenise


class FeatureSpace:
    """Fit once on the training corpus, then transform documents to sparse dicts."""

    def __init__(self, max_features: int = 4000, min_df: int = 2,
                 max_df_ratio: float = 0.85, ngram: int = 2,
                 sublinear_tf: bool = True, meta_scale: float = 0.6) -> None:
        self.max_features = max_features
        self.min_df = min_df
        self.max_df_ratio = max_df_ratio
        self.ngram = ngram
        self.sublinear_tf = sublinear_tf
        self.meta_scale = meta_scale
        self.vocab: Dict[str, int] = {}
        self.idf: List[float] = []
        self.n_docs = 0

    # -- fit ---------------------------------------------------------------

    def fit(self, docs: List[str]) -> "FeatureSpace":
        n = len(docs)
        self.n_docs = n
        df: Counter = Counter()
        for d in docs:
            df.update(set(tokenise(d, self.ngram)))
        ceiling = max(1, int(self.max_df_ratio * n))
        kept = [(t, c)
                for t, c in df.items() if c >= self.min_df and c <= ceiling]
        # Sort by document frequency then alphabetically: deterministic vocabulary
        # regardless of dict iteration order, which keeps the saved model
        # stable.
        kept.sort(key=lambda tc: (-tc[1], tc[0]))
        kept = kept[: self.max_features]
        self.vocab = {t: i for i, (t, _) in enumerate(kept)}
        self.idf = [math.log((1.0 + n) / (1.0 + c)) + 1.0 for _, c in kept]
        return self

    # -- transform ---------------------------------------------------------

    @property
    def n_text(self) -> int:
        return len(self.vocab)

    @property
    def dim(self) -> int:
        return len(self.vocab) + len(META_KEYS)

    def transform_text(self, doc: str) -> Dict[int, float]:
        counts: Counter = Counter(
            t for t in tokenise(
                doc, self.ngram) if t in self.vocab)
        vec: Dict[int, float] = {}
        for term, c in counts.items():
            j = self.vocab[term]
            tf = (1.0 + math.log(c)) if self.sublinear_tf else float(c)
            vec[j] = tf * self.idf[j]
        norm = math.sqrt(sum(x * x for x in vec.values()))
        if norm > 0:
            for j in vec:
                vec[j] /= norm
        return vec

    def transform(self,
                  doc: str,
                  meta_values: Dict[str,
                                    float]) -> Dict[int,
                                                    float]:
        vec = self.transform_text(doc)
        base = self.n_text
        for k, key in enumerate(META_KEYS):
            val = float(meta_values.get(key, 0.0))
            if val:
                vec[base + k] = val * self.meta_scale
        return vec

    def transform_email(self, parsed) -> Dict[int, float]:
        from .features import document

        return self.transform(document(parsed), meta(parsed))

    # -- names / persistence ----------------------------------------------

    def names(self) -> List[str]:
        out = [""] * self.dim
        for term, j in self.vocab.items():
            out[j] = term
        for k, key in enumerate(META_KEYS):
            out[self.n_text + k] = key
        return out

    def to_dict(self) -> Dict:
        terms = [""] * len(self.vocab)
        for t, j in self.vocab.items():
            terms[j] = t
        return {
            "terms": terms, "idf": [round(x, 6) for x in self.idf],
            "meta_keys": list(META_KEYS), "meta_scale": self.meta_scale,
            "ngram": self.ngram, "sublinear_tf": self.sublinear_tf,
            "min_df": self.min_df, "max_features": self.max_features,
            "max_df_ratio": self.max_df_ratio, "n_docs": self.n_docs,
        }

    @classmethod
    def from_dict(cls, d: Dict) -> "FeatureSpace":
        fs = cls(max_features=int(d.get("max_features", 4000)),
                 min_df=int(d.get("min_df", 2)),
                 max_df_ratio=float(d.get("max_df_ratio", 0.85)),
                 ngram=int(d.get("ngram", 2)),
                 sublinear_tf=bool(d.get("sublinear_tf", True)),
                 meta_scale=float(d.get("meta_scale", 0.6)))
        fs.vocab = {t: i for i, t in enumerate(d.get("terms", []))}
        fs.idf = [float(x) for x in d.get("idf", [])]
        fs.n_docs = int(d.get("n_docs", 0))
        return fs


def build(docs: List[str], metas: List[Dict[str, float]], **kw
          ) -> Tuple[FeatureSpace, List[Dict[int, float]]]:
    """Convenience: fit a space and return the training design matrix."""
    fs = FeatureSpace(**kw).fit(docs)
    return fs, [fs.transform(d, m) for d, m in zip(docs, metas)]
