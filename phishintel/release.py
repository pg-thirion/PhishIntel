"""Offline training and safe, non-executable JSON model releases."""
import argparse
from collections import Counter
import hashlib
import json
import math
import os
from pathlib import Path
import re
import tempfile

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import average_precision_score, precision_score, recall_score, roc_auc_score
from sklearn.model_selection import StratifiedGroupKFold
from .model import fit_model, load_data

SCHEMA = 1
MAX_ARTIFACT = 16 * 1024 * 1024
MAX_FEATURES = 50_000
MIN_CLASS_PER_SPLIT = 100

def digest(raw):
    return hashlib.sha256(raw).hexdigest()

def finite(value):
    return type(value) in (float, int) and math.isfinite(value)

class ReleasedModel:
    """JSON parameters only; no pickle, joblib or executable deserialisation."""
    def __init__(self, payload, fingerprint):
        if payload.get("schema") != SCHEMA:
            raise ValueError("Unsupported model schema")
        self.fingerprint = fingerprint
        self.threshold = payload["threshold"]
        self.intercept = payload["intercept"]
        self.metrics = payload["test_metrics"]
        self.terms = payload["terms"]
        self.idf = payload["idf"]
        self.weights = payload["weights"]
        n = len(self.terms)
        if not 1 <= n <= MAX_FEATURES or len(self.idf) != n or len(self.weights) != n:
            raise ValueError("Invalid feature dimensions")
        if any(type(t) is not str or not t or len(t) > 200_000 for t in self.terms):
            raise ValueError("Invalid feature")
        if len(set(self.terms)) != n or not all(finite(v) and 1 <= v <= 100 for v in self.idf):
            raise ValueError("Invalid vocabulary or IDF")
        if not all(finite(v) and abs(v) <= 1000 for v in self.weights + [self.intercept]):
            raise ValueError("Invalid coefficient")
        if not finite(self.threshold) or not 0.5 <= self.threshold <= 0.99:
            raise ValueError("Invalid threshold")
        if not gate(self.metrics) or not gate(payload["validation_metrics"]):
            raise ValueError("Release metrics do not meet acceptance policy")
        self.vocabulary = {term: i for i, term in enumerate(self.terms)}
        self.analyzer = TfidfVectorizer(ngram_range=(1, 2), strip_accents="unicode").build_analyzer()

    def analyse(self, text):
        if not text.strip() or len(text) > 100_000:
            raise ValueError("Provide 1 to 100,000 text characters")
        counts = Counter(self.vocabulary[t] for t in self.analyzer(text) if t in self.vocabulary)
        values = {i: (1 + math.log(c)) * self.idf[i] for i, c in counts.items()}
        norm = math.sqrt(sum(v*v for v in values.values()))
        terms = [{"term": self.terms[i], "contribution": v / norm * self.weights[i]}
                 for i, v in values.items()] if norm else []
        log_odds = self.intercept + math.fsum(t["contribution"] for t in terms)
        score = 1 / (1 + math.exp(-max(-700, min(700, log_odds))))
        verdict = ("Insufficient evidence" if not terms else
                   "Likely phishing" if score >= self.threshold else
                   "Likely legitimate" if score <= 1 - self.threshold else "Needs review")
        return {"score": score, "verdict": verdict, "matched_features": len(terms),
                "intercept": self.intercept, "log_odds": log_odds,
                "phishing_terms": sorted((t for t in terms if t["contribution"] > 0),
                                         key=lambda t: -t["contribution"])[:10],
                "legitimate_terms": sorted((t for t in terms if t["contribution"] < 0),
                                           key=lambda t: t["contribution"])[:10]}

def load_release(path, expected_sha256):
    if not re.fullmatch(r"[a-f0-9]{64}", expected_sha256 or ""):
        raise ValueError("A trusted SHA-256 digest is required")
    with open(path, "rb") as handle:
        raw = handle.read(MAX_ARTIFACT + 1)
    if len(raw) > MAX_ARTIFACT or digest(raw) != expected_sha256:
        raise ValueError("Release size or integrity check failed")
    try:
        return ReleasedModel(json.loads(raw), expected_sha256)
    except (KeyError, TypeError, OverflowError, RecursionError) as exc:
        raise ValueError("Invalid release structure") from exc

def metrics(labels, scores, threshold, recognised):
    predictions = [int(known and s >= threshold) for s,known in zip(scores,recognised)]
    counts = Counter(labels)
    return {"legitimate": counts[0], "phishing": counts[1],
            "precision": float(precision_score(labels, predictions, zero_division=0)),
            "recall": float(recall_score(labels, predictions, zero_division=0)),
            "roc_auc": float(roc_auc_score(labels, scores)),
            "average_precision": float(average_precision_score(labels, scores)),
            "unsafe_clearance_rate": sum(y == 1 and known and s <= 1-threshold for y,s,known in zip(labels,scores,recognised))/counts[1],
            "review_rate": sum(not known or 1-threshold < s < threshold for s,known in zip(scores,recognised))/len(labels)}

def gate(m):
    return (isinstance(m, dict)
            and all(type(m.get(k)) is int and m[k] >= MIN_CLASS_PER_SPLIT
                    for k in ("legitimate", "phishing"))
            and all(finite(m.get(k)) and 0 <= m[k] <= 1 for k in
                    ("precision", "recall", "roc_auc", "average_precision", "unsafe_clearance_rate", "review_rate"))
            and m["precision"] >= .90 and m["recall"] >= .80
            and m["roc_auc"] >= .90 and m["unsafe_clearance_rate"] <= .05)

def train_release(source, target, dataset_id, threshold=.65):
    if not dataset_id.strip() or not .5 <= threshold <= .99:
        raise ValueError("Dataset provenance and a valid threshold are required")
    def file_digest():
        with open(source, "rb") as handle:
            return hashlib.file_digest(handle, "sha256").hexdigest()
    source_hash = file_digest()
    texts, labels, groups = load_data(source)
    if file_digest() != source_hash:
        raise ValueError("Dataset changed during training input load")
    if not all(groups) or len(set(groups)) < 5:
        raise ValueError("At least five independent campaign/thread groups are required")
    # Independent partitions, chosen without inspecting model performance.
    folds = list(StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=42).split(texts, labels, groups))
    test, validation = list(folds[0][1]), list(folds[1][1])
    held = set(test) | set(validation)
    train = [i for i in range(len(texts)) if i not in held]
    partitions = [train, validation, test]
    group_sets = [set(groups[i] for i in indices) for indices in partitions]
    if any(group_sets[i] & group_sets[j] for i in range(3) for j in range(i)):
        raise ValueError("Group leakage detected")
    if any(min(Counter(labels[i] for i in indices).get(c, 0) for c in (0,1)) < MIN_CLASS_PER_SPLIT
           for indices in partitions):
        raise ValueError("Each partition requires at least 100 examples per class")
    model = fit_model([texts[i] for i in train], [labels[i] for i in train])
    def evaluate(indices):
        inputs = [texts[i] for i in indices]
        vectors = model.named_steps["tfidf"].transform(inputs)
        recognised = vectors.getnnz(axis=1) > 0
        return metrics([labels[i] for i in indices],
                       model.named_steps["classifier"].predict_proba(vectors)[:, 1], threshold, recognised)
    val = evaluate(validation)
    if not gate(val):
        raise ValueError("Validation gate failed: " + json.dumps(val))
    test_result = evaluate(test)
    if not gate(test_result):
        raise ValueError("Independent test gate failed: " + json.dumps(test_result))
    v, c = model.named_steps["tfidf"], model.named_steps["classifier"]
    payload = {"schema": SCHEMA, "dataset_id": dataset_id, "threshold": threshold,
               "train_count": len(train), "dataset_sha256": source_hash, "validation_metrics": val, "test_metrics": test_result,
               "terms": v.get_feature_names_out().tolist(), "idf": v.idf_.tolist(),
               "weights": c.coef_[0].tolist(), "intercept": float(c.intercept_[0])}
    raw = json.dumps(payload, ensure_ascii=True, allow_nan=False, separators=(",", ":")).encode()
    if len(raw) > MAX_ARTIFACT:
        raise ValueError("Model exceeds release size limit")
    # Verify numerical equivalence before publishing.
    fingerprint = digest(raw)
    loaded = ReleasedModel(payload, fingerprint)
    for i in test[:100]:
        if not math.isclose(loaded.analyse(texts[i])["score"],
                            model.predict_proba([texts[i]])[0,1], abs_tol=1e-10):
            raise ValueError("Exported model does not match training implementation")
    target = Path(target)
    target.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=target.parent, delete=False) as handle:
        tmp = Path(handle.name)
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())
    try:
        os.link(tmp, target)  # atomic publication; never overwrite an existing release
    finally:
        tmp.unlink(missing_ok=True)
    return {"sha256": fingerprint, "validation": val, "test": test_result}

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dataset")
    parser.add_argument("output")
    parser.add_argument("--dataset-id", required=True)
    parser.add_argument("--threshold", type=float, default=.65)
    args = parser.parse_args()
    print(json.dumps(train_release(args.dataset, args.output, args.dataset_id, args.threshold), indent=2))
