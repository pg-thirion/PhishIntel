"""TF-IDF and logistic regression with exact additive log-odds explanations."""
import csv
from pathlib import Path
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline

DEMO_PATH = Path(__file__).resolve().parent.parent / "data" / "demo.csv"
LABELS = {"phishing": 1, "legitimate": 0}

def load_data(path):
    # Reject contradictory duplicates and avoid exact duplicates leaking across splits.
    rows = {}
    with open(path, encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        if not {"text", "label"}.issubset(reader.fieldnames or []):
            raise ValueError("CSV requires text and label columns.")
        for row in reader:
            body = (row["text"] or "").strip()[:100_000]
            label = (row["label"] or "").strip().lower()
            group = (row.get("group") or "").strip()
            if not body or label not in LABELS:
                raise ValueError("Every row needs text and a phishing or legitimate label.")
            key = " ".join(body.casefold().split())
            if key in rows:
                if rows[key][1] != LABELS[label]:
                    raise ValueError("Duplicate message has conflicting labels.")
                continue
            rows[key] = (body, LABELS[label], group)
    values = list(rows.values())
    if set(item[1] for item in values) != {0, 1}:
        raise ValueError("Both classes are required.")
    return [x[0] for x in values], [x[1] for x in values], [x[2] for x in values]

def fit_model(texts, labels):
    model = Pipeline([
        ("tfidf", TfidfVectorizer(ngram_range=(1, 2), sublinear_tf=True,
                                 strip_accents="unicode", max_features=50_000)),
        ("classifier", LogisticRegression(max_iter=1000, class_weight="balanced",
                                         random_state=42)),
    ])
    return model.fit(texts, labels)

def analyse(model, text, threshold=0.65):
    if not text.strip():
        raise ValueError("Enter a subject or message body.")
    if not 0.5 <= threshold <= 0.99:
        raise ValueError("Threshold must be between 0.50 and 0.99.")
    vectorizer = model.named_steps["tfidf"]
    classifier = model.named_steps["classifier"]
    vector = vectorizer.transform([text[:100_000]])
    weights = classifier.coef_[0]
    names = vectorizer.get_feature_names_out()
    terms = [{"term": str(names[i]), "contribution": float(v * weights[i])}
             for i, v in zip(vector.indices, vector.data)]
    score = float(classifier.predict_proba(vector)[0, 1])
    # No vocabulary overlap means a score based on intercept alone.
    if not terms:
        verdict = "Insufficient evidence"
    elif score >= threshold:
        verdict = "Likely phishing"
    elif score <= 1 - threshold:
        verdict = "Likely legitimate"
    else:
        verdict = "Needs review"
    return {"score": score, "verdict": verdict, "intercept": float(classifier.intercept_[0]),
            "log_odds": float(classifier.decision_function(vector)[0]),
            "matched_features": len(terms),
            "phishing_terms": sorted((t for t in terms if t["contribution"] > 0),
                                     key=lambda t: -t["contribution"])[:10],
            "legitimate_terms": sorted((t for t in terms if t["contribution"] < 0),
                                      key=lambda t: t["contribution"])[:10],
            "all_terms": terms}
