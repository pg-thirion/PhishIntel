"""Evaluate a labelled CSV on held-out messages; never fit on the test fold."""
import argparse
import json
from collections import Counter
from sklearn.model_selection import train_test_split, StratifiedGroupKFold
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score, average_precision_score
from .model import load_data, fit_model, DEMO_PATH

def evaluate(path, threshold=0.65):
    if not 0.5 <= threshold <= 0.99:
        raise ValueError("Invalid threshold")
    texts, labels, groups = load_data(path)
    if min(Counter(labels).values()) < 5:
        raise ValueError("At least five unique messages per class are needed.")
    if any(groups):
        if not all(groups):
            raise ValueError("Provide a group for every message or leave all blank.")
        splitter = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=42)
        train, test = next(splitter.split(texts, labels, groups))
        strategy = "group-disjoint holdout"
    else:
        train, test = train_test_split(range(len(labels)), test_size=0.25,
                                       stratify=labels, random_state=42)
        strategy = "stratified random holdout"
    y_train, y_test = [labels[i] for i in train], [labels[i] for i in test]
    if len(set(y_train)) < 2 or len(set(y_test)) < 2:
        raise ValueError("Both classes must occur in each split. Supply more diverse groups.")
    model = fit_model([texts[i] for i in train], y_train)
    scores = model.predict_proba([texts[i] for i in test])[:, 1]
    predictions = (scores >= threshold).astype(int)
    return {"split": strategy, "train_count": len(train), "test_count": len(test),
            "threshold": threshold, "demo_data": str(path) == str(DEMO_PATH),
            "roc_auc": roc_auc_score(y_test, scores),
            "average_precision": average_precision_score(y_test, scores),
            "confusion_matrix": confusion_matrix(y_test, predictions, labels=[0, 1]).tolist(),
            "classification_report": classification_report(y_test, predictions, labels=[0, 1],
                target_names=["legitimate", "phishing"], output_dict=True, zero_division=0)}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("csv", nargs="?", default=str(DEMO_PATH))
    parser.add_argument("--threshold", type=float, default=0.65)
    args = parser.parse_args()
    print(json.dumps(evaluate(args.csv, args.threshold), indent=2))

if __name__ == "__main__":
    main()
