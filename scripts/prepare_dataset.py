"""Convert a locally downloaded body/label CSV into PhishIntel format.

Suggested source: https://doi.org/10.5281/zenodo.17314806
Review the dataset licence, provenance and privacy before use.
No network requests are made and original text is not printed.
"""
import argparse
import csv
from pathlib import Path

def convert(source, destination):
    if source.resolve() == destination.resolve():
        raise ValueError("Source and destination must be different.")
    csv.field_size_limit(10_000_000)
    destination.parent.mkdir(parents=True, exist_ok=True)
    count = skipped = 0
    with source.open(encoding="utf-8-sig", newline="") as src:
        reader = csv.DictReader(src)
        if not {"body", "label"}.issubset(reader.fieldnames or []):
            raise ValueError("Expected body and label columns.")
        with destination.open("x", encoding="utf-8", newline="") as dst:
            writer = csv.DictWriter(dst, fieldnames=["text", "label"])
            writer.writeheader()
            for row in reader:
                body = (row["body"] or "").strip()
                label = (row["label"] or "").strip()
                if not body or label not in {"0", "1"}:
                    skipped += 1
                    continue
                writer.writerow({"text": body[:100_000],
                                 "label": "phishing" if label == "1" else "legitimate"})
                count += 1
    return count, skipped

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    count, skipped = convert(args.source, args.destination)
    print(f"Converted {count} rows; skipped {skipped}.")
