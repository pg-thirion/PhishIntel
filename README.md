# PhishIntel

Explainable machine-learning phishing email triage. A local-first portfolio prototype for security analysts.

## What it does

- Analyse pasted email subjects and bodies or upload an RFC 5322 .eml file.
- Classify message text with TF-IDF word/bigram features and logistic regression.
- Show the strongest positive and negative feature contributions, the model score and a configurable review band.
- Independently flag Reply-To mismatches, IP-based and internationalised URLs, HTTP links, risky attachment extensions and reported authentication failures.
- Parse HTML without rendering it or opening remote resources. No external inference API, persistent email storage or attachment execution.
- Evaluate a labelled dataset with held-out precision, recall, F1, ROC AUC, average precision and a confusion matrix.

## Run locally

Use Python 3.11 or 3.12.

```bash
python -m venv .venv
# Windows PowerShell: .venv\Scripts\Activate.ps1
# Linux/macOS: source .venv/bin/activate
python -m pip install -r requirements.txt
python -m streamlit run app.py
```

Open http://127.0.0.1:8501. Streamlit binds to localhost by default and telemetry is disabled. Do not expose the application publicly without authentication, transport security and an appropriate data-handling review.

## Train on real labelled data

The bundled CSV contains **32 original synthetic examples** and is intended only to demonstrate the UI and pipeline. It is not a representative phishing corpus. Do not interpret its evaluation as real-world detection accuracy.

Supply a permitted, de-identified CSV with columns `text,label` and optionally `group`. Labels must be `phishing` or `legitimate`. Combine subject and body in the text column. Group related campaigns, threads, templates or senders to reduce leakage.

```csv
text,label,group
"Example message for model training",legitimate,thread-001
"Example suspicious message for training",phishing,campaign-001
```

Set the environment variable PHISHINTEL_DATA to the local CSV path before starting Streamlit. Use data/private/ for sensitive local datasets, which is ignored by Git. The application trains at startup and does not load untrusted pickle files.

```bash
python -m phishintel.evaluate data/private/messages.csv
python -m pytest -q
```

The evaluation fits on the training fold only. Exact normalised duplicates are removed and conflicting labels rejected. With a complete group column it uses a group-disjoint holdout. Otherwise it uses a stratified random split, which can overstate performance when related messages occur on both sides. The evaluation threshold is a binary phishing/not-phishing threshold; the UI additionally abstains on uncertain scores. Choose thresholds and calibrate on validation data before evaluating on a final independent test set. A chronological, campaign-disjoint test set is recommended for deployment.

## Explainability

For each active feature, the displayed signed contribution equals its TF-IDF value times its learned logistic regression coefficient. The intercept plus all contributions equals the decision log-odds. The logistic function converts this to the model score. These are exact model-specific explanations, not causal evidence. Scores are not calibrated.

The heuristic observations are intentionally separate from the model. Authentication-Results headers can be forged and need verification at the trusted mail gateway. Attachment types are only metadata, not malware analysis. An empty indicator list or low score does not prove that a message is safe.

## Limitations and roadmap

This is an English-language experimental tool, not a production filter. It does not resolve URLs, detect all obfuscations, scan files, verify authentication cryptographically or inspect encrypted archives. There is no live threat intelligence, real-world benchmark, automatic quarantine or multi-user access control. Next steps include representative licensed corpora, campaign/time-aware validation, probability calibration, multilingual coverage and an isolated gateway integration.

## Public research dataset option

The [Phishing-Email-Detection-Dataset](https://doi.org/10.5281/zenodo.17314806) by Alhuzali, Alloqmani, Aljabri and Alharbi (2025) provides a merged and balanced corpus. Review its CC BY 4.0 licence and underlying corpus terms before use. The balanced CSV is approximately 359 MB. Download it manually to data/private/ and convert its body/label schema:

```bash
python scripts/prepare_dataset.py data/private/Balanced_Dataset.csv data/private/messages.csv
python -m phishintel.evaluate data/private/messages.csv
```

Then set PHISHINTEL_DATA to data/private/messages.csv and launch the app. This conversion discards source grouping because the published two-column format lacks campaign IDs. Its random holdout is a preliminary benchmark only. No external corpus is redistributed in this repository, and no results on that corpus are claimed.

GitHub Actions runs the unit tests and synthetic smoke evaluation on Python 3.11 and 3.12.
