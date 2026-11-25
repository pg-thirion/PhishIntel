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

## Production inference (separate from the demo UI)

The API will not train on startup or accept the bundled demonstration model. It requires a release produced offline using a labelled, group-aware dataset, an independently provisioned SHA-256 digest and an API key of at least 32 characters. The digest verifies integrity against a trusted deployment value, not the provenance of an untrusted artifact.

```bash
python -m phishintel.release data/private/grouped.csv artifacts/model.json --dataset-id "approved-corpus-v1"
# Record the emitted SHA-256 in protected deployment configuration.
# Set PHISHINTEL_MODEL, PHISHINTEL_MODEL_SHA256 and PHISHINTEL_API_KEY.
python -m uvicorn phishintel.api:app --host 127.0.0.1 --port 8080 --no-access-log
```

The release gate uses campaign-disjoint train, validation and test partitions, each with at least 100 samples per class. Default acceptance policy: precision >= 90%, recall >= 80%, ROC AUC >= 90%, phishing incorrectly cleared <= 5%. These are proposed engineering minimums, not measured results or an organisation-approved risk policy. Freeze the threshold before independent evaluation; do not repeatedly tune against the held-out test set. Uncalibrated scores must not be treated as probabilities. The public two-column corpus converter does not supply group IDs and therefore cannot alone qualify a production release.

POST /v1/analyse accepts UTF-8 text/plain or message/rfc822, with Authorization: Bearer <key>. Maximum request size 1 MiB. Responses contain model fingerprint, verdict, signed feature contributions and independent security indicators. No raw email logging, remote link access or attachment execution. Health endpoints are /healthz and /readyz. The API is designed for a private network behind an authenticated TLS gateway with per-client rate limiting.

See [deployment runbook](docs/production.md) and [security policy](SECURITY.md). The Streamlit UI remains a local demonstration interface; do not expose it as a production multi-user service.

## Extended offline evidence and triage

The API and local UI now share a deterministic evidence layer, independent of the model score. It detects HTML forms/password fields/remote images/tracking pixels/active or hidden HTML/misleading anchor text; missing or duplicate sender headers and envelope mismatch; shortened URLs, deep subdomains, unusual ports, encoded authorities and redirect parameters; policy watchlist matches and one-edit protected-domain lookalikes; bidirectional filename controls, deceptive double extensions, archives, HTML and macro documents, attached messages; urgency, credential, banking and gift-card language. These are heuristic observations, not verified attacks.

Set PHISHINTEL_POLICY to a local JSON file with optional watched and protected arrays (see config/policy.example.json). Entries match whole domains or subdomains. The lookalike check is deliberately limited to a single insertion, deletion or substitution. Do not put real customer indicators into the public repository.

API responses include defanged domain inventory, bounded link and attachment counts, independent rule codes, analyst priority, and a metadata-only summary excluding raw messages, domains and explanation terms. The Streamlit UI supports downloading that summary. No content is fetched, executed, or automatically cleared. Exported metadata can still be sensitive in context; apply your retention rules.
