# Production deployment and release checklist

## Before release

1. Obtain authorised, representative and de-identified email samples. Establish provenance, retention limits and consent/legal basis. Keep source data and the model vocabulary private.
2. Assign related campaigns, threads and near-duplicates to the same group. Freeze a chronological independent evaluation set as an additional external check. The built-in group split is not chronological.
3. Review thresholds against business costs and validate by department, language, campaign type and time period. Measure false negatives, false positives, abstention and calibration. The default gate is a minimum demonstration policy.
4. Train offline using phishintel.release. Retain immutable dataset and code versions, evaluation report and SHA-256. Independently approve and provision the digest through protected configuration. A digest does not authenticate a malicious release producer.
5. Require green CI, dependency review, penetration testing and sign-off. Generate a platform-specific hash-locked dependency file, SBOM, and signed image in the organisation's release pipeline. Current dependency ranges and container tag are development inputs, not a reproducible production lock.
6. Verify runtime output parity with offline model. Run shadow-mode trials and capacity tests on expected message traffic. Do not auto-quarantine or approve mail.

## Runtime

Build: docker build -t phishintel:local .

Supply a read-only mounted model directory and protected environment configuration (PHISHINTEL_MODEL=/models/model.json, PHISHINTEL_MODEL_SHA256, PHISHINTEL_API_KEY). Ensure UID 10001 can read the artifact. Do not include credentials or models in the image. Example runtime flags: --read-only --tmpfs /tmp:rw,noexec,nosuid,size=64m --cap-drop ALL --security-opt no-new-privileges --memory 512m --cpus 1 --pids-limit 64. Bind the published port to localhost or a private gateway. Enforce TLS, client-specific identity, rate limits, request size and network policy at the gateway; disable outbound internet access for inference. Health probes should be restricted to the private network.

Rotate credentials using the secret manager and restart instances with the new key. Use one key per isolated deployment or enforce client identity at the gateway. Restrict access to response explanations, which can include sensitive terms. Disable gateway request/response logging and tracing payload capture.

Monitor request counts, latency, failures, 429s, score distribution and drift without logging email contents. Audit model fingerprints and access metadata under an approved retention policy. Alert on gate failure, drift, availability and unusual traffic. Test rollback by deploying the previous approved image and artifact digest. The API intentionally does not include a tenant database, durable audit store, external reputation lookups, automatic response or monitoring backend.

## Threat boundaries

Inputs are hostile. MIME limits, authenticated access, bounded concurrency, streamed size checks, non-executable serialization, no remote fetching and a non-root container reduce exposure. They do not replace sandboxing, network controls, resource limits or independent security testing. Headers such as Authentication-Results are untrusted unless validated by the receiving gateway. Attachment extensions and URL indicators are heuristics, not malware scanning. A low model score does not establish safety.

The release records the input CSV SHA-256. Acceptance metrics count unrecognised vocabulary as review, matching serving behaviour. The training fixture in CI is synthetic and is not evidence of real-world accuracy.
