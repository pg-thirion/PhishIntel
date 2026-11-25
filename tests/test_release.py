import json
import math
import pytest
from fastapi.testclient import TestClient
from phishintel.model import DEMO_PATH, load_data, fit_model
from phishintel.release import ReleasedModel, digest, load_release, train_release
from phishintel.api import create_app

@pytest.fixture
def artifact(tmp_path):
    x,y,_ = load_data(DEMO_PATH)
    model = fit_model(x,y)
    v,c = model.named_steps["tfidf"],model.named_steps["classifier"]
    # Fabricated acceptance metadata ONLY for testing serialization/API mechanics.
    m = {"legitimate": 100, "phishing": 100, "precision": .95, "recall": .9,
         "roc_auc": .95, "average_precision": .95, "unsafe_clearance_rate": .01, "review_rate": .2}
    payload = {"schema": 1, "threshold": .65, "validation_metrics": m, "test_metrics": m,
               "terms": v.get_feature_names_out().tolist(), "idf": v.idf_.tolist(),
               "weights": c.coef_[0].tolist(), "intercept": float(c.intercept_[0])}
    raw = json.dumps(payload).encode()
    path = tmp_path / "test.json"
    path.write_bytes(raw)
    return path, digest(raw), model, payload

def test_release_equivalence(artifact):
    path,sha,model,_ = artifact
    release = load_release(path,sha)
    for text in ["Confirm your password immediately", "Team meeting next week", "zzxxvv",
                 "password password password", "Café team meeting"]:
        assert math.isclose(release.analyse(text)["score"],
                            model.predict_proba([text])[0,1], abs_tol=1e-10)

def test_bad_digest(artifact):
    with pytest.raises(ValueError):
        load_release(artifact[0], "0"*64)

def test_reject_nonfinite(artifact):
    payload = artifact[3]
    payload["weights"][0] = float("nan")
    with pytest.raises(ValueError):
        ReleasedModel(payload, artifact[1])

def test_reject_gate(artifact):
    payload = artifact[3]
    payload["test_metrics"]["precision"] = .4
    with pytest.raises(ValueError):
        ReleasedModel(payload, artifact[1])

def test_demo_cannot_train_release(tmp_path):
    with pytest.raises(ValueError):
        train_release(DEMO_PATH, tmp_path / "release.json", "demo")

def test_api(artifact, monkeypatch):
    key = "a"*40
    monkeypatch.setenv("PHISHINTEL_API_KEY", key)
    monkeypatch.setenv("PHISHINTEL_MODEL", str(artifact[0]))
    monkeypatch.setenv("PHISHINTEL_MODEL_SHA256", artifact[1])
    headers = {"Authorization": "Bearer " + key, "Content-Type": "text/plain"}
    with TestClient(create_app()) as client:
        assert client.get("/readyz").status_code == 200
        assert client.post("/v1/analyse", content="test").status_code == 401
        response = client.post("/v1/analyse", content="Verify your password", headers=headers)
        assert response.status_code == 200
        assert response.headers["cache-control"] == "no-store"
        assert response.json()["model_sha256"] == artifact[1]
        assert client.post("/v1/analyse", content=b"x"*(1024*1024+1), headers=headers).status_code == 413
        assert client.post("/v1/analyse", content=b"\xff", headers=headers).status_code == 422
        assert client.post("/v1/analyse", content=" ", headers=headers).status_code == 422

def test_api_refuses_weak_key(monkeypatch):
    monkeypatch.setenv("PHISHINTEL_API_KEY", "weak")
    with pytest.raises(RuntimeError):
        with TestClient(create_app()):
            pass

def test_full_training_release(tmp_path):
    import csv
    path = tmp_path / "synthetic_grouped.csv"
    with path.open("w", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["text", "label", "group"])
        # Artificially separable fixture, not a phishing benchmark.
        for group in range(10):
            for i in range(100):
                writer.writerow([f"verify password credential urgent account verify password unique {group} {i}", "phishing", f"g{group}"])
                writer.writerow([f"meeting lunch project planning colleague meeting lunch unique {group} {i}", "legitimate", f"g{group}"])
    target = tmp_path / "release.json"
    report = train_release(path, target, "synthetic-test-fixture")
    released = load_release(target, report["sha256"])
    assert released.analyse("verify password credential urgent")["score"] > .65
    assert released.analyse("meeting lunch project planning")["score"] < .35
    assert released.analyse("zzxxvv")["verdict"] == "Insufficient evidence"
    assert len(json.loads(target.read_bytes())["dataset_sha256"]) == 64

def test_unknown_features_not_counted_as_clearance_or_detection():
    from phishintel.release import metrics
    result = metrics([0, 1], [.1, .1], .65, [True, False])
    assert result["unsafe_clearance_rate"] == 0
    assert result["review_rate"] == .5
    assert result["recall"] == 0
