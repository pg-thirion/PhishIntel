import math
import pytest
from phishintel.email import Email, parse_eml, indicators, MAX_BYTES
from phishintel.model import DEMO_PATH, load_data, fit_model, analyse
from phishintel.evaluate import evaluate

@pytest.fixture(scope="module")
def model():
    x, y, _ = load_data(DEMO_PATH)
    return fit_model(x, y)

def test_exact_explanation(model):
    result = analyse(model, "Urgent verification of your account password")
    assert math.isclose(result["intercept"] + sum(t["contribution"] for t in result["all_terms"]),
                        result["log_odds"], abs_tol=1e-9)
    assert math.isclose(1 / (1 + math.exp(-result["log_odds"])), result["score"])

def test_relative_score(model):
    bad = analyse(model, "Verify your account immediately. Confirm your password.")
    good = analyse(model, "The weekly team meeting is on Thursday.")
    assert bad["score"] > good["score"]

def test_unknown_text(model):
    assert analyse(model, "zzzzqxxvvv")["verdict"] == "Insufficient evidence"

def test_empty(model):
    with pytest.raises(ValueError):
        analyse(model, " ")

def test_html_parsing():
    raw = b"Subject: test\r\nContent-Type: text/html\r\n\r\n<p>Hello</p><script>secret</script><a href='http://192.0.2.1'>link</a>"
    email = parse_eml(raw)
    assert "Hello" in email.body
    assert "secret" not in email.body
    assert "http://192.0.2.1" in email.links
    assert any(x["indicator"] == "IP address used as link host" for x in indicators(email))

def test_reply_to():
    email = Email(sender="Alice <alice@example.org>", reply_to="bob@example.net")
    assert indicators(email)[0]["indicator"] == "Reply-To domain differs"

def test_oversize():
    with pytest.raises(ValueError):
        parse_eml(b"x" * (MAX_BYTES + 1))

def test_invalid_csv(tmp_path):
    path = tmp_path / "test.csv"
    path.write_text("text,label\nhello,phishing\nHELLO,legitimate\n")
    with pytest.raises(ValueError):
        load_data(path)

def test_evaluation():
    report = evaluate(DEMO_PATH)
    assert report["train_count"] + report["test_count"] == 32
    assert 0 <= report["roc_auc"] <= 1
    assert sum(map(sum, report["confusion_matrix"])) == report["test_count"]

def test_attached_email_is_not_main_body():
    raw = (b"Subject: outer\r\nContent-Type: multipart/mixed; boundary=x\r\n\r\n"
           b"--x\r\nContent-Type: text/plain\r\n\r\nHello team\r\n"
           b"--x\r\nContent-Type: message/rfc822\r\nContent-Disposition: attachment\r\n\r\n"
           b"Subject: inner\r\n\r\nNested secret\r\n--x--\r\n")
    result = parse_eml(raw)
    assert "Hello team" in result.body
    assert "Nested secret" not in result.body

def test_mime_part_limit():
    raw = (b"Content-Type: multipart/mixed; boundary=x\r\n\r\n" +
           b"--x\r\nContent-Type: text/plain\r\n\r\nhello\r\n"*201 + b"--x--\r\n")
    with pytest.raises(ValueError):
        parse_eml(raw)
