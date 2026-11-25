"""Streamlit smoke checks. CI installs Streamlit; offline core-only runs skip this module."""
import pytest

pytest.importorskip("streamlit")
from streamlit.testing.v1 import AppTest
from phishintel.model import DEMO_PATH

def test_ui_analysis(monkeypatch):
    monkeypatch.setenv("PHISHINTEL_DATA", str(DEMO_PATH))
    monkeypatch.delenv("PHISHINTEL_POLICY", raising=False)
    app = AppTest.from_file("app.py", default_timeout=30).run()
    assert not app.exception
    app.text_input[0].set_value("analyst@example.org")
    app.text_input[2].set_value("Urgent")
    app.text_area[0].set_value("Confirm your password immediately.")
    app.button[0].click().run()
    assert not app.exception
    labels = {metric.label for metric in app.metric}
    assert {"Model verdict", "Phishing model score", "Analyst priority"} <= labels

def test_ui_empty_input(monkeypatch):
    monkeypatch.setenv("PHISHINTEL_DATA", str(DEMO_PATH))
    app = AppTest.from_file("app.py", default_timeout=30).run()
    app.button[0].click().run()
    assert not app.exception
    assert any("Unable to analyse" in error.value for error in app.error)
