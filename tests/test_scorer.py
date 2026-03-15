import pytest
import pandas as pd
from core.scorer import compute_scores, assign_priority_band
from config import DEFAULT_WEIGHTS, TIER_DEFAULTS


def test_assign_priority_band():
    assert assign_priority_band(0.80) == "Critical"
    assert assign_priority_band(0.75) == "Critical"
    assert assign_priority_band(0.60) == "High"
    assert assign_priority_band(0.55) == "High"
    assert assign_priority_band(0.40) == "Medium"
    assert assign_priority_band(0.35) == "Medium"
    assert assign_priority_band(0.30) == "Low"
    assert assign_priority_band(0.00) == "Low"


def test_compute_scores_basic():
    df = pd.DataFrame([
        {"cve_id": "CVE-2021-44228", "asset_exposure": "internet-facing",
         "cvss_v3": 10.0, "epss": 0.97, "published_date": "2021-11-26T00:00:00.000"},
    ])
    result = compute_scores(df)
    assert "composite_score" in result.columns
    assert "priority_band" in result.columns
    assert result.iloc[0]["composite_score"] > 0.7  # Log4Shell should be high


def test_compute_scores_missing_data():
    df = pd.DataFrame([
        {"cve_id": "CVE-2099-00001"},
    ])
    result = compute_scores(df)
    assert result.iloc[0]["composite_score"] >= 0.0


def test_compute_scores_sorting():
    df = pd.DataFrame([
        {"cve_id": "CVE-A", "cvss_v3": 2.0, "epss": 0.001},
        {"cve_id": "CVE-B", "cvss_v3": 9.8, "epss": 0.90},
    ])
    result = compute_scores(df)
    assert result.iloc[0]["cve_id"] == "CVE-B"


def test_custom_weights():
    df = pd.DataFrame([
        {"cve_id": "CVE-TEST", "cvss_v3": 5.0, "epss": 0.5},
    ])
    all_cvss_weights = {"cvss": 1.0, "epss": 0.0, "exposure": 0.0, "age": 0.0}
    result = compute_scores(df, weights=all_cvss_weights)
    assert abs(result.iloc[0]["composite_score"] - 0.5) < 0.01
