import pytest
import math
from core.age_decay import normalize_age, compute_age_days


def test_normalize_age_zero():
    assert normalize_age(0) == 0.0


def test_normalize_age_none():
    assert normalize_age(None) == 0.0


def test_normalize_age_cap():
    assert normalize_age(365 * 3) == 1.0
    assert normalize_age(365 * 10) == 1.0


def test_normalize_age_six_months():
    six_months = 180
    result = normalize_age(six_months)
    assert 0.70 < result < 0.80  # log1p(180)/log1p(1095) ≈ 0.743


def test_compute_age_days_valid():
    days = compute_age_days("2020-01-01T00:00:00.000")
    assert days > 1000  # well in the past


def test_compute_age_days_invalid():
    assert compute_age_days(None) is None
    assert compute_age_days("not-a-date") is None
