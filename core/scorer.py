import pandas as pd
from core.normalizer import normalize_cvss, normalize_epss, normalize_exposure
from core.age_decay import normalize_age, compute_age_days
from config import DEFAULT_WEIGHTS, TIER_DEFAULTS, PRIORITY_BANDS


def compute_scores(df: pd.DataFrame, weights: dict = None, tier_values: dict = None) -> pd.DataFrame:
    """
    Enrich a DataFrame with normalized factor scores and composite score.

    Expected columns: cve_id, cvss_v3 (optional), epss (optional),
                      asset_exposure (optional), published_date (optional),
                      asset_name (optional)
    """
    if weights is None:
        weights = DEFAULT_WEIGHTS
    if tier_values is None:
        tier_values = TIER_DEFAULTS

    result = df.copy()

    # Fill missing exposure
    if "asset_exposure" not in result.columns:
        result["asset_exposure"] = "unknown"
    result["asset_exposure"] = result["asset_exposure"].fillna("unknown")

    # Compute normalized factors
    result["N_cvss"] = result.get("cvss_v3", pd.Series([None] * len(result))).apply(normalize_cvss)
    result["N_epss"] = result.get("epss", pd.Series([None] * len(result))).apply(normalize_epss)
    result["N_exposure"] = result["asset_exposure"].apply(lambda t: normalize_exposure(t, tier_values))

    if "published_date" in result.columns:
        result["age_days"] = result["published_date"].apply(compute_age_days)
    else:
        result["age_days"] = None
    result["N_age"] = result["age_days"].apply(normalize_age)

    # Composite score
    w = weights
    result["composite_score"] = (
        w.get("cvss", 0.35) * result["N_cvss"] +
        w.get("epss", 0.30) * result["N_epss"] +
        w.get("exposure", 0.20) * result["N_exposure"] +
        w.get("age", 0.15) * result["N_age"]
    )

    result["priority_band"] = result["composite_score"].apply(assign_priority_band)

    return result.sort_values("composite_score", ascending=False)


def assign_priority_band(score: float) -> str:
    for band, threshold in PRIORITY_BANDS:
        if score >= threshold:
            return band
    return "Low"
