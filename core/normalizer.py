import math


def normalize_cvss(cvss_v3: float | None) -> float:
    if cvss_v3 is None:
        return 0.0
    return max(0.0, min(1.0, cvss_v3 / 10.0))


def normalize_epss(epss_probability: float | None) -> float:
    if epss_probability is None:
        return 0.0
    return math.sqrt(max(0.0, min(1.0, epss_probability)))


def normalize_exposure(tier: str, tier_values: dict) -> float:
    return tier_values.get(tier.lower() if tier else "unknown", tier_values.get("unknown", 0.6))
