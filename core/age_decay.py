import math
from datetime import datetime, timezone


def compute_age_days(published_date: str | None) -> int | None:
    """Parse ISO 8601 date string and return age in days."""
    if not published_date:
        return None
    try:
        dt = datetime.fromisoformat(published_date.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        return max(0, (now - dt).days)
    except (ValueError, TypeError):
        return None


def normalize_age(age_days: int | None) -> float:
    """Log scale age normalization, capped at 3 years."""
    if age_days is None:
        return 0.0
    return min(1.0, math.log1p(age_days) / math.log1p(365 * 3))
