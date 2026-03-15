import streamlit as st
from config import DEFAULT_WEIGHTS, TIER_DEFAULTS


def render_sidebar() -> tuple[dict, dict, str | None]:
    """Returns (weights, tier_values, api_key)"""
    with st.sidebar:
        st.header("Configuration")

        # API Key
        st.subheader("NVD API Key")
        api_key = st.text_input("API Key (optional — speeds up fetching)", type="password", key="nvd_api_key")
        if api_key:
            st.caption("With key: 50 req/30s")
        else:
            st.caption("No key: 5 req/30s (slower)")

        st.divider()

        # Weight sliders
        st.subheader("Scoring Weights")
        st.caption("Sliders auto-rebalance to sum = 1.0")

        w_cvss = st.slider("CVSS v3", 0.0, 1.0, DEFAULT_WEIGHTS["cvss"], 0.05, key="w_cvss")
        w_epss = st.slider("EPSS", 0.0, 1.0, DEFAULT_WEIGHTS["epss"], 0.05, key="w_epss")
        w_exposure = st.slider("Exposure Tier", 0.0, 1.0, DEFAULT_WEIGHTS["exposure"], 0.05, key="w_exposure")
        w_age = st.slider("Age Decay", 0.0, 1.0, DEFAULT_WEIGHTS["age"], 0.05, key="w_age")

        total = w_cvss + w_epss + w_exposure + w_age
        if total == 0:
            weights = DEFAULT_WEIGHTS.copy()
        else:
            weights = {
                "cvss": w_cvss / total,
                "epss": w_epss / total,
                "exposure": w_exposure / total,
                "age": w_age / total,
            }

        st.caption(f"Effective weights sum: {sum(weights.values()):.2f}")

        st.divider()

        # Tier multipliers
        st.subheader("Exposure Tier Values")
        tier_values = {}
        for tier, default in TIER_DEFAULTS.items():
            tier_values[tier] = st.slider(tier, 0.0, 1.0, default, 0.05, key=f"tier_{tier}")

    return weights, tier_values, api_key or None
