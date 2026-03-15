import re
import pandas as pd
import streamlit as st

CVE_PATTERN = re.compile(r'^CVE-\d{4}-\d{4,}$', re.IGNORECASE)

SAMPLE_DATA = """cve_id,asset_name,asset_exposure
CVE-2021-44228,prod-api-gateway-01,internet-facing
CVE-2023-23397,exchange-server-corp,internal
CVE-2022-30190,workstation-fleet,
CVE-2021-34527,print-spooler-srv,internet-facing
CVE-2020-1472,domain-controller-01,critical-infra
"""


def render_uploader() -> pd.DataFrame | None:
    col1, col2 = st.columns([3, 1])
    with col1:
        uploaded = st.file_uploader("Upload CVE list (CSV)", type=["csv"], label_visibility="collapsed")
    with col2:
        load_sample = st.button("Load sample data", use_container_width=True)

    df = None
    if load_sample:
        from io import StringIO
        df = pd.read_csv(StringIO(SAMPLE_DATA))
        st.success("Sample data loaded (5 CVEs)")
    elif uploaded:
        try:
            df = pd.read_csv(uploaded)
        except Exception as e:
            st.error(f"Failed to parse CSV: {e}")
            return None

    if df is None:
        return None

    return validate_dataframe(df)


def validate_dataframe(df: pd.DataFrame) -> pd.DataFrame | None:
    if "cve_id" not in df.columns:
        st.error("CSV must contain a `cve_id` column.")
        return None

    df["cve_id"] = df["cve_id"].astype(str).str.strip().str.upper()
    invalid = df[~df["cve_id"].apply(lambda x: bool(CVE_PATTERN.match(x)))]
    if not invalid.empty:
        st.warning(f"Skipping {len(invalid)} row(s) with invalid CVE IDs: {', '.join(invalid['cve_id'].tolist()[:5])}")
        df = df[df["cve_id"].apply(lambda x: bool(CVE_PATTERN.match(x)))]

    df = df.drop_duplicates(subset=["cve_id"])

    if "asset_exposure" not in df.columns:
        df["asset_exposure"] = "unknown"
    df["asset_exposure"] = df["asset_exposure"].fillna("unknown")

    if df.empty:
        st.error("No valid CVE IDs found.")
        return None

    st.info(f"Loaded {len(df)} unique CVE(s)")
    return df.reset_index(drop=True)
