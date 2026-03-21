import streamlit as st
import pandas as pd
from dotenv import load_dotenv
import os

from config import DEFAULT_WEIGHTS, TIER_DEFAULTS
from ui.uploader import render_uploader
from ui.sidebar import render_sidebar
from ui.results_table import render_results_table
from api.nvd_client import NVDClient
from api.epss_client import EPSSClient
from api.cache import get_cached, set_cached
from core.scorer import compute_scores
from export.csv_exporter import to_csv_bytes
from export.html_report import render_html_report

load_dotenv()

st.set_page_config(
    page_title="Vuln Prioritization Scorer",
    page_icon="🔒",
    layout="wide",
)

st.markdown("""
<style>
/* Hide Streamlit top toolbar */
header[data-testid="stHeader"] { display: none !important; }
#MainMenu, footer { visibility: hidden !important; }
.stDeployButton { display: none !important; }

/* Fix dropdown/selectbox options — dark bg, legible text */
[data-baseweb="popover"],
[data-baseweb="menu"] {
    background-color: #161b22 !important;
    border: 1px solid #30363d !important;
}
[role="listbox"] {
    background-color: #161b22 !important;
}
[role="option"] {
    background-color: #161b22 !important;
    color: #e6edf3 !important;
}
[role="option"]:hover,
[role="option"][aria-selected="true"],
[data-baseweb="list-item"]:hover {
    background-color: #1f2937 !important;
    color: #e6edf3 !important;
}
[data-baseweb="popover"] *,
[data-baseweb="menu"] *,
[role="listbox"] * {
    color: #e6edf3 !important;
}
[data-baseweb="popover"] li,
[data-baseweb="menu"] li {
    background-color: #161b22 !important;
}
[data-baseweb="popover"] li:hover,
[data-baseweb="menu"] li:hover {
    background-color: #1f2937 !important;
}

/* Fix Plotly chart tooltip (hoverlabel) via CSS fallback */
.plotly .hoverlayer .hovertext {
    fill: #e6edf3 !important;
}
</style>
""", unsafe_allow_html=True)


def main():
    st.title("Vulnerability Prioritization Scorer")
    st.caption("Enrich CVE lists with NVD + EPSS data and score by configurable multi-factor formula")

    weights, tier_values, api_key = render_sidebar()

    st.subheader("1. Upload CVE List")
    df_input = render_uploader()

    if df_input is None:
        st.info("Upload a CSV or load sample data to get started.")
        return

    cve_ids = df_input["cve_id"].tolist()

    # Check cache
    cached = get_cached(cve_ids)
    if cached is None:
        # Fetch NVD data
        st.subheader("2. Fetching CVE Data")
        progress_bar = st.progress(0, text="Starting NVD fetch...")

        def progress_callback(current, total):
            progress = current / total
            progress_bar.progress(progress, text=f"Fetching CVE {current} of {total} from NVD...")

        nvd_client = NVDClient(api_key=api_key or os.getenv("NVD_API_KEY"))
        nvd_data = nvd_client.fetch_batch(cve_ids, progress_callback=progress_callback)
        progress_bar.empty()

        # Fetch EPSS data
        with st.spinner("Fetching EPSS probabilities..."):
            epss_client = EPSSClient()
            epss_data = epss_client.fetch(cve_ids)

        combined = {"nvd": nvd_data, "epss": epss_data}
        set_cached(cve_ids, combined)
    else:
        nvd_data = cached["nvd"]
        epss_data = cached["epss"]
        st.success("Using cached API data (adjust weights/tiers without re-fetching)")

    # Enrich dataframe
    df_enriched = df_input.copy()
    df_enriched["cvss_v3"] = df_enriched["cve_id"].map(
        lambda cid: nvd_data.get(cid, {}).get("cvss_v3")
    )
    df_enriched["published_date"] = df_enriched["cve_id"].map(
        lambda cid: nvd_data.get(cid, {}).get("published_date")
    )
    df_enriched["epss"] = df_enriched["cve_id"].map(
        lambda cid: epss_data.get(cid.upper())
    )
    df_enriched["nvd_error"] = df_enriched["cve_id"].map(
        lambda cid: nvd_data.get(cid, {}).get("error")
    )

    # Count NVD errors
    errors = df_enriched[df_enriched["nvd_error"].notna() & (df_enriched["nvd_error"] != "")]
    if not errors.empty:
        st.warning(f"{len(errors)} CVE(s) had NVD lookup issues — CVSS/age set to N/A for those entries.")

    # Score
    df_scored = compute_scores(df_enriched, weights=weights, tier_values=tier_values)

    st.subheader("3. Results")
    render_results_table(df_scored, weights)

    # Export
    st.divider()
    st.subheader("Export")
    col1, col2 = st.columns(2)

    with col1:
        csv_bytes = to_csv_bytes(df_scored)
        st.download_button(
            "Download CSV Report",
            data=csv_bytes,
            file_name="vuln_prioritization_report.csv",
            mime="text/csv",
        )

    with col2:
        try:
            html_report = render_html_report(df_scored, weights, tier_values)
            st.download_button(
                "Download HTML Report",
                data=html_report.encode("utf-8"),
                file_name="vuln_prioritization_report.html",
                mime="text/html",
            )
        except Exception as e:
            st.error(f"HTML report generation failed: {e}")


if __name__ == "__main__":
    main()
