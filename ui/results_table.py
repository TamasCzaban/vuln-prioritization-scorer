import pandas as pd
import plotly.graph_objects as go
import streamlit as st

BAND_COLORS = {
    "Critical": "#d32f2f",
    "High": "#f57c00",
    "Medium": "#fbc02d",
    "Low": "#388e3c",
}

BAND_TEXT_COLORS = {
    "Critical": "#ffffff",
    "High": "#ffffff",
    "Medium": "#1a1a1a",
    "Low": "#ffffff",
}

_CSS_INJECTED = False


def _inject_table_css():
    global _CSS_INJECTED
    if _CSS_INJECTED:
        return
    st.markdown("""
<style>
.vuln-table-wrap {
    width: 100%;
    overflow-x: auto;
    border-radius: 8px;
    border: 1px solid rgba(255,255,255,0.08);
}
.vuln-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 13px;
    font-family: 'JetBrains Mono', 'Fira Code', 'Cascadia Code', monospace;
    background: transparent;
}
.vuln-table thead tr {
    background: rgba(255,255,255,0.05);
    border-bottom: 1px solid rgba(255,255,255,0.12);
}
.vuln-table th {
    padding: 10px 14px;
    text-align: left;
    font-weight: 600;
    font-size: 11px;
    letter-spacing: 0.08em;
    text-transform: uppercase;
    color: rgba(255,255,255,0.5);
    white-space: nowrap;
}
.vuln-table tbody tr {
    border-bottom: 1px solid rgba(255,255,255,0.05);
    transition: background 0.15s;
}
.vuln-table tbody tr:hover {
    background: rgba(255,255,255,0.04);
}
.vuln-table tbody tr:last-child {
    border-bottom: none;
}
.vuln-table td {
    padding: 9px 14px;
    color: rgba(255,255,255,0.85);
    white-space: nowrap;
}
.vuln-table td.cve-id {
    font-weight: 700;
    color: #ffffff;
    letter-spacing: 0.03em;
}
.vuln-table td.score-cell {
    font-weight: 700;
    font-size: 14px;
}
.band-badge {
    display: inline-block;
    padding: 2px 10px;
    border-radius: 100px;
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 0.05em;
}
.band-Critical { background: #d32f2f; color: #fff; }
.band-High     { background: #f57c00; color: #fff; }
.band-Medium   { background: #fbc02d; color: #1a1a1a; }
.band-Low      { background: #388e3c; color: #fff; }
.na-val        { color: rgba(255,255,255,0.3); }
</style>
""", unsafe_allow_html=True)
    _CSS_INJECTED = True


def _fmt(val, precision=3):
    if val is None or (isinstance(val, float) and pd.isna(val)):
        return '<span class="na-val">N/A</span>'
    return f"{val:.{precision}f}"


def _render_html_table(df: pd.DataFrame, display_cols: list):
    _inject_table_css()

    col_labels = {
        "cve_id": "CVE ID",
        "asset_name": "Asset",
        "asset_exposure": "Exposure",
        "cvss_v3": "CVSS v3",
        "epss": "EPSS",
        "age_days": "Age (days)",
        "composite_score": "Score",
        "priority_band": "Priority",
        "N_cvss": "N_cvss",
        "N_epss": "N_epss",
        "N_exposure": "N_exp",
        "N_age": "N_age",
    }

    header_html = "".join(f"<th>{col_labels.get(c, c)}</th>" for c in display_cols)

    rows_html = ""
    for _, row in df.iterrows():
        cells = ""
        for c in display_cols:
            val = row.get(c)
            if c == "cve_id":
                cells += f'<td class="cve-id">{val}</td>'
            elif c == "priority_band":
                band = val or "Low"
                cells += f'<td><span class="band-badge band-{band}">{band}</span></td>'
            elif c == "composite_score":
                cells += f'<td class="score-cell">{_fmt(val)}</td>'
            elif c in ("cvss_v3", "epss", "N_cvss", "N_epss", "N_exposure", "N_age"):
                cells += f"<td>{_fmt(val)}</td>"
            elif c == "age_days":
                if val is None or (isinstance(val, float) and pd.isna(val)):
                    cells += '<td><span class="na-val">N/A</span></td>'
                else:
                    cells += f"<td>{int(val)}</td>"
            else:
                cells += f"<td>{val if val is not None else ''}</td>"
        rows_html += f"<tr>{cells}</tr>"

    html = f"""
<div class="vuln-table-wrap">
  <table class="vuln-table">
    <thead><tr>{header_html}</tr></thead>
    <tbody>{rows_html}</tbody>
  </table>
</div>
"""
    st.markdown(html, unsafe_allow_html=True)


def render_metrics(df: pd.DataFrame):
    bands = ["Critical", "High", "Medium", "Low"]
    cols = st.columns(4)
    for col, band in zip(cols, bands):
        count = len(df[df["priority_band"] == band])
        col.metric(band, count, delta=None)


def render_chart(df: pd.DataFrame, weights: dict):
    if df.empty:
        return

    fig = go.Figure()

    factor_cols = [
        ("N_cvss", "CVSS", weights.get("cvss", 0.35)),
        ("N_epss", "EPSS", weights.get("epss", 0.30)),
        ("N_exposure", "Exposure", weights.get("exposure", 0.20)),
        ("N_age", "Age Decay", weights.get("age", 0.15)),
    ]

    colors = ["#1976d2", "#43a047", "#f57c00", "#ab47bc"]

    plot_df = df.head(20)

    for (col, label, w), color in zip(factor_cols, colors):
        if col in plot_df.columns:
            fig.add_trace(go.Bar(
                name=label,
                y=plot_df["cve_id"],
                x=plot_df[col] * w,
                orientation="h",
                marker_color=color,
            ))

    num_rows = len(plot_df)
    fig.update_layout(
        barmode="stack",
        title=dict(
            text="Factor Contributions to Composite Score (Top 20)",
            x=0,
            xanchor="left",
            font=dict(size=15),
        ),
        xaxis_title="Score Contribution",
        yaxis_title="",
        height=max(420, num_rows * 32 + 140),
        legend=dict(
            orientation="h",
            yanchor="top",
            y=-0.12,
            xanchor="left",
            x=0,
        ),
        margin=dict(l=10, r=20, t=50, b=80),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color="rgba(255,255,255,0.75)"),
        xaxis=dict(gridcolor="rgba(255,255,255,0.08)", zerolinecolor="rgba(255,255,255,0.15)"),
        yaxis=dict(gridcolor="rgba(0,0,0,0)"),
    )

    st.plotly_chart(fig, use_container_width=True)


def render_results_table(df: pd.DataFrame, weights: dict):
    if df.empty:
        st.info("No results to display.")
        return

    render_metrics(df)
    render_chart(df, weights)

    display_cols = [c for c in [
        "cve_id", "asset_name", "asset_exposure", "cvss_v3", "epss",
        "age_days", "composite_score", "priority_band",
        "N_cvss", "N_epss", "N_exposure", "N_age"
    ] if c in df.columns]

    tabs = st.tabs(["All", "Critical", "High", "Medium", "Low"])
    band_filters = [None, "Critical", "High", "Medium", "Low"]

    for tab, band in zip(tabs, band_filters):
        with tab:
            filtered = df if band is None else df[df["priority_band"] == band]

            if filtered.empty:
                st.info(f"No {band} findings.")
                continue

            _render_html_table(filtered, display_cols)

    with st.expander("Scoring config used for this run"):
        st.json({"weights": weights})
