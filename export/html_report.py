import plotly.io as pio
import plotly.graph_objects as go
from jinja2 import Environment, FileSystemLoader
import pandas as pd
from pathlib import Path


def build_chart_html(df: pd.DataFrame, weights: dict) -> str:
    factor_cols = [
        ("N_cvss", "CVSS", weights.get("cvss", 0.35)),
        ("N_epss", "EPSS", weights.get("epss", 0.30)),
        ("N_exposure", "Exposure", weights.get("exposure", 0.20)),
        ("N_age", "Age Decay", weights.get("age", 0.15)),
    ]
    colors = ["#1976d2", "#388e3c", "#f57c00", "#7b1fa2"]
    fig = go.Figure()
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
    fig.update_layout(barmode="stack", height=500)
    return pio.to_html(fig, full_html=False, include_plotlyjs="cdn")


def render_html_report(df: pd.DataFrame, weights: dict, tier_values: dict) -> str:
    templates_dir = Path(__file__).parent.parent / "templates"
    env = Environment(loader=FileSystemLoader(str(templates_dir)))
    template = env.get_template("report.html.j2")

    band_counts = df["priority_band"].value_counts().to_dict()
    top5 = df.head(5)[["cve_id", "composite_score", "priority_band"]].to_dict("records")

    chart_html = build_chart_html(df, weights)

    table_rows = []
    for _, row in df.iterrows():
        table_rows.append({
            "cve_id": row.get("cve_id", ""),
            "asset_name": row.get("asset_name", "N/A"),
            "exposure": row.get("asset_exposure", "unknown"),
            "cvss": f"{row['cvss_v3']:.1f}" if pd.notna(row.get("cvss_v3")) else "N/A",
            "epss": f"{row['epss']:.4f}" if pd.notna(row.get("epss")) else "N/A",
            "score": f"{row['composite_score']:.3f}",
            "band": row.get("priority_band", "Low"),
        })

    return template.render(
        band_counts=band_counts,
        top5=top5,
        chart_html=chart_html,
        table_rows=table_rows,
        weights=weights,
        tier_values=tier_values,
    )
