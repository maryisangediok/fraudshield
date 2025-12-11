# fraudshield/dashboard/eval_dashboard.py
"""
Streamlit dashboard for FraudShield evaluation results.

Run with:
    streamlit run fraudshield/dashboard/eval_dashboard.py

Features:
- Load and compare evaluation results
- Visualize metrics over time
- Drill down into specific categories
- Score distribution analysis
- Business impact calculator
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional

import streamlit as st
import numpy as np

# Page config
st.set_page_config(
    page_title="FraudShield Eval Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom CSS for dark theme with accent colors
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=Space+Grotesk:wght@400;500;600;700&display=swap');
    
    :root {
        --bg-primary: #0d1117;
        --bg-secondary: #161b22;
        --bg-tertiary: #21262d;
        --accent-green: #3fb950;
        --accent-red: #f85149;
        --accent-yellow: #d29922;
        --accent-blue: #58a6ff;
        --accent-purple: #a371f7;
        --text-primary: #e6edf3;
        --text-secondary: #8b949e;
        --border: #30363d;
    }
    
    .stApp {
        background: linear-gradient(180deg, var(--bg-primary) 0%, #0a0e14 100%);
    }
    
    h1, h2, h3, h4 {
        font-family: 'Space Grotesk', sans-serif !important;
        color: var(--text-primary) !important;
    }
    
    .metric-card {
        background: var(--bg-secondary);
        border: 1px solid var(--border);
        border-radius: 12px;
        padding: 20px;
        text-align: center;
    }
    
    .metric-value {
        font-family: 'JetBrains Mono', monospace;
        font-size: 2.5rem;
        font-weight: 600;
        margin: 10px 0;
    }
    
    .metric-label {
        font-family: 'Space Grotesk', sans-serif;
        font-size: 0.9rem;
        color: var(--text-secondary);
        text-transform: uppercase;
        letter-spacing: 1px;
    }
    
    .green { color: var(--accent-green); }
    .red { color: var(--accent-red); }
    .yellow { color: var(--accent-yellow); }
    .blue { color: var(--accent-blue); }
    .purple { color: var(--accent-purple); }
    
    .score-bar {
        height: 8px;
        border-radius: 4px;
        background: var(--bg-tertiary);
        overflow: hidden;
        margin: 10px 0;
    }
    
    .score-bar-fill {
        height: 100%;
        border-radius: 4px;
        transition: width 0.5s ease;
    }
    
    .recommendation-card {
        background: var(--bg-tertiary);
        border-left: 4px solid var(--accent-blue);
        padding: 15px;
        margin: 10px 0;
        border-radius: 0 8px 8px 0;
    }
    
    .stSelectbox > div > div {
        background: var(--bg-secondary);
        border-color: var(--border);
    }
</style>
""", unsafe_allow_html=True)


def load_eval_results(results_dir: Path) -> List[Dict[str, Any]]:
    """Load all evaluation result files."""
    results = []
    
    if not results_dir.exists():
        return results
    
    for file in sorted(results_dir.glob("*.json"), reverse=True):
        try:
            with open(file) as f:
                data = json.load(f)
                data["_filename"] = file.name
                results.append(data)
        except:
            pass
    
    return results


def render_metric_card(label: str, value: str, color: str = "blue", delta: str = None):
    """Render a styled metric card."""
    delta_html = ""
    if delta:
        delta_color = "green" if delta.startswith("+") or delta.startswith("↑") else "red"
        delta_html = f'<div class="{delta_color}" style="font-size: 0.8rem;">{delta}</div>'
    
    st.markdown(f"""
    <div class="metric-card">
        <div class="metric-label">{label}</div>
        <div class="metric-value {color}">{value}</div>
        {delta_html}
    </div>
    """, unsafe_allow_html=True)


def render_score_bar(label: str, value: float, max_val: float = 100):
    """Render a horizontal score bar."""
    pct = min(100, (value / max_val) * 100)
    
    if pct >= 80:
        color = "var(--accent-green)"
    elif pct >= 60:
        color = "var(--accent-yellow)"
    else:
        color = "var(--accent-red)"
    
    st.markdown(f"""
    <div style="margin: 15px 0;">
        <div style="display: flex; justify-content: space-between; margin-bottom: 5px;">
            <span style="color: var(--text-primary);">{label}</span>
            <span style="color: var(--text-secondary); font-family: 'JetBrains Mono';">{value:.1f}%</span>
        </div>
        <div class="score-bar">
            <div class="score-bar-fill" style="width: {pct}%; background: {color};"></div>
        </div>
    </div>
    """, unsafe_allow_html=True)


def main():
    # Import settings for default paths
    try:
        from fraudshield.config import settings
        default_results_dir = settings.eval_output_dir
    except ImportError:
        default_results_dir = "eval_results"
    
    # Sidebar
    st.sidebar.markdown("# 🛡️ FraudShield")
    st.sidebar.markdown("### Evaluation Dashboard")
    st.sidebar.markdown("---")
    
    # Load results
    results_dir = Path(default_results_dir)
    results = load_eval_results(results_dir)
    
    if not results:
        st.warning("No evaluation results found. Run an evaluation first:")
        st.code("python -m fraudshield.eval.run_comprehensive --dataset-dir datasets/fraudshield_dataset_large")
        return
    
    # Result selector
    result_names = [r.get("_filename", "Unknown") for r in results]
    selected_idx = st.sidebar.selectbox(
        "Select Evaluation",
        range(len(result_names)),
        format_func=lambda i: result_names[i],
    )
    
    result = results[selected_idx]
    
    # Compare mode
    compare_enabled = st.sidebar.checkbox("Compare with previous")
    compare_result = results[min(selected_idx + 1, len(results) - 1)] if compare_enabled and len(results) > 1 else None
    
    st.sidebar.markdown("---")
    st.sidebar.markdown("### Quick Actions")
    
    if st.sidebar.button("🔄 Refresh Results"):
        st.rerun()
    
    if st.sidebar.button("📊 Run New Evaluation"):
        st.info("Run from terminal: `python -m fraudshield.eval.run_comprehensive --dataset-dir datasets/fraudshield_dataset_large`")
    
    # Main content
    st.markdown("# 📊 Evaluation Results")
    st.markdown(f"**Run:** `{result.get('run_name', 'Unknown')}` | **Date:** `{result.get('timestamp', 'Unknown')[:19]}`")
    
    # Overall scores section
    st.markdown("## 🏆 Overall Scores")
    
    scores = result.get("scores", {})
    
    col1, col2, col3, col4, col5 = st.columns(5)
    
    with col1:
        val = scores.get("detection", 0)
        delta = None
        if compare_result:
            prev = compare_result.get("scores", {}).get("detection", 0)
            diff = val - prev
            delta = f"{'↑' if diff >= 0 else '↓'} {abs(diff):.1f}"
        render_metric_card("Detection", f"{val:.1f}", "green" if val >= 80 else "yellow", delta)
    
    with col2:
        val = scores.get("calibration", 0)
        render_metric_card("Calibration", f"{val:.1f}", "green" if val >= 80 else "red")
    
    with col3:
        val = scores.get("business", 0)
        render_metric_card("Business", f"{val:.1f}", "blue")
    
    with col4:
        val = scores.get("robustness", 0)
        render_metric_card("Robustness", f"{val:.1f}", "purple" if val >= 80 else "yellow")
    
    with col5:
        val = scores.get("overall", 0)
        render_metric_card("Overall", f"{val:.1f}", "green" if val >= 70 else "red")
    
    st.markdown("---")
    
    # Traditional metrics
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("## 📈 Detection Metrics")
        
        trad = result.get("traditional_metrics", {})
        
        if trad:
            render_score_bar("Accuracy", trad.get("accuracy", 0) * 100)
            render_score_bar("Precision", trad.get("precision", 0) * 100)
            render_score_bar("Recall", trad.get("recall", 0) * 100)
            render_score_bar("F1 Score", trad.get("f1_score", 0) * 100)
            
            if trad.get("roc_auc"):
                render_score_bar("ROC-AUC", trad.get("roc_auc", 0) * 100)
        else:
            st.info("No traditional metrics available")
    
    with col2:
        st.markdown("## 💰 Business Impact")
        
        biz = result.get("business_metrics", {})
        
        if biz:
            st.markdown(f"""
            <div class="metric-card" style="text-align: left;">
                <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px;">
                    <div>
                        <div class="metric-label">Fraud Blocked</div>
                        <div class="metric-value green" style="font-size: 1.8rem;">${biz.get('fraud_blocked_value', 0):,.0f}</div>
                    </div>
                    <div>
                        <div class="metric-label">Fraud Missed</div>
                        <div class="metric-value red" style="font-size: 1.8rem;">${biz.get('fraud_missed_value', 0):,.0f}</div>
                    </div>
                    <div>
                        <div class="metric-label">FP Cost</div>
                        <div class="metric-value yellow" style="font-size: 1.8rem;">${biz.get('total_fp_cost', 0):,.0f}</div>
                    </div>
                    <div>
                        <div class="metric-label">Net Savings</div>
                        <div class="metric-value blue" style="font-size: 1.8rem;">${biz.get('net_savings', 0):,.0f}</div>
                    </div>
                </div>
                <div style="margin-top: 20px; padding-top: 20px; border-top: 1px solid var(--border);">
                    <div class="metric-label">Return on Investment</div>
                    <div class="metric-value green" style="font-size: 2rem;">{biz.get('roi_percentage', 0):,.1f}%</div>
                </div>
            </div>
            """, unsafe_allow_html=True)
        else:
            st.info("No business metrics available")
    
    st.markdown("---")
    
    # Advanced metrics
    st.markdown("## 🔬 Advanced Metrics")
    
    col1, col2, col3 = st.columns(3)
    
    adv = result.get("advanced_metrics", {})
    
    with col1:
        st.markdown("### Calibration")
        if adv and "calibration" in adv:
            cal = adv["calibration"]
            st.metric("ECE", f"{cal.get('expected_calibration_error', 0):.4f}")
            st.metric("Brier Score", f"{cal.get('brier_score', 0):.4f}")
        else:
            st.info("N/A")
    
    with col2:
        st.markdown("### Threshold Analysis")
        if adv and "threshold_analysis" in adv:
            thresh = adv["threshold_analysis"]
            st.metric("Optimal Threshold", f"{thresh.get('optimal_f1_threshold', 0.5):.3f}")
            st.metric("Precision @ 95% Recall", f"{thresh.get('precision_at_95_recall', 0)*100:.1f}%")
        else:
            st.info("N/A")
    
    with col3:
        st.markdown("### Score Distribution")
        if adv and "score_distribution" in adv:
            dist = adv["score_distribution"]
            st.metric("Score Separation", f"{dist.get('score_separation', 0):.2f}")
            st.metric("Positive Mean", f"{dist.get('positive_mean', 0):.2f}")
            st.metric("Negative Mean", f"{dist.get('negative_mean', 0):.2f}")
        else:
            st.info("N/A")
    
    # Temporal metrics
    temp = result.get("temporal_metrics", {})
    if temp:
        st.markdown("---")
        st.markdown("## 📉 Temporal Analysis")
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            trend = temp.get("accuracy_trend", "stable")
            icon = "📈" if trend == "improving" else "📉" if trend == "degrading" else "➡️"
            st.metric("Accuracy Trend", f"{icon} {trend.title()}")
        
        with col2:
            drift = temp.get("drift_detected", False)
            st.metric("Drift Detected", "⚠️ Yes" if drift else "✅ No")
        
        with col3:
            staleness = temp.get("staleness_score", 0)
            st.metric("Model Staleness", f"{staleness*100:.1f}%")
    
    # Recommendations
    recs = result.get("recommendations", [])
    if recs:
        st.markdown("---")
        st.markdown("## 📋 Recommendations")
        
        for rec in recs:
            st.markdown(f"""
            <div class="recommendation-card">
                {rec}
            </div>
            """, unsafe_allow_html=True)
    
    # Raw data expander
    with st.expander("📄 Raw JSON Data"):
        st.json(result)


if __name__ == "__main__":
    main()

