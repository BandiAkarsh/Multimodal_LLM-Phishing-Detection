"""
Phishing Detection Analytics Dashboard

A Streamlit-based dashboard for monitoring:
- Detection statistics
- Model performance metrics  
- Drift detection status
- Prediction history

Usage:
    streamlit run app.py
"""

import os
import sys
from datetime import datetime, timedelta
from typing import Any, Dict, List

import requests
import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots

# Add project root to path
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(project_root)

# ============== Configuration ==============

API_BASE_URL = os.getenv("API_BASE_URL", "http://localhost:8000")

# Page configuration
st.set_page_config(
    page_title="Phishing Guard - Analytics Dashboard",
    page_icon="📊",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom CSS
st.markdown("""
<style>
    .metric-card {
        background-color: #f8f9fa;
        padding: 1rem;
        border-radius: 0.5rem;
        border-left: 4px solid #007bff;
        margin-bottom: 1rem;
    }
    .metric-value {
        font-size: 2rem;
        font-weight: bold;
        color: #007bff;
    }
    .metric-label {
        font-size: 0.9rem;
        color: #6c757d;
    }
    .status-healthy {
        color: #28a745;
        font-weight: bold;
    }
    .status-warning {
        color: #ffc107;
        font-weight: bold;
    }
    .status-degraded {
        color: #dc3545;
        font-weight: bold;
    }
    .drift-detected {
        background-color: #f8d7da;
        padding: 1rem;
        border-radius: 0.5rem;
        border-left: 4px solid #dc3545;
    }
    .drift-stable {
        background-color: #d4edda;
        padding: 1rem;
        border-radius: 0.5rem;
        border-left: 4px solid #28a745;
    }
</style>
""", unsafe_allow_html=True)


# ============== API Functions ==============

def check_api_health() -> Dict[str, Any]:
    """Check if API is available."""
    try:
        response = requests.get(f"{API_BASE_URL}/health", timeout=5)
        if response.status_code == 200:
            return {**response.json(), "status": "online"}
        return {"status": "error", "detail": response.text}
    except Exception as e:
        return {"status": "offline", "detail": str(e)}


def get_monitoring_summary() -> Dict[str, Any]:
    """Get comprehensive monitoring summary."""
    try:
        response = requests.get(f"{API_BASE_URL}/api/v1/monitoring/summary", timeout=10)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        st.error(f"Failed to get monitoring summary: {e}")
        return {}


def get_prediction_history(limit: int = 50) -> List[Dict]:
    """Get prediction history."""
    try:
        response = requests.get(
            f"{API_BASE_URL}/api/v1/monitoring/history",
            params={"limit": limit},
            timeout=10
        )
        response.raise_for_status()
        return response.json().get("predictions", [])
    except Exception as e:
        st.error(f"Failed to get history: {e}")
        return []


def get_cache_stats() -> Dict[str, Any]:
    """Get cache statistics."""
    try:
        response = requests.get(f"{API_BASE_URL}/api/v1/monitoring/cache", timeout=5)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        return {}


# ============== UI Components ==============

def render_header():
    """Render dashboard header."""
    col1, col2, col3 = st.columns([3, 1, 1])
    
    with col1:
        st.title("📊 Phishing Guard - Analytics Dashboard")
        st.markdown("Real-time monitoring of phishing detection system")
    
    with col2:
        # API status
        api_status = check_api_health()
        if api_status.get("status") == "online":
            st.success("🟢 API Online")
        else:
            st.error("🔴 API Offline")
    
    with col3:
        # Refresh button
        if st.button("🔄 Refresh", use_container_width=True):
            st.rerun()
    
    st.divider()


def render_metrics_row(summary: Dict[str, Any]):
    """Render key metrics in a row."""
    st.subheader("📈 Key Metrics")
    
    metrics = summary.get("metrics", {})
    health = summary.get("health", {})
    
    col1, col2, col3, col4, col5 = st.columns(5)
    
    with col1:
        total = metrics.get("total_predictions", 0)
        st.markdown("""
        <div class="metric-card">
            <div class="metric-label">Total Predictions</div>
            <div class="metric-value">{total}</div>
        </div>
        """.format(total=total), unsafe_allow_html=True)
    
    with col2:
        avg_latency = metrics.get("avg_latency_ms", 0)
        st.markdown("""
        <div class="metric-card">
            <div class="metric-label">Avg Latency</div>
            <div class="metric-value">{latency:.1f}ms</div>
        </div>
        """.format(latency=avg_latency), unsafe_allow_html=True)
    
    with col3:
        p95 = metrics.get("p95_latency_ms", 0)
        st.markdown("""
        <div class="metric-card">
            <div class="metric-label">P95 Latency</div>
            <div class="metric-value">{p95:.1f}ms</div>
        </div>
        """.format(p95=p95), unsafe_allow_html=True)
    
    with col4:
        hit_rate = metrics.get("cache_hit_rate", 0) * 100
        st.markdown("""
        <div class="metric-card">
            <div class="metric-label">Cache Hit Rate</div>
            <div class="metric-value">{hit_rate:.1f}%</div>
        </div>
        """.format(hit_rate=hit_rate), unsafe_allow_html=True)
    
    with col5:
        predictions_per_min = metrics.get("predictions_per_minute", 0)
        st.markdown("""
        <div class="metric-card">
            <div class="metric-label">Predictions/min</div>
            <div class="metric-value">{ppm:.1f}</div>
        </div>
        """.format(ppm=predictions_per_min), unsafe_allow_html=True)


def render_health_status(health: Dict[str, Any]):
    """Render health status card."""
    st.subheader("🏥 System Health")
    
    health_status = health.get("health", "unknown")
    
    col1, col2 = st.columns([1, 3])
    
    with col1:
        if health_status == "healthy":
            st.markdown('<p class="status-healthy">✅ HEALTHY</p>', unsafe_allow_html=True)
        elif health_status == "degraded":
            st.markdown('<p class="status-degraded">⚠️ DEGRADED</p>', unsafe_allow_html=True)
        else:
            st.markdown('<p class="status-warning">⚠️ WARNING</p>', unsafe_allow_html=True)
    
    with col2:
        uptime = health.get("uptime_minutes", 0)
        st.metric("Uptime", f"{uptime:.1f} minutes")
        
        issues = health.get("issues", [])
        if issues:
            st.warning("Issues: " + "; ".join(issues))


def render_class_distribution(metrics: Dict[str, Any]):
    """Render class distribution chart."""
    st.subheader("🎯 Classification Distribution")
    
    class_dist = metrics.get("class_distribution", {})
    
    if not class_dist:
        st.info("No prediction data available yet.")
        return
    
    # Create dataframe
    df = pd.DataFrame([
        {"class": k, "count": v}
        for k, v in class_dist.items()
    ])
    
    # Create pie chart
    fig = px.pie(
        df,
        values="count",
        names="class",
        title="Prediction Distribution",
        color_discrete_sequence=px.colors.qualitative.Set3
    )
    
    fig.update_traces(textposition='inside', textinfo='percent+label')
    
    st.plotly_chart(fig, use_container_width=True)


def render_latency_chart(history: List[Dict]):
    """Render latency over time chart."""
    st.subheader("⏱️ Latency Trend")
    
    if not history:
        st.info("No prediction history available.")
        return
    
    # Create dataframe
    df = pd.DataFrame(history)
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    df = df.sort_values("timestamp")
    
    # Create line chart
    fig = px.line(
        df,
        x="timestamp",
        y="latency_ms",
        title="Prediction Latency Over Time",
        labels={"latency_ms": "Latency (ms)", "timestamp": "Time"}
    )
    
    fig.update_layout(
        xaxis_title="Time",
        yaxis_title="Latency (ms)",
        hovermode="x unified"
    )
    
    st.plotly_chart(fig, use_container_width=True)


def render_drift_status(drift: Dict[str, Any]):
    """Render drift detection status."""
    st.subheader("📉 Model Drift Detection")
    
    if not drift:
        st.info("Drift detection not initialized yet.")
        return
    
    drift_status = drift.get("status", "unknown")
    
    if drift_status == "stable":
        st.markdown("""
        <div class="drift-stable">
            ✅ <strong>Model is STABLE</strong><br>
            No significant drift detected.
        </div>
        """, unsafe_allow_html=True)
    elif drift_status == "drifted":
        st.markdown("""
        <div class="drift-detected">
            ⚠️ <strong>DRIFT DETECTED!</strong><br>
            Model predictions have changed significantly.
        </div>
        """, unsafe_allow_html=True)
    else:
        st.info(f"Drift Status: {drift_status}")
        return
    
    # Show drift details
    col1, col2 = st.columns(2)
    
    with col1:
        st.metric("Drift Score", f"{drift.get('drift_score', 0):.4f}")
        st.metric("Threshold", f"{drift.get('threshold', 0):.4f}")
    
    with col2:
        st.metric("Total Samples", drift.get("total_samples", 0))
        last_check = drift.get("last_check", "N/A")
        st.metric("Last Check", last_check[:19] if last_check != "N/A" else "N/A")
    
    # Feature drift
    feature_drift = drift.get("feature_drift", {})
    if feature_drift:
        st.subheader("🔍 Feature Drift Details")
        
        for feature, details in feature_drift.items():
            with st.expander(f"Feature: {feature}"):
                col1, col2, col3 = st.columns(3)
                
                with col1:
                    st.metric("Baseline Mean", f"{details.get('baseline_mean', 0):.2f}")
                
                with col2:
                    st.metric("Current Mean", f"{details.get('current_mean', 0):.2f}")
                
                with col3:
                    change = details.get("change_pct", 0)
                    st.metric("Change", f"{change:.1f}%")


def render_prediction_history(history: List[Dict]):
    """Render prediction history table."""
    st.subheader("📋 Recent Predictions")
    
    if not history:
        st.info("No prediction history available.")
        return
    
    # Create dataframe
    df = pd.DataFrame(history)
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    df = df.sort_values("timestamp", ascending=False)
    
    # Format dataframe
    df_display = df.copy()
    df_display["probability"] = df_display["probability"].apply(lambda x: f"{x:.3f}")
    df_display["latency_ms"] = df_display["latency_ms"].apply(lambda x: f"{x:.1f}ms")
    
    # Display table
    st.dataframe(
        df_display[["timestamp", "url", "classification", "probability", "latency_ms"]],
        use_container_width=True,
        hide_index=True
    )


def render_cache_stats():
    """Render cache statistics."""
    st.subheader("💾 Cache Performance")
    
    cache_stats = get_cache_stats()
    
    if not cache_stats:
        st.info("Cache statistics not available.")
        return
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Cache Size", f"{cache_stats.get('size', 0)} / {cache_stats.get('max_size', 0)}")
    
    with col2:
        st.metric("Hits", cache_stats.get("hits", 0))
    
    with col3:
        st.metric("Misses", cache_stats.get("misses", 0))
    
    with col4:
        hit_rate = cache_stats.get("hit_rate", 0) * 100
        st.metric("Hit Rate", f"{hit_rate:.1f}%")


def render_sidebar():
    """Render sidebar controls."""
    with st.sidebar:
        st.header("⚙️ Controls")
        
        # API URL
        api_url = st.text_input("API URL", value=API_BASE_URL)
        if api_url != API_BASE_URL:
            st.session_state["api_url"] = api_url
        
        st.divider()
        
        # Auto-refresh
        auto_refresh = st.toggle("Auto Refresh", value=False)
        if auto_refresh:
            refresh_interval = st.slider("Interval (seconds)", 5, 60, 10)
            st.info(f"Will refresh every {refresh_interval}s")
        
        st.divider()
        
        # History limit
        history_limit = st.slider("History Limit", 10, 100, 50)
        st.session_state["history_limit"] = history_limit
        
        st.divider()
        
        # Reset metrics button
        if st.button("🔄 Reset Metrics", use_container_width=True):
            try:
                response = requests.post(f"{API_BASE_URL}/api/v1/monitoring/reset", timeout=5)
                if response.status_code == 200:
                    st.success("Metrics reset successfully!")
                    st.rerun()
                else:
                    st.error("Failed to reset metrics")
            except Exception as e:
                st.error(f"Error: {e}")


# ============== Main App ==============

def main():
    """Main dashboard application."""
    
    # Render sidebar
    render_sidebar()
    
    # Render header
    render_header()
    
    # Get monitoring data
    with st.spinner("Loading monitoring data..."):
        summary = get_monitoring_summary()
    
    if not summary:
        st.error("Failed to load monitoring data. Is the API server running?")
        st.info("Start the API server with: `cd 04_inference && uvicorn api:app --reload`")
        return
    
    # Render metrics row
    render_metrics_row(summary)
    st.divider()
    
    # Two-column layout
    col1, col2 = st.columns([1, 1])
    
    with col1:
        # Health status
        render_health_status(summary.get("health", {}))
    
    with col2:
        # Cache stats
        render_cache_stats()
    
    st.divider()
    
    # Class distribution
    render_class_distribution(summary.get("metrics", {}))
    st.divider()
    
    # Get prediction history
    history_limit = st.session_state.get("history_limit", 50)
    history = get_prediction_history(limit=history_limit)
    
    # Latency chart
    render_latency_chart(history)
    st.divider()
    
    # Drift status
    render_drift_status(summary.get("drift", {}))
    st.divider()
    
    # Prediction history
    render_prediction_history(history)


if __name__ == "__main__":
    main()
