"""
Phishing Detection Explainability Chat Interface

A Streamlit-based chat UI that allows users to:
1. Analyze URLs and get detailed explanations
2. Ask follow-up questions about detection results
3. View key factors that influenced the classification
4. Get actionable recommendations

Usage:
    streamlit run app.py
"""

import os
import sys
from typing import Any, Dict, List, Optional

import requests
import streamlit as st
from streamlit_chat import message

# Add project root to path
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(project_root)

# ============== Configuration ==============

# API Configuration
API_BASE_URL = os.getenv("API_BASE_URL", "http://localhost:8000")
API_TIMEOUT = 30

# Page configuration
st.set_page_config(
    page_title="Phishing Guard - Explainability Chat",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom CSS
st.markdown("""
<style>
    .main {
        background-color: #f8f9fa;
    }
    .stApp {
        background-color: #ffffff;
    }
    .chat-message {
        padding: 1rem;
        border-radius: 0.5rem;
        margin-bottom: 1rem;
    }
    .chat-message.user {
        background-color: #e3f2fd;
        border-left: 4px solid #2196f3;
    }
    .chat-message.assistant {
        background-color: #f3e5f5;
        border-left: 4px solid #9c27b0;
    }
    .factor-card {
        padding: 0.75rem;
        background-color: #fff3e0;
        border-radius: 0.5rem;
        margin-bottom: 0.5rem;
        border-left: 3px solid #ff9800;
    }
    .recommendation-card {
        padding: 0.75rem;
        background-color: #e8f5e9;
        border-radius: 0.5rem;
        margin-bottom: 0.5rem;
        border-left: 3px solid #4caf50;
    }
    .risk-high {
        color: #d32f2f;
        font-weight: bold;
    }
    .risk-critical {
        color: #b71c1c;
        font-weight: bold;
    }
    .risk-low {
        color: #388e3c;
    }
    .confidence-score {
        font-size: 1.5rem;
        font-weight: bold;
    }
    .confidence-high {
        color: #d32f2f;
    }
    .confidence-medium {
        color: #ff9800;
    }
    .confidence-low {
        color: #4caf50;
    }
</style>
""", unsafe_allow_html=True)


# ============== API Functions ==============

def check_api_health() -> bool:
    """Check if API is available."""
    try:
        response = requests.get(f"{API_BASE_URL}/health", timeout=5)
        return response.status_code == 200
    except:
        return False


def analyze_url(url: str, use_llm: bool = True) -> Dict[str, Any]:
    """Analyze a URL using the detection API."""
    try:
        response = requests.post(
            f"{API_BASE_URL}/api/v1/analyze",
            json={"url": url},
            timeout=API_TIMEOUT
        )
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        st.error(f"API Error: {str(e)}")
        return {"error": str(e)}


def explain_detection(
    url: str,
    classification: str,
    confidence: float,
    features: Dict,
    use_llm: bool = True
) -> Dict[str, Any]:
    """Get explanation for a detection result."""
    try:
        response = requests.post(
            f"{API_BASE_URL}/api/v1/chat/explain",
            json={
                "url": url,
                "classification": classification,
                "confidence": confidence,
                "features": features,
                "use_llm": use_llm
            },
            timeout=60 if use_llm else 10
        )
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        st.error(f"Explanation Error: {str(e)}")
        return {"error": str(e)}


# ============== UI Components ==============

def render_header():
    """Render the page header."""
    st.title("🛡️ Phishing Guard - Explainability Chat")
    st.markdown("""
    **Understand why a URL was classified as phishing or legitimate.**
    
    This tool uses AI to explain the detection results in plain language.
    """)
    st.divider()


def render_url_input() -> Optional[str]:
    """Render URL input form."""
    with st.container():
        col1, col2 = st.columns([4, 1])
        
        with col1:
            url = st.text_input(
                "Enter URL to analyze:",
                placeholder="https://example.com",
                key="url_input"
            )
        
        with col2:
            use_llm = st.toggle("Use AI Explanation", value=True, help="Use LLM for detailed explanations (slower)")
        
        if st.button("🔍 Analyze URL", type="primary", use_container_width=True):
            if url:
                return url, use_llm
    
    return None


def render_detection_result(result: Dict[str, Any], use_llm: bool):
    """Render the detection result with explanation."""
    
    if "error" in result:
        st.error(f"Error: {result['error']}")
        return
    
    # Extract data
    url = result.get("url", "N/A")
    classification = result.get("classification", "unknown")
    confidence = result.get("confidence", 0.0)
    features = result.get("features", {})
    ml_prediction = result.get("ml_prediction")
    llm_analysis = result.get("llm_analysis")
    toolkit_detection = result.get("toolkit_detection")
    typosquatting = result.get("typosquatting")
    
    # Display classification
    st.subheader("📊 Detection Result")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.metric("Classification", classification.replace("_", " ").title())
    
    with col2:
        confidence_pct = confidence * 100
        if confidence_pct >= 80:
            conf_class = "confidence-high"
        elif confidence_pct >= 60:
            conf_class = "confidence-medium"
        else:
            conf_class = "confidence-low"
        
        st.markdown(f"""
        <div class="confidence-score {conf_class}">
            Confidence: {confidence_pct:.1f}%
        </div>
        """, unsafe_allow_html=True)
    
    with col3:
        mode = result.get("mode", "unknown")
        st.metric("Detection Mode", mode.upper())
    
    # Get explanation
    with st.spinner("Generating explanation..." if use_llm else "Generating explanation..."):
        explanation = explain_detection(
            url=url,
            classification=classification,
            confidence=confidence,
            features=features,
            use_llm=use_llm
        )
    
    if "error" not in explanation:
        render_explanation(explanation)
    else:
        # Fallback to basic display
        st.warning("Could not generate detailed explanation. Showing basic results.")
        render_basic_result(result)


def render_explanation(explanation: Dict[str, Any]):
    """Render the explanation with all details."""
    
    st.divider()
    st.subheader("💡 Explanation")
    
    # Main explanation
    st.markdown(f"""
    <div style="
        padding: 1rem;
        background-color: #f5f5f5;
        border-radius: 0.5rem;
        margin-bottom: 1rem;
    ">
        {explanation.get('explanation', 'No explanation available')}
    </div>
    """, unsafe_allow_html=True)
    
    # Key factors
    key_factors = explanation.get("key_factors", [])
    if key_factors:
        st.subheader("🔍 Key Factors")
        
        for factor in key_factors:
            risk_level = factor.get("risk_level", "medium")
            if risk_level == "critical":
                risk_class = "risk-critical"
            elif risk_level == "high":
                risk_class = "risk-high"
            else:
                risk_class = "risk-low"
            
            st.markdown(f"""
            <div class="factor-card">
                <strong>{factor.get('name', 'Unknown')}</strong><br>
                <span class="{risk_class}">[{risk_level.upper()}]</span><br>
                {factor.get('description', '')}
            </div>
            """, unsafe_allow_html=True)
    
    # Recommendations
    recommendations = explanation.get("recommendations", [])
    if recommendations:
        st.subheader("✅ Recommendations")
        
        for rec in recommendations:
            st.markdown(f"""
            <div class="recommendation-card">
                • {rec}
            </div>
            """, unsafe_allow_html=True)
    
    # Technical details
    with st.expander("🔧 Technical Details"):
        tech_details = explanation.get("technical_details", {})
        st.write(f"Features Analyzed: {tech_details.get('features_analyzed', 'N/A')}")
        st.write(f"Model Used: {tech_details.get('model_used', 'N/A')}")
        st.write(f"Device: {tech_details.get('device', 'N/A')}")


def render_basic_result(result: Dict[str, Any]):
    """Render basic result without explanation."""
    
    st.subheader("📋 Detection Details")
    
    classification = result.get("classification", "unknown")
    confidence = result.get("confidence", 0.0)
    
    if classification.lower() in ["phishing", "ai_generated_phishing", "phishing_kit"]:
        st.error(f"⚠️ This URL was classified as **{classification.replace('_', ' ').title()}** with {confidence*100:.1f}% confidence.")
        st.markdown("""
        **Recommendations:**
        - Do NOT enter any personal information on this website
        - Do NOT click any links or download files
        - Report this URL to your security team
        """)
    else:
        st.success(f"✅ This URL appears to be **{classification.title()}** with {confidence*100:.1f}% confidence.")
        st.markdown("""
        **Tips:**
        - Always verify the URL before entering information
        - Look for HTTPS in the address bar
        - Be cautious of unexpected login requests
        """)


def render_sidebar():
    """Render sidebar with information."""
    with st.sidebar:
        st.header("ℹ️ About")
        st.markdown("""
        **Phishing Guard** uses machine learning and AI to detect phishing websites.
        
        This explainability feature helps you understand *why* a URL was classified.
        """)
        
        st.header("⚙️ Settings")
        
        api_url = st.text_input("API URL", value=API_BASE_URL)
        if api_url != API_BASE_URL:
            st.session_state["api_url"] = api_url
        
        st.header("📊 Stats")
        
        if check_api_health():
            st.success("✅ API Connected")
        else:
            st.error("❌ API Not Connected")
            st.info("Make sure the API server is running on port 8000")


def render_chat_history():
    """Render chat history section."""
    st.divider()
    st.subheader("💬 Chat History")
    
    if "messages" not in st.session_state:
        st.session_state["messages"] = []
    
    # Display messages
    for i, msg in enumerate(st.session_state["messages"]):
        message(
            msg["content"],
            is_user=msg["role"] == "user",
            key=f"msg_{i}"
        )
    
    # Clear chat button
    if st.session_state["messages"]:
        if st.button("Clear Chat History"):
            st.session_state["messages"] = []
            st.rerun()


# ============== Main App ==============

def main():
    """Main application entry point."""
    
    # Initialize session state
    if "messages" not in st.session_state:
        st.session_state["messages"] = []
    
    if "last_result" not in st.session_state:
        st.session_state["last_result"] = None
    
    # Render components
    render_sidebar()
    render_header()
    
    # URL input
    result = render_url_input()
    
    if result:
        url, use_llm = result
        
        with st.spinner("Analyzing URL..."):
            detection_result = analyze_url(url)
        
        if detection_result and "error" not in detection_result:
            st.session_state["last_result"] = detection_result
            
            # Add to chat
            st.session_state["messages"].append({
                "role": "user",
                "content": f"Analyze: {url}"
            })
            
            # Render result
            render_detection_result(detection_result, use_llm)
            
            # Add response to chat
            st.session_state["messages"].append({
                "role": "assistant",
                "content": f"**{detection_result.get('classification', 'Unknown').replace('_', ' ').title()}** ({detection_result.get('confidence', 0)*100:.1f}% confidence)"
            })
        else:
            st.error("Failed to analyze URL. Please check the URL and try again.")
    
    # Show last result if exists
    elif st.session_state.get("last_result"):
        st.subheader("📌 Last Analysis")
        if st.button("Show Last Result"):
            render_detection_result(st.session_state["last_result"], True)
    
    # Chat history
    render_chat_history()


if __name__ == "__main__":
    main()