"""
FraudShield Streamlit UI
A demo interface for the multi-modal fraud detection API.
"""

import json
from typing import Optional, Dict, Any

import requests
import streamlit as st


st.set_page_config(
    page_title="FraudShield Demo",
    page_icon="🛡️",
    layout="wide",
)


# ---------- Helpers ----------


def call_analyze(
    base_url: str,
    api_key: Optional[str],
    type_: str,
    text: Optional[str] = None,
    url: Optional[str] = None,
    file_bytes: Optional[bytes] = None,
    file_name: Optional[str] = None,
    file_type: Optional[str] = None,
    source_hint: Optional[str] = None,
) -> Dict[str, Any]:
    """Call FraudShield /analyze endpoint with multipart/form-data."""

    endpoint = base_url.rstrip("/") + "/analyze"

    data = {
        "type": type_,
        "text": text or "",
        "url": url or "",
        "source_hint": source_hint or "",
    }

    files = {}
    if file_bytes is not None and file_name is not None:
        files["file"] = (file_name, file_bytes, file_type or "application/octet-stream")

    headers = {}
    if api_key:
        headers["X-API-Key"] = api_key

    resp = requests.post(endpoint, data=data, files=files, headers=headers or None, timeout=120)
    resp.raise_for_status()
    return resp.json()


def render_result(result: Dict[str, Any]):
    """Render analysis result in a nice format."""
    st.subheader("🔎 Result")
    
    # Risk level color coding
    risk_level = result.get("risk_level", "N/A")
    risk_colors = {"LOW": "🟢", "MEDIUM": "🟡", "HIGH": "🔴", "UNKNOWN": "⚪"}
    risk_icon = risk_colors.get(risk_level, "⚪")
    
    col1, col2, col3 = st.columns(3)

    with col1:
        st.metric("Risk Level", f"{risk_icon} {risk_level}")
    
    with col2:
        st.metric("Overall Score", f"{result.get('overall_score', 0.0):.2f}/10")
    
    with col3:
        confidence = result.get("confidence")
        if confidence is not None:
            st.metric("Confidence", f"{confidence:.1%}")
        else:
            st.metric("Confidence", "N/A")

    # Recommendations (if present)
    recommendations = result.get("recommendations") or []
    if recommendations:
        st.divider()
        st.markdown("### 💡 Recommendations")
        for rec in recommendations:
            st.markdown(f"- {rec}")

    st.divider()
    
    col_left, col_right = st.columns(2)

    with col_left:
        # Feature breakdown (explainability)
        explainability = result.get("explainability") or {}
        feature_breakdown = explainability.get("feature_breakdown") or []
        
        if feature_breakdown:
            st.markdown("**📊 Feature Breakdown**")
            for feat in feature_breakdown[:5]:
                weight_bar = "█" * int(feat.get("weight", 0) * 5)
                st.write(f"- **{feat.get('feature')}** (+{feat.get('contribution', 0):.1f})")
                st.caption(f"  {feat.get('description', '')}")
        else:
            modality_scores = result.get("modality_scores") or {}
            if modality_scores:
                st.markdown("**📊 Per-modality scores**")
                for m, s in modality_scores.items():
                    st.write(f"- `{m}`: {s:.2f}")

        indicators = result.get("indicators") or []
        if indicators:
            st.markdown("**🚩 Indicators**")
            for ind in indicators[:8]:
                st.write(f"- {ind}")
            if len(indicators) > 8:
                st.write(f"... and {len(indicators) - 8} more")

    with col_right:
        st.markdown("**📝 Summary**")
        # Show explainability summary if available
        if explainability and explainability.get("summary"):
            st.info(explainability.get("summary"))
        
        st.markdown("**📝 Detailed Explanation**")
        explanation = result.get("explanation", "No explanation provided.")
        st.text_area("", explanation, height=180, disabled=True, label_visibility="collapsed")

    # Category breakdown
    category_scores = explainability.get("category_scores") if explainability else None
    if category_scores:
        with st.expander("📈 Risk by Category"):
            for cat, score in sorted(category_scores.items(), key=lambda x: x[1], reverse=True):
                st.write(f"**{cat.title()}**: {score:.2f}")

    with st.expander("🔧 Raw JSON response"):
        st.json(result)


# ---------- Sidebar config ----------


st.sidebar.title("⚙️ Settings")

base_url = st.sidebar.text_input(
    "Backend URL",
    value="http://127.0.0.1:8000",
    help="FastAPI server base URL.",
)

api_key = st.sidebar.text_input(
    "API Key (optional)",
    type="password",
    help="If you secure /analyze with X-API-Key, put it here.",
)

st.sidebar.markdown("---")

# Status check
if st.sidebar.button("🔌 Check Connection"):
    try:
        resp = requests.get(f"{base_url.rstrip('/')}/health", timeout=5)
        if resp.status_code == 200:
            st.sidebar.success("✅ Backend is online!")
        else:
            st.sidebar.error(f"❌ Backend returned {resp.status_code}")
    except Exception as e:
        st.sidebar.error(f"❌ Cannot connect: {e}")

st.sidebar.markdown("---")
st.sidebar.markdown("Select a tab to analyze text, URLs, audio, images, or combine them.")


# ---------- Main UI ----------


st.title("🛡️ FraudShield")
st.markdown("**Multi-Modal AI Fraud Detection Demo**")
st.markdown("---")

tabs = st.tabs(["📝 Text", "🔗 URL", "🎙️ Audio", "🖼️ Image", "🔀 Multi-Modal"])


# --- TEXT TAB ---
with tabs[0]:
    st.header("Text Scam / Fraud Analysis")
    st.markdown("Analyze messages, emails, or chat content for fraud indicators.")

    text = st.text_area(
        "Paste a message, email, or chat content",
        height=200,
        placeholder="Example: Hi, this is Tech Support. Please send me the verification code you just received...",
    )

    if st.button("🔍 Analyze Text", key="analyze_text", type="primary"):
        if not text.strip():
            st.warning("Please enter some text.")
        else:
            with st.spinner("Analyzing..."):
                try:
                    result = call_analyze(
                        base_url=base_url,
                        api_key=api_key,
                        type_="text",
                        text=text,
                    )
                    render_result(result)
                except requests.exceptions.HTTPError as e:
                    st.error(f"API Error: {e.response.status_code} - {e.response.text}")
                except Exception as e:
                    st.error(f"Error calling backend: {e}")


# --- URL TAB ---
with tabs[1]:
    st.header("URL / Link Analysis")
    st.markdown("Check if a URL is potentially phishing or malicious.")

    url_val = st.text_input(
        "Paste a URL",
        placeholder="https://secure-login-paypal.com/account/verify?otp=123456",
    )

    if st.button("🔍 Analyze URL", key="analyze_url", type="primary"):
        if not url_val.strip():
            st.warning("Please enter a URL.")
        else:
            with st.spinner("Analyzing..."):
                try:
                    result = call_analyze(
                        base_url=base_url,
                        api_key=api_key,
                        type_="url",
                        url=url_val,
                    )
                    render_result(result)
                except requests.exceptions.HTTPError as e:
                    st.error(f"API Error: {e.response.status_code} - {e.response.text}")
                except Exception as e:
                    st.error(f"Error calling backend: {e}")


# --- AUDIO TAB ---
with tabs[2]:
    st.header("Audio Scam Call Analysis")
    st.markdown("Upload a recording of a suspicious call to analyze.")

    audio_file = st.file_uploader(
        "Upload an audio file (e.g., .wav, .mp3)",
        type=["wav", "mp3", "m4a"],
    )

    if audio_file is not None:
        st.audio(audio_file)

    if st.button("🔍 Analyze Audio", key="analyze_audio", type="primary"):
        if audio_file is None:
            st.warning("Please upload an audio file.")
        else:
            with st.spinner("Transcribing and analyzing... (this may take a moment)"):
                try:
                    result = call_analyze(
                        base_url=base_url,
                        api_key=api_key,
                        type_="audio",
                        file_bytes=audio_file.getvalue(),
                        file_name=audio_file.name,
                        file_type=audio_file.type,
                        source_hint="audio",
                    )
                    render_result(result)
                except requests.exceptions.HTTPError as e:
                    st.error(f"API Error: {e.response.status_code} - {e.response.text}")
                except Exception as e:
                    st.error(f"Error calling backend: {e}")


# --- IMAGE TAB ---
with tabs[3]:
    st.header("Screenshot / Image Analysis")
    st.markdown("Upload a screenshot of a suspicious login page, email, OTP prompt, etc.")

    image_file = st.file_uploader(
        "Upload a screenshot",
        type=["png", "jpg", "jpeg", "webp"],
    )

    if image_file is not None:
        st.image(image_file, caption="Uploaded image", use_container_width=True)

    if st.button("🔍 Analyze Image", key="analyze_image", type="primary"):
        if image_file is None:
            st.warning("Please upload an image.")
        else:
            with st.spinner("Analyzing image with vision model..."):
                try:
                    result = call_analyze(
                        base_url=base_url,
                        api_key=api_key,
                        type_="image",
                        file_bytes=image_file.getvalue(),
                        file_name=image_file.name,
                        file_type=image_file.type,
                        source_hint="image",
                    )
                    render_result(result)
                except requests.exceptions.HTTPError as e:
                    st.error(f"API Error: {e.response.status_code} - {e.response.text}")
                except Exception as e:
                    st.error(f"Error calling backend: {e}")


# --- MULTI TAB ---
with tabs[4]:
    st.header("Multi-Modal Analysis")
    st.markdown("Combine text, URL, and file analysis for comprehensive fraud detection.")

    mm_text = st.text_area(
        "Optional: message or email text",
        height=150,
        placeholder="Example: Dear customer, your account will be closed unless you verify...",
        key="mm_text",
    )

    mm_url = st.text_input(
        "Optional: URL",
        placeholder="https://secure-login-paypal.com/account/verify?otp=123456",
        key="mm_url",
    )

    mm_file = st.file_uploader(
        "Optional: upload audio or screenshot",
        type=["wav", "mp3", "m4a", "png", "jpg", "jpeg", "webp"],
        key="multi_file",
    )

    source_hint = st.selectbox(
        "What is the file?",
        options=["image (default)", "audio"],
        key="source_hint",
    )

    if mm_file is not None:
        if "image" in (mm_file.type or ""):
            st.image(mm_file, caption="Uploaded image", use_container_width=True)
        elif "audio" in (mm_file.type or ""):
            st.audio(mm_file)

    if st.button("🔍 Analyze Multi-Modal", key="analyze_multi", type="primary"):
        if not mm_text and not mm_url and mm_file is None:
            st.warning("Provide at least one of: text, URL, file.")
        else:
            with st.spinner("Running multi-modal analysis..."):
                try:
                    hint_val = "audio" if source_hint == "audio" else "image"

                    result = call_analyze(
                        base_url=base_url,
                        api_key=api_key,
                        type_="multi",
                        text=mm_text if mm_text else None,
                        url=mm_url if mm_url else None,
                        file_bytes=mm_file.getvalue() if mm_file else None,
                        file_name=mm_file.name if mm_file else None,
                        file_type=mm_file.type if mm_file else None,
                        source_hint=hint_val,
                    )
                    render_result(result)
                except requests.exceptions.HTTPError as e:
                    st.error(f"API Error: {e.response.status_code} - {e.response.text}")
                except Exception as e:
                    st.error(f"Error calling backend: {e}")


# --- Footer ---
st.markdown("---")
st.markdown(
    "<div style='text-align: center; color: gray;'>"
    "FraudShield v0.1.0 • Multi-Modal AI Fraud Detection"
    "</div>",
    unsafe_allow_html=True,
)

