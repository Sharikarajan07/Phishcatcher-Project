import streamlit as st
import pickle
import numpy as np
import pandas as pd
from urllib.parse import urlparse
from feature_extraction import extract_features, TRUSTED_DOMAINS

def sanitize_url(raw):
    return raw.replace('[.]', '.').replace('[', '%5B').replace(']', '%5D')

@st.cache_resource
def load_artifacts():
    with open("phishcatcher_model.pkl", "rb") as f:
        model = pickle.load(f)
    with open("label_encoder.pkl", "rb") as f:
        le = pickle.load(f)
    return model, le

model, le = load_artifacts()

# Sidebar UI
st.sidebar.title("⚙️ Settings & Help")
st.sidebar.write("**Trusted domains**")
for d in TRUSTED_DOMAINS:
    st.sidebar.write(f"• {d}")
st.sidebar.markdown("---")
st.sidebar.info("Enter a URL and click **Analyze** to check threat status.")

# Main App UI
st.title("🛡️ PhishCatcher – URL Threat Detector")
url_input = st.text_input("🔗 Enter URL", placeholder="https://example.com")

if st.button("Analyze"):
    raw = url_input.strip()
    if not raw:
        st.warning("⚠️ Please enter a valid URL.")
    else:
        clean = sanitize_url(raw)
        try:
            parsed = urlparse(clean)
        except ValueError:
            st.error("❌ Invalid URL format.")
            st.stop()

        domain = parsed.netloc.lower().removeprefix("www.")

        if domain in TRUSTED_DOMAINS:
            st.success(f"✅ Trusted domain **{domain}** — classified as **Benign**")
        else:
            features = extract_features(clean)
            if not features or len(features) != model.n_features_in_:
                st.error(f"❌ Feature mismatch: expected {model.n_features_in_}, got {len(features) if features else 'None'}.")
            else:
                probs = model.predict_proba([features])[0]
                pred = int(np.argmax(probs))
                confidence = probs[pred]
                label = le.inverse_transform([pred])[0].title()
                emojis = {"Phishing": "⚠️", "Benign": "✅", "Malware": "❗", "Defacement": "🚫"}

                st.markdown(f"### 🔍 Prediction: **{label} {emojis.get(label, '')}**")
                st.write(f"**Confidence:** {confidence:.2f}")

                # Probability bar chart
                prob_df = pd.DataFrame({
                    "Class": [cls.title() for cls in le.classes_],
                    "Probability": probs
                }).sort_values("Probability", ascending=True)
                st.bar_chart(prob_df.set_index("Class"), use_container_width=True)
