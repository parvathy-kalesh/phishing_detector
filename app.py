from flask import Flask, request, render_template
import joblib
import pickle
import ipaddress
import re
from urllib.parse import urlparse
from feature_extractor import prepare_features, extract_Impersonating_Brand

app = Flask(__name__)

# --- Configuration ---
MODEL_PATH = "phishing_model_weighted.pkl"
FEATURE_COLUMNS_PATH = "feature_columns.pkl"

# Whitelist of known legitimate domains
WHITELIST = [
    "google.com", "www.google.com",
    "paypal.com", "www.paypal.com",
    "amazon.com", "www.amazon.com",
    "facebook.com", "www.facebook.com"
]

# Normalize whitelist
WHITELIST_NORMALIZED = {d.lower().lstrip("www.") for d in WHITELIST}

# Brand keywords for impersonation check
BRAND_KEYWORDS = ["paypal", "google", "amazon", "facebook"]

# --- Helper functions ---
def is_valid_url(url: str) -> bool:
    """Basic URL validation using urlparse."""
    try:
        parsed = urlparse(url)
        return bool(parsed.scheme and parsed.netloc)
    except Exception:
        return False

_ip_pattern = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
def is_ip_address(hostname: str) -> bool:
    """Return True if hostname looks like an IPv4 address."""
    if not hostname:
        return False
    return bool(_ip_pattern.match(hostname))

def normalize_domain(hostname: str) -> str:
    """Lowercase and strip leading 'www.' from hostname."""
    if not hostname:
        return ""
    host = hostname.lower()
    if host.startswith("www."):
        host = host[4:]
    return host

# --- Load model and feature columns ---
model = None
feature_columns = None

try:
    model = joblib.load(MODEL_PATH)
    print(f"[INFO] Loaded model from {MODEL_PATH}")
except Exception as e:
    print(f"[WARN] Could not load model: {e}")
    model = None

try:
    with open(FEATURE_COLUMNS_PATH, "rb") as f:
        feature_columns = pickle.load(f)
    print(f"[INFO] Loaded feature columns from {FEATURE_COLUMNS_PATH}")
except Exception as e:
    print(f"[WARN] Could not load feature columns: {e}")
    feature_columns = None

# --- Routes ---
@app.route("/")
def welcome():
    return render_template("welcome.html")

@app.route("/check", methods=["GET", "POST"])
def check_url():
    result = None
    url = None
    prob_legit = 0.0
    prob_phish = 0.0
    details = {}

    if request.method == "POST":
        url = request.form.get("url", "").strip()

        if not url:
            result = "Please enter a URL."
        elif not is_valid_url(url):
            result = "Invalid URL ❌"
        else:
            parsed = urlparse(url)
            hostname = parsed.hostname
            normalized = normalize_domain(hostname)

            # Localhost / Private IP checks
            if normalized in ("localhost", "127.0.0.1"):
                result = "Legitimate ✅ (Local URL)"
                prob_legit, prob_phish = 1.0, 0.0
            elif is_ip_address(hostname):
                try:
                    ip_obj = ipaddress.ip_address(hostname)
                    if ip_obj.is_private:
                        result = "Legitimate ✅ (Private IP)"
                        prob_legit, prob_phish = 1.0, 0.0
                except ValueError:
                    pass

            # Whitelist check
            if result is None and normalized in WHITELIST_NORMALIZED:
                result = "Legitimate ✅"
                prob_legit, prob_phish = 1.0, 0.0

            # Brand impersonation check
            if result is None:
                for brand in BRAND_KEYWORDS:
                    if brand in normalized and normalized not in WHITELIST_NORMALIZED:
                        result = f"Phishing 🚨 (Impersonating {brand})"
                        prob_legit, prob_phish = 0.0, 1.0
                        details["reason_impersonating_brand"] = f"Suspicious use of brand: {brand}"
                        break

            # Run ML model if undecided
            if result is None and model is not None and feature_columns is not None:
                try:
                    features_df = prepare_features(url, feature_columns)
                    probs = model.predict_proba(features_df)[0]
                    pred = model.predict(features_df)[0]

                    prob_legit = round(float(probs[0]), 2)
                    prob_phish = round(float(probs[1]), 2)

                    # Extra details (heuristics)
                    details["reason_shortening"] = (
                        "Likely shortened URL" if "Shortining_Service" in features_df.columns and features_df["Shortining_Service"].iloc[0] == 1 else None
                    )
                    if extract_Impersonating_Brand(url) == 1:
                        details["reason_impersonating_brand"] = "Impersonating brand detected"

                    # Decision with threshold
                    if prob_phish >= 0.6:
                        result = "Phishing 🚨"
                    elif prob_legit >= 0.6:
                        result = "Legitimate ✅"
                    else:
                        result = "Suspicious ⚠️ (Unclear)"
                except Exception as e:
                    print(f"[ERROR] Prediction failed for URL={url}: {e}")
                    result = "Error processing URL"
                    prob_legit, prob_phish = 0.0, 0.0

            elif result is None:
                result = "Model not available ❌"

    return render_template(
        "check_url.html",
        result=result,
        url=url,
        prob_legit=f"{prob_legit:.2f}",
        prob_phish=f"{prob_phish:.2f}",
        details=details
    )

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)











