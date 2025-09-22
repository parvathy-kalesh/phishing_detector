from flask import Flask, request, render_template
import joblib
import pickle
import ipaddress
import re
from urllib.parse import urlparse
from feature_extractor import prepare_features, extract_Impersonating_Brand

app = Flask(__name__)

# --- Configuration ---
MODEL_PATH = "phishing_model.pkl"
FEATURE_COLUMNS_PATH = "feature_columns.pkl"

# Whitelist of known legitimate domains (can include or exclude www.)
WHITELIST = [
    "google.com", "www.google.com",
    "paypal.com", "www.paypal.com",
    "amazon.com", "www.amazon.com",
    "facebook.com", "www.facebook.com"
]

# Normalize whitelist (strip www. and lowercase) for easier matching
WHITELIST_NORMALIZED = {d.lower().lstrip("www.") for d in WHITELIST}

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
except Exception as e:
    # If model fails to load, set model to None and print a helpful message
    print(f"[WARN] Could not load model from {MODEL_PATH}: {e}")
    model = None

try:
    with open(FEATURE_COLUMNS_PATH, "rb") as f:
        feature_columns = pickle.load(f)
except Exception as e:
    print(f"[WARN] Could not load feature columns from {FEATURE_COLUMNS_PATH}: {e}")
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

            # Run model if undecided
            if result is None:
                try:
                    features_df = prepare_features(url, feature_columns)
                    probs = model.predict_proba(features_df)[0]
                    pred = model.predict(features_df)[0]

                    prob_legit = round(float(probs[0]), 2)
                    prob_phish = round(float(probs[1]), 2)

                    # Optional heuristics: mark additional reasons
                    details["reason_shortening"] = bool(features_df.get("Shortining_Service", [0])[0] == 1)
                    details["reason_impersonating_brand"] = bool(extract_Impersonating_Brand(url) == 1)

                    # Determine final result based on model probability (>0.5)
                    result = "Phishing 🚨" if prob_phish > 0.5 else "Legitimate ✅"

                except Exception as e:
                    print(f"[ERROR] Prediction failed for URL={url}: {e}")
                    result = "Error processing URL"
                    prob_legit, prob_phish = 0.0, 0.0

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










