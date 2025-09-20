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
            # parse hostname and normalize
            parsed = urlparse(url)
            hostname = parsed.hostname  # Usually returns None-safe hostname
            normalized = normalize_domain(hostname)

            # Check local hostnames explicitly
            try:
                if normalized in ("localhost", "127.0.0.1"):
                    result = "Legitimate ✅ (Local URL)"
                    prob_legit, prob_phish = 1.0, 0.0

                # If hostname looks like IP, check if it's private
                elif is_ip_address(hostname):
                    try:
                        ip_obj = ipaddress.ip_address(hostname)
                        if ip_obj.is_private:
                            result = "Legitimate ✅ (Private IP)"
                            prob_legit, prob_phish = 1.0, 0.0
                        else:
                            # public IP — treat like any other domain (fall through to ML)
                            pass
                    except ValueError:
                        # invalid IP format (shouldn't happen if is_ip_address True)
                        pass

                # Whitelist check (normalized)
                if result is None and normalized in WHITELIST_NORMALIZED:
                    result = "Legitimate ✅"
                    prob_legit, prob_phish = 1.0, 0.0

                # If still undecided, run ML + heuristic checks
                if result is None:
                    # Ensure feature_columns available
                    if feature_columns is None or model is None:
                        # Cannot run model; mark unknown but do some basic heuristic checks
                        # Heuristic checks: shortening service + impersonating brand
                        short_flag = False
                        try:
                            features_df = prepare_features(url, feature_columns if feature_columns is not None else [])
                            short_flag = bool(features_df.get("Shortining_Service", [0])[0])
                        except Exception:
                            short_flag = False

                        brand_flag = False
                        try:
                            brand_flag = bool(extract_Impersonating_Brand(url) == 1)
                        except Exception:
                            brand_flag = False

                        if short_flag or brand_flag:
                            result = "Phishing 🚨 (heuristic)"
                            prob_legit, prob_phish = 0.0, 1.0
                        else:
                            result = "Unknown — model not loaded"
                            prob_legit, prob_phish = 0.0, 0.0
                    else:
                        # Run feature extraction and model prediction
                        try:
                            features_df = prepare_features(url, feature_columns)
                            probs = model.predict_proba(features_df)[0]
                            pred = model.predict(features_df)[0]

                            # probs ordering assumed [legit_prob, phish_prob]
                            prob_legit = round(float(probs[0]), 2)
                            prob_phish = round(float(probs[1]), 2)

                            # Heuristic checks
                            phishing_flag = False
                            try:
                                if features_df.get("Shortining_Service", [0])[0] == 1:
                                    phishing_flag = True
                                    details["reason_shortening"] = True
                            except Exception:
                                pass

                            try:
                                if extract_Impersonating_Brand(url) == 1:
                                    phishing_flag = True
                                    details["reason_impersonating_brand"] = True
                            except Exception:
                                pass

                            # model prediction threshold
                            if pred == 1 and prob_phish > 0.5:
                                phishing_flag = True
                                details["reason_model_predicted"] = True

                            result = "Phishing 🚨" if phishing_flag else "Legitimate ✅"

                        except Exception as e:
                            # Catch any unexpected errors during feature extraction/prediction
                            print(f"[ERROR] Prediction failed for URL={url}: {e}")
                            result = "Error processing URL"
                            prob_legit, prob_phish = 0.0, 0.0

            except Exception as outer_e:
                # Any unexpected outer errors (parsing etc.)
                print(f"[ERROR] Unexpected error checking URL {url}: {outer_e}")
                result = "Invalid URL ❌"
                prob_legit, prob_phish = 0.0, 0.0

    # Render the check template with consistent numeric probabilities
    return render_template(
        "check_url.html",
        result=result,
        url=url,
        prob_legit=f"{prob_legit:.2f}" if prob_legit is not None else "0.00",
        prob_phish=f"{prob_phish:.2f}" if prob_phish is not None else "0.00",
        details=details
    )

if __name__ == "__main__":
    # WARNING: debug=True should NOT be used in production
    app.run(host="0.0.0.0", port=5000, debug=False)










