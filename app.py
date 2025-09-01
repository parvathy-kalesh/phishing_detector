from flask import Flask, request, render_template
import joblib
import pickle
from urllib.parse import urlparse
from feature_extractor import prepare_features, extract_Impersonating_Brand

app = Flask(__name__)

# Whitelist of known legitimate domains
WHITELIST = [
    "google.com", "www.google.com",
    "paypal.com", "www.paypal.com",
    "amazon.com", "www.amazon.com",
    "facebook.com", "www.facebook.com"
]

def is_valid_url(url):
    try:
        parsed = urlparse(url)
        return all([parsed.scheme, parsed.netloc])
    except:
        return False

# Load model and feature columns
model = joblib.load('phishing_model.pkl')
with open('feature_columns.pkl', 'rb') as f:
    feature_columns = pickle.load(f)

# --- Routes ---

@app.route('/')
def welcome():
    return render_template('welcome.html')

@app.route('/check', methods=['GET', 'POST'])
def check_url():
    result = None
    url = None
    prob_legit = prob_phish = None

    if request.method == 'POST':
        url = request.form['url']

        if not is_valid_url(url):
            result = "Invalid URL ❌"
        else:
            domain = urlparse(url).netloc.lower()

            # Check whitelist first
            if domain in WHITELIST:
                result = "Legitimate ✅"
                prob_legit, prob_phish = 1.0, 0.0
            else:
                features_df = prepare_features(url, feature_columns)
                probs = model.predict_proba(features_df)[0]
                pred = model.predict(features_df)[0]

                prob_legit = round(probs[0], 2)
                prob_phish = round(probs[1], 2)

                phishing_flag = False
                if features_df['Shortining_Service'].iloc[0] == 1:
                    phishing_flag = True
                elif extract_Impersonating_Brand(url) == 1:
                    phishing_flag = True
                elif pred == 1 and prob_phish > 0.5:
                    phishing_flag = True

                result = "Phishing 🚨" if phishing_flag else "Legitimate ✅"

    return render_template('check_url.html', result=result, url=url,
                           prob_legit=prob_legit, prob_phish=prob_phish)

if __name__ == '__main__':
    app.run(debug=True)










