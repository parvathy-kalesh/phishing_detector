from flask import Flask, request, render_template_string
import pickle
import pandas as pd
from feature_extractor import prepare_features  # Use prepare_features instead of extract_features

app = Flask(__name__)

# Load model and feature columns
with open('phishing_model.pkl', 'rb') as f:
    model = pickle.load(f)

with open('feature_columns.pkl', 'rb') as f:
    feature_columns = pickle.load(f)

HTML = """
<!DOCTYPE html>
<html>
<head><title>Phishing URL Detection</title></head>
<body>
<h2>🔍 Phishing URL Detector</h2>
<form method="POST">
    <input type="text" name="url" placeholder="Enter a URL" required>
    <input type="submit" value="Check">
</form>
{% if url %}
    <p><strong>URL Entered:</strong> {{ url }}</p>
{% endif %}
{% if result %}
    <h3>Result: {{ result }}</h3>
{% endif %}
</body>
</html>
"""

@app.route('/', methods=['GET', 'POST'])
def home():
    result = None
    url = None
    if request.method == 'POST':
        url = request.form['url']
        features_df = prepare_features(url, feature_columns)
        
        # Heuristic override
        if features_df['Shortining_Service'].iloc[0] == 1:
            result = "Phishing 🚨"
        else:
            pred = model.predict(features_df)[0]
            result = "Phishing 🚨" if pred == 1 else "Legitimate ✅"

    return render_template_string(HTML, result=result, url=url)


if __name__ == '__main__':
    app.run(debug=True)





