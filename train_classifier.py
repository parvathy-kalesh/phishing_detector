import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import joblib

# -----------------------------
# 1. Load dataset
# -----------------------------
df = pd.read_csv("data/phishing_data_fixed.csv")

# Features and target
X = df.drop(columns=["Result"])
y = df["Result"]

# -----------------------------
# 2. Split data (70/30)
# -----------------------------
X_train, X_test, y_train, y_test = train_test_split(
    X, y,
    test_size=0.3,
    random_state=42,
    stratify=y
)

# -----------------------------
# 2a. Create sample weights to emphasize short URLs and new domains
# -----------------------------
weights = pd.Series(1.0, index=X_train.index)
weights[(X_train['Shortining_Service'] == 1) | (X_train['age_of_domain'] == 1)] = 2.0
# Slightly increase weight (2x) so model pays more attention to these features

# -----------------------------
# 3. Random Forest (original params)
# -----------------------------
clf = RandomForestClassifier(
    n_estimators=50,
    max_depth=6,
    max_features="sqrt",
    min_samples_leaf=10,
    class_weight="balanced",
    random_state=42
)

# -----------------------------
# 4. Train the model with sample weights
# -----------------------------
clf.fit(X_train, y_train, sample_weight=weights)

# -----------------------------
# 5. Predict and evaluate
# -----------------------------
y_pred = clf.predict(X_test)

print("Accuracy:", accuracy_score(y_test, y_pred))
print("\nConfusion Matrix:\n", confusion_matrix(y_test, y_pred))
print("\nClassification Report:\n", classification_report(y_test, y_pred))

# -----------------------------
# 6. Save the trained model
# -----------------------------
joblib.dump(clf, "phishing_model_weighted.pkl")
print("\n✅ Model saved as phishing_model_weighted.pkl")













