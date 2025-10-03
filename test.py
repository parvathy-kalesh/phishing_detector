# test_model_accuracy.py

import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report

# -----------------------------
# 1. Load trained model
# -----------------------------
clf = joblib.load("phishing_model_xgb.pkl")
print("✅ Model loaded successfully.\n")

# -----------------------------
# 2. Load dataset
# -----------------------------
df = pd.read_csv("data/phishing_data_fixed.csv")

# Separate features and target
X = df.drop(columns=["Result"])
y = df["Result"]

# -----------------------------
# 3. Split dataset (train/test)
# -----------------------------
X_train, X_test, y_train, y_test = train_test_split(
    X, y,
    test_size=0.3,  # 70% train, 30% test
    random_state=42,
    stratify=y
)

# -----------------------------
# 4. Predict on test set
# -----------------------------
y_pred = clf.predict(X_test)

# -----------------------------
# 5. Evaluate performance
# -----------------------------
print("Accuracy:", accuracy_score(y_test, y_pred))
print("\nConfusion Matrix:\n", confusion_matrix(y_test, y_pred))
print("\nClassification Report:\n", classification_report(y_test, y_pred))

# -----------------------------
# 6. Feature Importances
# -----------------------------
if hasattr(clf, "feature_importances_"):
    print("\n--- Feature Importances ---")
    for name, importance in zip(X.columns, clf.feature_importances_):
        print(f"{name}: {importance:.4f}")
else:
    print("\n⚠️ Model does not have feature_importances_ attribute")

























