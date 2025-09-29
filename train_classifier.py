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
X = df.drop(columns=["Result"])  # Keep all 31 columns
y = df["Result"]

# -----------------------------
# 2. Split data (80/20)
# -----------------------------
X_train, X_test, y_train, y_test = train_test_split(
    X, y,
    test_size=0.3,   # 70% train, 30% test
    random_state=42,
    stratify=y
)
# -----------------------------
# 3. Initialize Random Forest
# -----------------------------
clf = RandomForestClassifier(
    n_estimators=100,      # number of trees
    max_depth=10,          # limit depth to reduce overfitting
    max_features="sqrt",   # features considered at each split
    min_samples_leaf=5,    # each leaf must have at least 5 samples
    class_weight="balanced",
    random_state=42
)

# -----------------------------
# 4. Train the model
# -----------------------------
clf.fit(X_train, y_train)

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
joblib.dump(clf, "phishing_model.pkl")
print("\n✅ Model saved as phishing_model.pkl")









