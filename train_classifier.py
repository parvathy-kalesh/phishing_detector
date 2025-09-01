from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import pandas as pd
import joblib

# Load dataset
df = pd.read_csv("data/phishing_data_fixed.csv")

# Features and target
X = df.drop(columns=["Result"])  # drop only the target
y = df["Result"]

# Split data
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

# Initialize Random Forest with balanced class weights
clf = RandomForestClassifier(
    n_estimators=100,
    class_weight="balanced",  # ✅ balances minority class
    random_state=42
)

# Train
clf.fit(X_train, y_train)

# Predict
y_pred = clf.predict(X_test)

# Evaluate
print("Accuracy:", accuracy_score(y_test, y_pred))
print("Confusion Matrix:\n", confusion_matrix(y_test, y_pred))
print("Classification Report:\n", classification_report(y_test, y_pred))

# Save model
joblib.dump(clf, "phishing_model.pkl")
print("✅ Model saved as phishing_model.pkl")









