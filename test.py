# train_test_accuracy_graph.py

import pandas as pd
import matplotlib.pyplot as plt
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report

# -----------------------------
# 1. Load dataset
# -----------------------------
df = pd.read_csv("data/phishing_data_fixed.csv")

# Fix class labels: convert -1 -> 0 for legitimate
df["Result"] = df["Result"].replace(-1, 0)

# Separate features and target
X = df.drop(columns=["Result"])
y = df["Result"]

# -----------------------------
# 2. Split dataset (70/30)
# -----------------------------
X_train, X_test, y_train, y_test = train_test_split(
    X, y,
    test_size=0.3,
    random_state=42,
    stratify=y
)

# -----------------------------
# 3. Train Random Forest
# -----------------------------
clf = RandomForestClassifier(
    n_estimators=100,
    max_depth=None,
    max_features="sqrt",
    min_samples_leaf=5,
    class_weight="balanced",
    random_state=42
)
clf.fit(X_train, y_train)

# -----------------------------
# 4. Predict and evaluate
# -----------------------------
y_train_pred = clf.predict(X_train)
y_test_pred = clf.predict(X_test)

train_acc = accuracy_score(y_train, y_train_pred)
test_acc = accuracy_score(y_test, y_test_pred)

print(f"Train Accuracy: {train_acc:.4f}")
print(f"Test Accuracy: {test_acc:.4f}")

print("\nConfusion Matrix (Test Set):\n", confusion_matrix(y_test, y_test_pred))
print("\nClassification Report (Test Set):\n", classification_report(y_test, y_test_pred))

# -----------------------------
# 5. Feature importances plot
# -----------------------------
importances = clf.feature_importances_
feature_names = X.columns
indices = importances.argsort()[::-1]

plt.figure(figsize=(12,6))
plt.title("Feature Importances")
plt.bar(range(len(importances)), importances[indices], align="center")
plt.xticks(range(len(importances)), [feature_names[i] for i in indices], rotation=90)
plt.tight_layout()
plt.show()

# -----------------------------
# 6. Train/Test Accuracy comparison graph
# -----------------------------
plt.figure(figsize=(6,4))
plt.bar(["Train Accuracy", "Test Accuracy"], [train_acc, test_acc], color=["green", "blue"])
plt.ylim(0,1)
plt.ylabel("Accuracy")
plt.title("Random Forest Accuracy Comparison")
plt.show()

























