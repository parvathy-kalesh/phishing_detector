import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report
import matplotlib.pyplot as plt
import joblib

# -----------------------------
# 1. Load dataset
# -----------------------------
df = pd.read_csv("data/phishing_data_fixed.csv")

# Convert -1 to 0 for binary classification
df["Result"] = df["Result"].replace(-1, 0)

X = df.drop(columns=["Result"])
y = df["Result"]

# -----------------------------
# 2. Split dataset (70/30)
# -----------------------------
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.3, random_state=42, stratify=y
)

# -----------------------------
# 3. Sample weights for Short URLs & new domains
# -----------------------------
weights = pd.Series(1.0, index=X_train.index)
weights[(X_train['Shortining_Service'] == 1) | (X_train['age_of_domain'] == 1)] = 2.5

# -----------------------------
# 4. Parameter tuning manually for plotting
# -----------------------------
n_estimators_list = [20, 50, 80, 100, 120, 150]
train_acc_list = []
test_acc_list = []

for n in n_estimators_list:
    clf = RandomForestClassifier(
        n_estimators=n,
        max_depth=12,
        min_samples_leaf=10,
        max_features="sqrt",
        class_weight="balanced",
        random_state=42,
    )
    clf.fit(X_train, y_train, sample_weight=weights)
    
    y_train_pred = clf.predict(X_train)
    y_test_pred = clf.predict(X_test)
    
    train_acc = accuracy_score(y_train, y_train_pred)
    test_acc = accuracy_score(y_test, y_test_pred)
    
    train_acc_list.append(train_acc)
    test_acc_list.append(test_acc)

# -----------------------------
# 5. Plot train/test accuracy vs n_estimators
# -----------------------------
plt.figure(figsize=(10,6))
plt.plot(n_estimators_list, train_acc_list, marker='o', label='Train Accuracy')
plt.plot(n_estimators_list, test_acc_list, marker='o', label='Test Accuracy')
plt.xlabel("Number of Trees (n_estimators)")
plt.ylabel("Accuracy")
plt.title("Random Forest Accuracy vs Number of Trees")
plt.legend()
plt.grid(True)
plt.tight_layout()
plt.show()

# -----------------------------
# 6. Train final model (best choice)
# -----------------------------
best_n_estimators = 100  # choose based on plot
final_clf = RandomForestClassifier(
    n_estimators=best_n_estimators,
    max_depth=12,
    min_samples_leaf=10,
    max_features="sqrt",
    class_weight="balanced",
    random_state=42,
)
final_clf.fit(X_train, y_train, sample_weight=weights)

# -----------------------------
# 7. Evaluate final model
# -----------------------------
y_pred = final_clf.predict(X_test)
print(f"\nTrain Accuracy: {accuracy_score(y_train, final_clf.predict(X_train)):.4f}")
print(f"Test Accuracy: {accuracy_score(y_test, y_pred):.4f}")
print("\nConfusion Matrix (Test Set):\n", confusion_matrix(y_test, y_pred))
print("\nClassification Report (Test Set):\n", classification_report(y_test, y_pred))

# -----------------------------
# 8. Feature importance
# -----------------------------
importances = final_clf.feature_importances_
indices = importances.argsort()[::-1]

plt.figure(figsize=(12,6))
plt.title("Feature Importances (Weighted & Tuned RF)")
plt.bar(range(len(importances)), importances[indices], align="center")
plt.xticks(range(len(importances)), [X.columns[i] for i in indices], rotation=90)
plt.tight_layout()
plt.show()

# -----------------------------
# 9. Save the final model
# -----------------------------
joblib.dump(final_clf, "phishing_model_weighted_tuned_final.pkl")
print("\n✅ Model saved as phishing_model_weighted_tuned_final.pkl")













