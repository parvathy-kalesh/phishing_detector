import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
import matplotlib.pyplot as plt
import joblib

# -----------------------------
# 1. Load dataset
# -----------------------------
df = pd.read_csv("data/phishing_data_fixed.csv")
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
# 4. Vary max_depth to reduce overfitting
# -----------------------------
max_depth_list = [2, 4, 6, 8, 10, 12]
train_acc_list = []
test_acc_list = []

for depth in max_depth_list:
    clf = RandomForestClassifier(
        n_estimators=50,
        max_depth=depth,
        min_samples_leaf=20,
        max_features="log2",
        class_weight="balanced",
        random_state=42,
    )
    clf.fit(X_train, y_train, sample_weight=weights)

    train_acc = accuracy_score(y_train, clf.predict(X_train))
    test_acc = accuracy_score(y_test, clf.predict(X_test))

    train_acc_list.append(train_acc)
    test_acc_list.append(test_acc)

# -----------------------------
# 5. Plot train vs test accuracy
# -----------------------------
plt.figure(figsize=(10,6))
plt.plot(max_depth_list, train_acc_list, marker='o', label='Train Accuracy')
plt.plot(max_depth_list, test_acc_list, marker='o', label='Test Accuracy')
plt.xlabel("Max Depth")
plt.ylabel("Accuracy")
plt.title("Random Forest Accuracy vs Max Depth (Weighted)")
plt.legend()
plt.grid(True)
plt.tight_layout()
plt.show()

# -----------------------------
# 6. Train final model with chosen max_depth
# -----------------------------
best_depth = 6  # pick based on graph to balance train/test accuracy
final_clf = RandomForestClassifier(
    n_estimators=50,
    max_depth=best_depth,
    min_samples_leaf=20,
    max_features="log2",
    class_weight="balanced",
    random_state=42,
)
final_clf.fit(X_train, y_train, sample_weight=weights)

# -----------------------------
# 7. Evaluate final model
# -----------------------------
y_train_pred = final_clf.predict(X_train)
y_test_pred = final_clf.predict(X_test)

print(f"\nTrain Accuracy: {accuracy_score(y_train, y_train_pred):.4f}")
print(f"Test Accuracy: {accuracy_score(y_test, y_test_pred):.4f}")

# -----------------------------
# 8. Save the final model
# -----------------------------
joblib.dump(final_clf, "phishing_model_weighted_graph.pkl")
print("\n✅ Model saved as phishing_model_weighted_graph.pkl")







