import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
import xgboost as xgb
import joblib
import pickle

# 1. Load dataset
df = pd.read_csv("phishing_dataset.csv")

# 2. Separate features and labels
X = df.drop("phishing", axis=1)
y = df["phishing"]

# 3. Train-test split (stratify to keep phishing/legit ratio)
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

# 4. Train XGBoost model
model = xgb.XGBClassifier(
    n_estimators=200,       # number of trees
    max_depth=6,            # tree depth, lower to reduce overfitting
    learning_rate=0.1,      # step size shrinkage
    subsample=0.8,          # fraction of samples per tree
    colsample_bytree=0.8,   # fraction of features per tree
    scale_pos_weight=1,     # adjust if phishing class is imbalanced
    random_state=42,
    use_label_encoder=False,
    eval_metric='logloss'   # avoid warning in newer xgboost versions
)

model.fit(X_train, y_train)

# 5. Evaluate on train set
train_pred = model.predict(X_train)
train_acc = accuracy_score(y_train, train_pred)

# 6. Evaluate on test set
test_pred = model.predict(X_test)
test_acc = accuracy_score(y_test, test_pred)

print("Train Accuracy:", train_acc)
print("Test Accuracy :", test_acc)
print("\nClassification Report:\n", classification_report(y_test, test_pred))
print("\nConfusion Matrix:\n", confusion_matrix(y_test, test_pred))

# 7. Save model and feature columns for Flask
joblib.dump(model, "phishing_model_xgb.pkl")
with open("feature_columns_xgb.pkl", "wb") as f:
    pickle.dump(list(X.columns), f)























