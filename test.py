import pandas as pd
import joblib
import matplotlib.pyplot as plt

# -----------------------------
# 1. Load model and dataset
# -----------------------------
model_path = "phishing_model_weighted_graph.pkl"
data_path = "data/phishing_data_fixed.csv"

print("🔹 Loading model and dataset...")
clf = joblib.load(model_path)
df = pd.read_csv(data_path)

# -----------------------------
# 2. Prepare feature names
# -----------------------------
df["Result"] = df["Result"].replace(-1, 0)
X = df.drop(columns=["Result"])
feature_names = X.columns

# -----------------------------
# 3. Get feature importance
# -----------------------------
importances = clf.feature_importances_

importance_df = pd.DataFrame({
    "Feature": feature_names,
    "Importance": importances
}).sort_values(by="Importance", ascending=False)

# -----------------------------
# 4. Display top 15 features
# -----------------------------
print("\n🔍 Top 15 Most Important Features:\n")
print(importance_df.head(15))

# -----------------------------
# 5. Plot top 15 features
# -----------------------------
plt.figure(figsize=(10,6))
importance_df.head(15).plot(
    kind="barh", x="Feature", y="Importance", legend=False, color="teal"
)
plt.gca().invert_yaxis()
plt.title("Top 15 Important Features - Random Forest Model")
plt.xlabel("Feature Importance Score")
plt.tight_layout()
plt.show()

# -----------------------------
# 6. Save full feature importance list
# -----------------------------
output_csv = "feature_importance_weighted.csv"
importance_df.to_csv(output_csv, index=False)
print(f"\n📁 Full feature importance saved to: {output_csv}")

























