import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
import pickle

# Define the new feature extractor function here or import from your feature extractor module


# Load your fixed dataset (adjust path if needed)
data = pd.read_csv('data/phishing_data_fixed.csv')

# Add the new feature column using the URL column in your data


# Convert labels from -1/1 to 0/1 for sklearn compatibility
data['Result'] = data['Result'].replace({-1: 0, 1: 1})

# Separate features and target
label_column = 'Result'

# Now drop columns you don't want to use as features (like 'url' itself)
X = data.drop(columns=[label_column, 'url'])  # drop 'url' since it's not numeric

y = data[label_column]

# Save feature columns for later use
feature_columns = X.columns.tolist()

# Split data
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

# Train model
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# Predict on test set
y_pred = model.predict(X_test)

# Show prediction distribution and accuracy
from collections import Counter
print("Prediction counts on test set:", Counter(y_pred))
print("Actual label counts:", Counter(y_test))
print("Accuracy:", accuracy_score(y_test, y_pred))
print(classification_report(y_test, y_pred))

# Save model
with open('phishing_model.pkl', 'wb') as f:
    pickle.dump(model, f)

# Save feature columns list
with open('feature_columns.pkl', 'wb') as f:
    pickle.dump(feature_columns, f)

print("✅ Model and feature columns saved!")





