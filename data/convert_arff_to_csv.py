import arff
import pandas as pd

# Load the ARFF file
with open('phishing_dataset.arff', 'r') as f:
    dataset = arff.load(f)

# Convert to DataFrame
df = pd.DataFrame(dataset['data'], columns=[attr[0] for attr in dataset['attributes']])

# Save as CSV
df.to_csv('phishing_dataset.csv', index=False)
print("✅ Converted to phishing_dataset.csv")
