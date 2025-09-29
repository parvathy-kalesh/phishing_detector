import pandas as pd

# Example: Load your dataset
df = pd.read_csv("data/phishing_data_fixed.csv")

# 1. Get number of columns
print(df['Result'].unique())

# Count how many of each class
print(df['Result'].value_counts())























