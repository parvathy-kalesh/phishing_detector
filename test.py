import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt

# Load dataset
data = pd.read_csv('data/phishing_data_fixed.csv')  # adjust path if needed

sns.countplot(x='URL_Length', hue='Result', data=data)
plt.show()


  # Hrow many missing values per column

     # First few rows










