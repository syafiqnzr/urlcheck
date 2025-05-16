import os
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
import pickle

# Define the folder paths
dataset_path = r'C:\xampp\htdocs\urlcheck\urlcheck\Dataset'
trainingmodel_path = r'C:\xampp\htdocs\urlcheck\urlcheck\Training Model'
vectorizer_path = r'C:\xampp\htdocs\urlcheck\urlcheck\Features Extraction'

# Automatically detect all CSV files in the folder
csv_files = [os.path.join(dataset_path, file) for file in os.listdir(dataset_path) if file.endswith('.csv')]

if not csv_files:
    raise FileNotFoundError("No CSV file found in the specified folder!")

# Print the names of dataset files used for training
print("Using the following dataset files for training:")
for csv_file in csv_files:
    print(f"- {os.path.basename(csv_file)}")

# Load and concatenate all datasets
dataframes = []
label_mapping = {
    'legitimate': 0, 'Safe': 0, 'benign': 0,
    'phishing': 1, 'malicious': 1, 'fraud': 1, 'scam': 1, 'Suspicious': 1
}

for csv_file in csv_files:
    df = pd.read_csv(csv_file, encoding='latin1')
    labels = df["type"].map(label_mapping)
    if labels.isna().all():
        print(f"Warning: {os.path.basename(csv_file)} has no valid labels and will be skipped.")
        continue
    dataframes.append(df)

# Combine all dataframes into one
data = pd.concat(dataframes, ignore_index=True)

labels = data["type"].map(label_mapping)

# Filter out rows with NaN labels
data = data[labels.notna()]
labels = labels[labels.notna()]
url_list = data["url"]

# Initialize the TF-IDF Vectorizer and the Logistic Regression model
vectorizer = TfidfVectorizer()
X = vectorizer.fit_transform(url_list)
y = labels

# Split into training and testing dataset (80:20 ratio)
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

logit = LogisticRegression()
logit.fit(X_train, y_train)

# Accuracy of Our Model
accuracy = logit.score(X_test, y_test) * 100
print(f"Accuracy: {accuracy:.2f}%")  

# Save the trained vectorizer
vectorizer_path = os.path.join(vectorizer_path, 'tfidf_vectorizer.pkl')
with open(vectorizer_path, 'wb') as file:
    pickle.dump(vectorizer, file)

# Save the trained model
model_path = os.path.join(trainingmodel_path, 'logistic_regression_model.pkl')
with open(model_path, 'wb') as file:
    pickle.dump(logit, file)

# Optional: Load the model to confirm it was saved successfully
with open(model_path, 'rb') as file:
    loaded_model = pickle.load(file)
    print("Model loaded successfully!")
