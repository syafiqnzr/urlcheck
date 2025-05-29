import os
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
import pickle
import matplotlib.pyplot as plt
import seaborn as sns


# Define the folder paths
dataset_path = "dataset"
trainingmodel_path = "training_model"
vectorizer_path = "features_extraction"

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

# Display basic information about the TF-IDF features
print("\nTF-IDF Vectorizer Output:")
print(f"- Number of URLs vectorized: {X.shape[0]}")
print(f"- Number of features generated: {X.shape[1]}")
print(f"- Sample features: {vectorizer.get_feature_names_out()[:10]}")

# Display class distribution
print("\nLabel Distribution:")
print(f"- Safe URLs: {sum(y == 0)}")
print(f"- Malicious URLs: {sum(y == 1)}")

# Split into training and testing dataset (80:20 ratio)
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

print("\nTraining and testing data prepared:")
print(f"- Training samples: {X_train.shape[0]}")
print(f"- Testing samples: {X_test.shape[0]}")

# Train the logistic regression model
logit = LogisticRegression()
logit.fit(X_train, y_train)


from sklearn.metrics import confusion_matrix, ConfusionMatrixDisplay, classification_report

# Predict and evaluate
y_pred = logit.predict(X_test)

# Confusion Matrix
cm = confusion_matrix(y_test, y_pred)
disp = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=['Safe', 'Malicious'])
disp.plot(cmap='Blues')
plt.title('Confusion Matrix')
plt.show()

# Classification report
print("\nClassification Report:")
print(classification_report(y_test, y_pred, target_names=['Safe', 'Malicious']))



print("\nModel training completed successfully.")


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
