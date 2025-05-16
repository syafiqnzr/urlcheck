import pickle

# Path to the trained model
trainingmodel_path = r'C:\xampp\htdocs\urlcheck\urlcheck\Training Model'
vectorizer_path = r'C:\xampp\htdocs\urlcheck\urlcheck\Features Extraction'

# Load the trained model
with open(trainingmodel_path, 'rb') as file:
    trainedmodel = pickle.load(file)

# Load the fitted TF-IDF vectorizer
with open(vectorizer_path, 'rb') as file:
    vectorizer = pickle.load(file)

def predict_url(url):
    """
    Predict if the given URL is malicious or benign using the trained model.
    Args:
        url (str): The URL to classify.
    Returns:
        prediction (str): The prediction result.
    """
    url_features = vectorizer.transform([url])
    prediction = trainedmodel.predict(url_features)
    return prediction[0]

if __name__ == "__main__":
    test_url = input("Enter the URL to check: ")
    result = predict_url(test_url)
    print(f"Prediction result: {result}")
