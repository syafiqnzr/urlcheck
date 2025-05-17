import os
import pickle

# Lokasi fail model dan vectorizer
model_file = r'C:\xampp\htdocs\urlcheck\urlcheck\Training Model\logistic_regression_model.pkl'
vectorizer_file = r'C:\xampp\htdocs\urlcheck\urlcheck\Features Extraction\tfidf_vectorizer.pkl'

# URL yang ingin diuji
test_url = "https://faceb00k.com"

# Muatkan vectorizer
with open(vectorizer_file, 'rb') as vf:
    vectorizer = pickle.load(vf)

# Muatkan model logistic regression
with open(model_file, 'rb') as mf:
    model = pickle.load(mf)

# Ubah URL kepada format vektor
url_vector = vectorizer.transform([test_url])

# Buat prediction
prediction = model.predict(url_vector)[0]

# Tukar result kepada label dan beri nota
if prediction == 1:
    result = "Malicious"
    note = "Warning: This URL may lead to a fake or harmful website designed to steal your personal information."
else:
    result = "Safe"
    note = "This URL appears to be safe and does not show signs of harmful content."

# Papar keputusan
print("URL:", test_url)
print("Prediction:", result)
print("Note:", note)
