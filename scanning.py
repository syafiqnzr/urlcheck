#Scanning.py

import pickle
import re
import os
import socket
import requests
from datetime import datetime
from urllib.parse import urlparse
import whois
import cgi
import cgitb
cgitb.enable()  # For debugging

# Path to the trained model
trainingmodel_path = r'C:\xampp\htdocs\urlcheck\urlcheck\Training Model\logistic_regression_model.pkl'
vectorizer_path = r'C:\xampp\htdocs\urlcheck\urlcheck\Features Extraction\tfidf_vectorizer.pkl'

# Load the trained model
with open(trainingmodel_path, 'rb') as file:
    trainedmodel = pickle.load(file)

# Load the fitted TF-IDF vectorizer
with open(vectorizer_path, 'rb') as file:
    vectorizer = pickle.load(file)

# List of suspicious keywords and injection commands
SUSPICIOUS_KEYWORDS = ["bank", "secure", "account", "verify", "update", "free", "gift", "prize", "paypal", "signin", "confirm", "password", "alert", "malicious","camera"]
SUSPICIOUS_DOMAIN = ["cfd", "top", "click"]
INJECTION_COMMANDS = ["SELECT", "DROP", "INSERT", "DELETE", "UPDATE", "UNION", "--", "#", "/*", "*/", "OR 1=1"]

def contains_suspicious_keywords(text, keywords):
    """Checks if the text contains any suspicious keywords."""
    return any(keyword in text.lower() for keyword in keywords)


def get_domain_age(url):
    """Extracts the domain from a URL and calculates its age."""
    try:
        # Extract domain from the URL
        parsed_url = urlparse(url)
        domain = parsed_url.netloc if parsed_url.netloc else parsed_url.path  

        # Get WHOIS information
        domain_info = whois.whois(domain)
        
        # Get the creation date
        creation_date = domain_info.creation_date
        
        # If multiple creation dates exist, take the first one
        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        # Calculate domain age
        if creation_date:
            today = datetime.today()
            age_days = (today - creation_date).days
            age_years = age_days // 365
            age_months = (age_days % 365) // 30
            age_remaining_days = (age_days % 365) % 30

            return domain, creation_date, f"{age_years} years, {age_months} months, {age_remaining_days} days"
        else:
            return domain, "Unknown", "Could not determine domain age"
    
    except Exception as e:
        return domain, "Unknown", f"Error: {str(e)}"


def get_domain_registrar(url):
    """Extracts the domain from a URL and gets the registrar information."""
    try:
        # Extract domain from URL
        parsed_url = urlparse(url)
        domain = parsed_url.netloc if parsed_url.netloc else parsed_url.path  

        # Get WHOIS information
        domain_info = whois.whois(domain)

        # Extract registrar
        registrar = domain_info.registrar if domain_info.registrar else "Registrar not found"

        return domain, registrar
    
    except Exception as e:
        return domain, f"Error: {str(e)}"

def get_domain_details(url):
    """Extracts domain from URL and retrieves WHOIS details (Creation, Updated, Expiry Dates)."""
    try:
        # Extract domain from the URL
        parsed_url = urlparse(url)
        domain = parsed_url.netloc if parsed_url.netloc else parsed_url.path  

        # Get WHOIS information
        domain_info = whois.whois(domain)

        # Extract important dates
        creation_date = domain_info.creation_date
        updated_date = domain_info.updated_date
        expiry_date = domain_info.expiration_date

        # Handle cases where WHOIS returns lists of dates
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if isinstance(updated_date, list):
            updated_date = updated_date[0]
        if isinstance(expiry_date, list):
            expiry_date = expiry_date[0]

        # Convert None values to a readable format
        creation_date = creation_date if creation_date else "Unknown"
        updated_date = updated_date if updated_date else "Unknown"
        expiry_date = expiry_date if expiry_date else "Unknown"

        return domain, creation_date, updated_date, expiry_date
    
    except Exception as e:
        return domain, "Error retrieving data", "Error retrieving data", "Error retrieving data"


def get_ip_from_url(url):
    """Extracts the domain from a URL and finds its IP address."""
    try:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc if parsed_url.netloc else parsed_url.path  # Handle cases where URL lacks scheme
        ip_address = socket.gethostbyname(domain)
        return domain, ip_address
    except socket.gaierror:
        return domain, "Invalid domain or unable to resolve IP"
    
def detect_protocol(domain):
    """Detects whether a domain supports HTTPS or falls back to HTTP."""
    https_url = f"https://{domain}"
    http_url = f"http://{domain}"

    try:
        # Try HTTPS first
        response = requests.get(https_url, timeout=5)
        if response.status_code == 200:
            return "https"
    except requests.exceptions.RequestException:
        pass  # HTTPS failed, try HTTP

    try:
        # Try HTTP as fallback
        response = requests.get(http_url, timeout=5)
        if response.status_code == 200:
            return "http"
    except requests.exceptions.RequestException:
        return "Unknown (Domain may be unreachable)"

    return "Unknown (Domain may be unreachable)"

def analyze_url_parts(url):
    """Breaks the URL into components and checks for malicious patterns."""
    parsed_url = urlparse(url)
    breakdown_results = {}
    reasons = {}
    mitigation = {}

    # Scheme (Protocol)
    breakdown_results['Scheme'] = (
    0 if parsed_url.scheme == "https" else 
    3 if parsed_url.scheme == "http" else 
    1  # Unusual protocol (e.g., ftp, file)
)

    reasons['Scheme'] = "HTTPS ensures encrypted communication." if parsed_url.scheme == "https" else "Non-HTTPS URLs are more vulnerable to attacks."
    mitigation['Scheme'] = "No mitigation needed." if parsed_url.scheme == "https" else "Use HTTPS for encryption."

    # Host
    breakdown_results['Host'] = 1 if contains_suspicious_keywords(parsed_url.netloc, SUSPICIOUS_KEYWORDS) or contains_suspicious_keywords(parsed_url.netloc, SUSPICIOUS_DOMAIN) else 0
    reasons['Host'] = "Contains suspicious keywords often associated with phishing domains." if breakdown_results['Host'] else "No suspicious keywords found in the host."
    mitigation['Host'] = "Verify domain authenticity. Avoid clicking on unfamiliar domains." if breakdown_results['Host'] else "No mitigation needed."

    # Path
    breakdown_results['Path'] = 1 if contains_suspicious_keywords(parsed_url.path, SUSPICIOUS_KEYWORDS) or contains_suspicious_keywords(parsed_url.path, INJECTION_COMMANDS) else 0
    reasons['Path'] = "URL path contains suspicious words or possible SQL injection commands." if breakdown_results['Path'] else "No suspicious patterns detected in the path."
    mitigation['Path'] = "Avoid URLs with 'login', 'secure', or SQL keywords like 'DROP' or 'SELECT'." if breakdown_results['Path'] else "No mitigation needed."

    # Port
    breakdown_results['Port'] = 1 if parsed_url.port and parsed_url.port not in [80, 443] else 0
    reasons['Port'] = f"Uses uncommon port ({parsed_url.port}), which may indicate an unsafe connection." if breakdown_results['Port'] else "Standard ports (80 for HTTP, 443 for HTTPS) detected."
    mitigation['Port'] = "Avoid URLs with unusual ports unless verified." if breakdown_results['Port'] else "No mitigation needed."

    # Query
    breakdown_results['Query'] = 1 if contains_suspicious_keywords(parsed_url.query, SUSPICIOUS_KEYWORDS) or contains_suspicious_keywords(parsed_url.query, INJECTION_COMMANDS) else 0
    reasons['Query'] = "Contains suspicious query parameters, possibly for phishing or SQL injection." if breakdown_results['Query'] else "No suspicious query parameters detected."
    mitigation['Query'] = "Do not submit sensitive data through URL parameters." if breakdown_results['Query'] else "No mitigation needed."

    # Fragment
    breakdown_results['Fragment'] = 1 if contains_suspicious_keywords(parsed_url.fragment, SUSPICIOUS_KEYWORDS) else 0
    reasons['Fragment'] = "Fragment contains suspicious words that might indicate deceptive content." if breakdown_results['Fragment'] else "No suspicious fragments detected."
    mitigation['Fragment'] = "Avoid clicking on links with misleading fragments." if breakdown_results['Fragment'] else "No mitigation needed."

    return breakdown_results, reasons, mitigation

def is_valid_url(url):
    """Checks if the given URL is valid using regex."""
    url_regex = re.compile(
        r'^(https?|ftp):\/\/'  # Protocol (http, https, ftp)
        r'([A-Z0-9][A-Z0-9_-]*(?:\.[A-Z0-9][A-Z0-9_-]*)+)'  # Domain
        r'(:\d+)?'  # Optional port
        r'(\/[A-Z0-9._%+-]*)*$', re.IGNORECASE)  # Path
    return bool(url_regex.match(url))

def classify_url(url):
    """Classifies a URL based on ML prediction and URL Breakdown Analysis."""

    def get_domain_extension(domain):
        # Extract the domain extension from the domain name
        if '.' in domain:
            return domain.rsplit('.', 1)[-1].lower()
        return ''

    # Ensure the URL has a protocol before proceeding
    parsed_url = urlparse(url)
    domain = parsed_url.netloc if parsed_url.netloc else parsed_url.path

    # ML Model Prediction
    url_vector = vectorizer.transform([url])  # Use 'url' instead of 'original_url'
    ml_prediction = trainedmodel.predict(url_vector)[0]  # 0 (Safe) or 1 (Malicious)

    # URL Breakdown Analysis
    breakdown_results, reasons, mitigation = analyze_url_parts(url)

    # **Determine the final classification**
    if any(value == 1 for value in breakdown_results.values()):
        if breakdown_results['Scheme'] == 0:
             final_result = "Safe"
             note = "The URL contains threats but is marked Safe due to HTTPS usage."
        else:
            final_result = "Suspicious"
            note = "The URL is classified as Malicious due to detected threats."

    elif ml_prediction == 1 and breakdown_results['Scheme'] == 3:
        final_result = "Safe"
        #note = "The link is safe but may be suspicious due to HTTP usage and ML model detection."
        note = "This link may not be fully secure. It uses an older connection method and contains potentially risky content."

    elif ml_prediction == 1:
        if breakdown_results['Scheme'] == 0:
            final_result = "Safe"
            #note = "The link is safe but may be suspicious due to the ML model detection. Marked Safe due to HTTPS usage."
            note = "This site uses secure HTTPS, but it contains patterns similar to risky websites."


        else:
            final_result = "Safe"
            #note = "The link is safe but may be suspicious due to the ML model detection."
            note = "This link may appear safe but contains patterns that are often seen in unsafe sites."



    elif breakdown_results['Scheme'] == 3:
        final_result = "Safe"
        note = "The link is safe but may be suspicious due to HTTP usage."
    else:
        final_result = "Safe"
        note = "The URL is Safe. No detected threats."

    

    ip_address = None
    try:
        import socket
        ip_address = socket.gethostbyname(domain)
    except Exception:
        ip_address = "Unknown"

    return final_result, note, breakdown_results, reasons, mitigation, domain, ip_address



def get_url_length(url):
    """Calculates the length of a URL."""
    return len(url)

# Function to check the domain's default protocol
def detect_protocol(domain):
    try:
        # Attempt HTTPS first
        response = requests.get(f"https://{domain}", timeout=3)
        if response.status_code == 200:
            return "https"
    except requests.exceptions.RequestException:
        pass  # HTTPS failed, try HTTP

    try:
        # Attempt HTTP
        response = requests.get(f"http://{domain}", timeout=3)
        if response.status_code == 200:
            return "http"
    except requests.exceptions.RequestException:
        pass  # HTTP also failed

    return "Unknown"

def run_full_scan(original_url):
    # logic from your __main__ block
    # returns a dictionary instead of printing
    # [Use same logic but replace all `print` with values returned in a dict]

    # (Shortened here, but full logic stays same)
    result = {
        'url': url,
        'final_result': final_result,
        'ml_prediction': '[Suspicious]' if ml_prediction == 1 else '[Safe]',
        'note': note,
        'domain': domain,
        'ip_address': ip_address,
        'creation_date': creation_date,
        'updated_date': updated_date,
        'expiry_date': expiry_date,
        'age': age,
        'registrar': registrar,
        'url_length': url_length,
        'protocol': protocol.upper(),
        'breakdown_results': breakdown_results,
        'reasons': reasons,
        'mitigation': mitigation
    }
    return result


if __name__ == "__main__":
    # Step 1: user input URL
    original_url = input("\nEnter URL to scan: ").strip()  # Store the original URL before modification
    url = original_url
    
    # Step 2: Detect the correct protocol before proceeding
    parsed_url = urlparse(url)
    domain = parsed_url.netloc if parsed_url.netloc else parsed_url.path
    
    if not parsed_url.scheme:
        # Loading process
        print("\n[INFO] URL has no protocol. Detecting correct protocol...\n")
        
        # Detect protocol dynamically
        protocol = detect_protocol(domain)
        if protocol == "Unknown":
            # Loading process
            print("[WARNING] Could not determine protocol. Defaulting to HTTPS.")
            protocol = "https"
        
        # Prepend the detected protocol to the URL
        url = f"{protocol}://{url}"
        # Loading process
        print(f"=> Detected Protocol: {protocol.upper()} | Adjusted URL: {url}\n")
    else:
        # Validate the given protocol by detecting the actual domain behavior
        detected_protocol = detect_protocol(domain)
        if detected_protocol != parsed_url.scheme and detected_protocol != "Unknown":
            # Loading process
            print(f"[WARNING] Provided protocol ({parsed_url.scheme}) may be incorrect. Using detected protocol ({detected_protocol}).")
            url = f"{detected_protocol}://{domain}"
            # Loading process
            print(f"=> Adjusted URL: {url}\n")
        protocol = parsed_url.scheme  # Extract protocol from input URL
    
    # Step 3: Verify if domain exists using WHOIS
    try:
        domain_info = whois.whois(domain)
        if domain_info.domain_name is None:
            # error handling after user input invalid domain
            print("Invalid URL: No valid domain found. Scanning cannot proceed.")
            exit()
    except Exception:
        # error handling after user input URL does not exist
        print("The URL does not exist")
        exit()
    
    # Step 4: Validate final URL format before scanning
    if not re.match(r"^(https?|ftp):\/\/[\S]+", url):
        # error handling after user input invalid URL
        print("Invalid URL format. Cannot proceed.")
        exit()
    
    # Get domain details
    domain, creation_date, age = get_domain_age(url)
    domain, registrar = get_domain_registrar(url)
    domain, creation_date, updated_date, expiry_date = get_domain_details(url)
    url_length = get_url_length(url)
    
    # Classify the URL
    final_result, note, breakdown_results, reasons, mitigation, domain, ip_address = classify_url(url)
    
    # Explicit ML prediction output
    url_vector = vectorizer.transform([original_url])
    ml_prediction = trainedmodel.predict(url_vector)[0]  # 0 (Safe) or 1 (Malicious)
    
    # Result (Display in resut.html)
    print(f"\nMachine Learning Model Output: {'[Suspicious]' if ml_prediction == 1 else '[Safe]'}")
    print(f"Final Classification: [{final_result}]")
    print(f"Note: {note}")
    
    # Display additional URL details (Display in detail_resut.html)
    print(f"\n\n1. URL: {url}")
    print(f"2. Domain: {domain}")
    print(f"3. IP Address: {ip_address}")
    print(f"4. Creation Date: {creation_date}")
    print(f"5. Updated Date: {updated_date}")
    print(f"6. Registry Expiry Date: {expiry_date}")
    print(f"7. Domain Age: {age}")
    print(f"8. Registrar: {registrar}")
    print(f"9. URL Length: {url_length}")
    print(f"10. Detected Protocol: {protocol.upper()}")

    # URL Breakdown Analysis (Display in detail_result.html)
    print("\n=== URL Breakdown Analysis ===")
    for part, result in breakdown_results.items():
        if result == 1:
             status = "Suspicious detected"
        elif result == 3:
            status = "Suspicious"
        else:
             status = "Safe"
        print(f"\n{part}: {status}")

        # Print the URL Fragment value for each part
        fragment_value = "-"
        if part == "Scheme":
            fragment_value = protocol.upper() if protocol.upper() else "-"
        elif part == "Host":
            fragment_value = domain if domain else "-"
        elif part == "Path":
            fragment_value = parsed_url.path if parsed_url.path else "-"
        elif part == "Port":
            fragment_value = str(parsed_url.port) if parsed_url.port else "-"
        elif part == "Query":
            fragment_value = parsed_url.query if parsed_url.query else "-"
        elif part == "Fragment":
            fragment_value = parsed_url.fragment if parsed_url.fragment else "-"
        print(f"URL Fragment: {fragment_value}")

        print(f"Reason: {reasons[part]}")
        print(f"Mitigation: {mitigation[part]}\n")

