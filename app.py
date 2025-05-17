import mysql.connector
from flask import Flask, render_template, request
import random
import hashlib
import sqlite3
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
# Your Scanning functions
from scanning import classify_url, get_domain_age, get_domain_details, get_domain_registrar, get_ip_from_url, get_url_length, detect_protocol, vectorizer, trainedmodel
from urllib.parse import urlparse, unquote
import whois
import os
import socket
from werkzeug.utils import secure_filename
from flask import url_for
import subprocess
from flask import Flask, render_template, request, redirect, url_for, session, flash
import mysql.connector
from dateutil.relativedelta import relativedelta
from flask import Flask, render_template, request, redirect, url_for, session
import os
import mysql.connector
from werkzeug.utils import secure_filename
import base64
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Required for session tracking

# Paths
dataset_path = r'C:\xampp\htdocs\urlcheck\urlcheck\Dataset'
trainingmodel_path = r'C:\xampp\htdocs\urlcheck\urlcheck\Training Model'
urcheck_script = r'C:\xampp\htdocs\urlcheck\urlcheck\urlcheck.py'

# Ensure necessary folders exist
os.makedirs(dataset_path, exist_ok=True)
os.makedirs(trainingmodel_path, exist_ok=True)

app.config['SECRET_KEY'] = 'your_flask_secret_key'
app.config['RECAPTCHA_PUBLIC_KEY'] = '6LdYRLUqAAAAAD3KAzcvV1YF_YI5DjpNVpAdEbmV'
app.config['RECAPTCHA_PRIVATE_KEY'] = '6LdYRLUqAAAAABFyAftq5DkoE2CEs9dzchOSCWSj'

UPLOAD_FOLDER = 'static/uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

@app.context_processor
def inject_user():
    from flask import session
    profile_picture = None
    username = None
    if 'username' in session:
        username = session['username']
        cursor = db.cursor(dictionary=True)
        # Check if user is admin
        cursor.execute("SELECT * FROM admin WHERE username = %s", (username,))
        admin_user = cursor.fetchone()
        if admin_user:
            # Fetch profile_picture from admin table
            profile_picture = admin_user.get('profile_picture', None)
        else:
            # Fetch profile_picture from users table
            cursor.execute("SELECT profile_picture FROM users WHERE username = %s", (username,))
            user = cursor.fetchone()
            if user and user['profile_picture']:
                profile_picture = user['profile_picture']
        cursor.close()
    return dict(profile_picture=profile_picture, username=username)

# ---- Database Config ----
db = mysql.connector.connect(
    host="localhost",
    user="root",
    password="",  
    database="urlscanner"
)

cursor = db.cursor(dictionary=True)


@app.route('/', methods=['GET'])
def index():
    username = session.get('username')
    is_admin = False
    if username:
        cursor = db.cursor(dictionary=True)
        cursor.execute("SELECT * FROM admin WHERE username = %s", (username,))
        admin_user = cursor.fetchone()
        cursor.close()
        if admin_user:
            is_admin = True
    return render_template('index.html', is_admin=is_admin)


@app.route('/result', methods=['POST'])
def result():
    username = session.get('username')
    is_admin = False
    if username:
        cursor = db.cursor(dictionary=True)
        cursor.execute("SELECT * FROM admin WHERE username = %s", (username,))
        admin_user = cursor.fetchone()
        cursor.close()
        if admin_user:
            is_admin = True

    original_url = request.form['url'].strip()

    # Validate URL contains a dot
    if '.' not in original_url:
        flash("This URL does not exist or is invalid.", "error")
        return redirect(url_for('index'))

    parsed_url = urlparse(original_url)
    domain = parsed_url.netloc if parsed_url.netloc else parsed_url.path

    # Detect or confirm protocol
    if not parsed_url.scheme:
        protocol = detect_protocol(domain)
        if protocol == "Unknown":
            protocol = "https"
        url = f"{protocol}://{original_url}"
    else:
        # Validate given protocol against detected protocol
        detected_protocol = detect_protocol(domain)
        if detected_protocol != parsed_url.scheme and detected_protocol != "Unknown":
            url = f"{detected_protocol}://{domain}"
            protocol = detected_protocol
        else:
            url = original_url
            protocol = parsed_url.scheme

    # WHOIS domain validation
    try:
        domain_info = whois.whois(domain)
        if domain_info.domain_name is None:
            flash("Invalid URL: No valid domain found.", "error")
            return redirect(url_for('index'))
    except Exception:
        flash("The URL does not exist or is invalid.", "error")
        return redirect(url_for('index'))

    # Additional IP resolution check
    try:
        ip_address = socket.gethostbyname(domain)
    except Exception:
        flash("The URL does not exist or is invalid.", "error")
        return redirect(url_for('index'))

    # Run classification and analysis
    final_result, note, breakdown, reasons, mitigation, domain, ip_address = classify_url(url)
    _, creation_date, age = get_domain_age(url)
    _, registrar = get_domain_registrar(url)
    _, _, updated_date, expiry_date = get_domain_details(url)
    url_length = get_url_length(url)

    # ML prediction label
    url_vector = vectorizer.transform([url])
    raw_prediction = trainedmodel.predict(url_vector)[0]
    ml_prediction = 'Safe' if raw_prediction == 0 else 'Suspicious'

    sender = session.get('username', 'guest')

    cursor = db.cursor(dictionary=True)

    # Save scan summary
    insert_summary_query = """
    INSERT INTO scan_results (
        url, domain, ip_address, protocol, creation_date, updated_date,
        expiry_date, age, registrar, url_length, classification, ml_prediction, note, sender
    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    """
    cursor.execute(insert_summary_query, (
        url, domain, ip_address, protocol, str(creation_date), str(updated_date),
        str(expiry_date), age, registrar, url_length, final_result, ml_prediction, note, sender
    ))

    # Save breakdown details
    insert_breakdown_query = """
        INSERT INTO url_breakdown (scan_url, part, fragment_value, score, reason, mitigation, sender)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
    """
    for part in breakdown:
        score = breakdown[part]
        reason_text = reasons.get(part, "")
        fix = mitigation.get(part, "")

        fragment_value = "-"
        if part == "Scheme":
            fragment_value = protocol.upper() if protocol else "-"
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

        cursor.execute(insert_breakdown_query, (
            url, part, fragment_value, score, reason_text, fix, sender
        ))

    db.commit()
    cursor.close()

    return render_template("result.html",
                           ml_prediction=ml_prediction,
                           prediction=final_result,
                           note=note,
                           url=url,
                           original_url=original_url,
                           is_admin=is_admin)

@app.route('/details', methods=['POST'])
def details():
    username = session.get('username')
    is_admin = False
    if username:
        cursor = db.cursor(dictionary=True)
        cursor.execute("SELECT * FROM admin WHERE username = %s", (username,))
        admin_user = cursor.fetchone()
        cursor.close()
        if admin_user:
            is_admin = True

    user = session.get('user')
    url = request.form.get('url')
    cursor = db.cursor(dictionary=True)

    # Get scan result for the given URL
    cursor.execute("""
        SELECT url, domain, ip_address, protocol, creation_date, updated_date,
               expiry_date, age, registrar, url_length, classification, note, sender
        FROM scan_results
        WHERE url = %s
        ORDER BY id DESC
        LIMIT 1
    """, (url,))
    scan_result = cursor.fetchone()

    if not scan_result:
        flash("No scan result found for the specified URL.", "warning")
        return redirect(url_for('index'))

    # Get the latest timestamp for the url_breakdown entries for this URL
    cursor.execute("""
        SELECT timestamp
        FROM url_breakdown
        WHERE scan_url = %s
        GROUP BY timestamp
        ORDER BY timestamp DESC
        LIMIT 1
    """, (url,))
    latest = cursor.fetchone()
    if not latest:
        flash("No breakdown details found for the specified URL.", "warning")
        return redirect(url_for('index'))

    latest_timestamp = latest['timestamp']

    # Fetch breakdown features for that timestamp and URL
    cursor.execute("""
        SELECT part, fragment_value, score, reason, mitigation, sender
        FROM url_breakdown
        WHERE scan_url = %s AND timestamp = %s
        ORDER BY FIELD(part, 'Scheme', 'Host', 'Path', 'Port', 'Query', 'Fragment')
    """, (url, latest_timestamp))
    features = cursor.fetchall()

    sender = features[0]['sender'] if features else ''

    cursor.close()

    return render_template(
        'detail_result.html',
        user=user,
        scan=scan_result,
        scan_url=url,
        sender=sender,
        features=features,
        is_admin=is_admin
    )


@app.route('/loginn')
def loginn():
    return render_template('loginn.html')

@app.route('/details/<path:url_encoded>', methods=['GET'])
def details_by_url(url_encoded):
    url = unquote(url_encoded)
    username = session.get('username')
    is_admin = False
    if username:
        cursor = db.cursor(dictionary=True)
        cursor.execute("SELECT * FROM admin WHERE username = %s", (username,))
        admin_user = cursor.fetchone()
        cursor.close()
        if admin_user:
            is_admin = True

    cursor = db.cursor(dictionary=True)

    # Get scan result for the given URL
    cursor.execute("""
        SELECT url, domain, ip_address, protocol, creation_date, updated_date,
               expiry_date, age, registrar, url_length, classification, note, sender
        FROM scan_results
        WHERE url = %s
        ORDER BY id DESC
        LIMIT 1
    """, (url,))
    scan_result = cursor.fetchone()

    if not scan_result:
        # If no scan result found, redirect or show error
        flash("No scan result found for the specified URL.", "warning")
        return redirect(url_for('archiveurl'))

    # Get the latest timestamp for the url_breakdown entries for this URL
    cursor.execute("""
        SELECT timestamp
        FROM url_breakdown
        WHERE scan_url = %s
        GROUP BY timestamp
        ORDER BY timestamp DESC
        LIMIT 1
    """, (url,))
    latest = cursor.fetchone()
    if not latest:
        flash("No breakdown details found for the specified URL.", "warning")
        return redirect(url_for('archiveurl'))

    latest_timestamp = latest['timestamp']

    # Fetch breakdown features for that timestamp and URL
    cursor.execute("""
        SELECT part, fragment_value, score, reason, mitigation, sender
        FROM url_breakdown
        WHERE scan_url = %s AND timestamp = %s
        ORDER BY FIELD(part, 'Scheme', 'Host', 'Path', 'Port', 'Query', 'Fragment')
    """, (url, latest_timestamp))
    features = cursor.fetchall()

    sender = features[0]['sender'] if features else ''

    cursor.close()

    return render_template(
        'detail_result.html',
        user=username,
        scan=scan_result,
        scan_url=url,
        sender=sender,
        features=features,
        is_admin=is_admin
    )

@app.route('/signup', methods=['POST'])
def signup():
    name = request.form.get('name')
    email = request.form.get('email')
    password = request.form.get('password')
    
    # Handle sign up logic here (e.g., save to DB)
    print(f"Signup attempt - Name: {name}, Email: {email}")
    return redirect(url_for('index'))

@app.route('/signin', methods=['POST'])
def signin():
    email = request.form.get('email')
    password = request.form.get('password')

    # Handle sign in logic here (e.g., verify credentials)
    print(f"Signin attempt - Email: {email}")
    return redirect(url_for('index'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    is_admin = False
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if not username or not password:
            flash("Username and password are required.", "error")
            return render_template('login.html', is_admin=is_admin)

        cursor = db.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()

        if user and check_password_hash(user['password'], password):
            cursor.execute("SELECT expiry_date FROM token WHERE token_number = %s", (user['token'],))
            token_data = cursor.fetchone()

            if token_data and datetime.now() > token_data['expiry_date']:
                flash(f"TOKEN_EXPIRED::{username}", "token_expired")
                return redirect(url_for('login'))
            
            # Check if user is admin
            cursor.execute("SELECT * FROM admin WHERE username = %s", (username,))
            admin_user = cursor.fetchone()
            if admin_user:
                is_admin = True
            
            # Store user info in session
            session['username'] = username
            return redirect('/')

        flash("Invalid username or password.", "error")
        return render_template('login.html', is_admin=is_admin)

    else:
        # For GET request, check if user in session is admin
        username = session.get('username')
        if username:
            cursor = db.cursor(dictionary=True)
            cursor.execute("SELECT * FROM admin WHERE username = %s", (username,))
            admin_user = cursor.fetchone()
            cursor.close()
            if admin_user:
                is_admin = True

    return render_template('login.html', is_admin=is_admin)  


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        token = request.form['token']

        if password != confirm_password:
            return render_template('register.html', error="Passwords do not match")

        cursor = db.cursor(dictionary=True)
        cursor.execute("SELECT * FROM token WHERE token_number = %s AND start_date IS NULL AND expiry_date IS NULL", (token,))
        token_data = cursor.fetchone()

        if token_data:
            hashed_password = generate_password_hash(password)
            cursor.execute("INSERT INTO users (username, email, password, token) VALUES (%s, %s, %s, %s)",
                           (username, email, hashed_password, token))
            db.commit()

            start_date = datetime.now()
            expiry_date = start_date + timedelta(minutes=60)
            cursor.execute("UPDATE token SET start_date = %s, expiry_date = %s WHERE token_number = %s",
                           (start_date, expiry_date, token))
            db.commit()

            return redirect('/login')
        else:
            return render_template('register.html', error="Invalid or used token")

    return render_template('register.html')



@app.template_filter('b64encode')
def b64encode_filter(data):
    if data is None:
        return ''
    return base64.b64encode(data).decode('utf-8')

# Allowed file types for profile picture upload
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}

# Check if file is allowed
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Profile route to handle displaying and updating profile data
@app.route('/profile', methods=['GET', 'POST'])
def profile():
    

    if not db.is_connected():
        db.reconnect()
    cursor = db.cursor(dictionary=True)
    if 'username' not in session:
        return redirect(url_for('login'))

    username = session['username']

    # Fetch user details from the database
    cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
    user = cursor.fetchone()

    if user:
        
        # Get token data
        cursor.execute("SELECT token_number, start_date, expiry_date FROM token WHERE token_number = %s", (user['token'],))
        token_info = cursor.fetchone()
        profile_picture = user.get('profile_picture', None)
    else:
        flash("User not found!", "error")
        return redirect(url_for('login'))

    if request.method == 'POST':
        # Handle Profile Picture Upload
        if 'profile_picture' in request.files:
            profile_picture = request.files['profile_picture']
            if profile_picture and allowed_file(profile_picture.filename):
                # Save the image as a BLOB in the database
                profile_picture_data = profile_picture.read()

                cursor.execute("UPDATE users SET profile_picture = %s WHERE username = %s", 
                               (profile_picture_data, username))
                db.commit()
                flash("Profile picture updated successfully!", "success")

        # Handle Username Update
        new_username = request.form.get('username')
        if new_username:
            cursor.execute("UPDATE users SET username = %s WHERE username = %s", (new_username, username))
            db.commit()
            session['username'] = new_username
            flash("Username updated successfully!", "success")  

        return redirect(url_for('profile'))

    return render_template('profile.html',
                               username=user['username'],
                               token_number=token_info['token_number'] if token_info else '',
                               start_date=token_info['start_date'].strftime('%d-%m-%Y') if token_info and token_info['start_date'] else '',
                               expiry_date=token_info['expiry_date'].strftime('%d-%m-%Y') if token_info and token_info['expiry_date'] else '',
                               profile_picture=profile_picture)



@app.route('/plan', methods=['GET'])
def plan():
    username = session.get('username')
    is_admin = False
    if username:
        cursor = db.cursor(dictionary=True)
        cursor.execute("SELECT * FROM admin WHERE username = %s", (username,))
        admin_user = cursor.fetchone()
        cursor.close()
        if admin_user:
            is_admin = True
    return render_template('plan.html', is_admin=is_admin)

@app.route('/archiveurl')
def archiveurl():
    if 'username' not in session:
        flash("You must be logged in to view your scan history.", "warning")
        return redirect(url_for('login'))

    username = session['username']
    cursor = db.cursor(dictionary=True)
    cursor.execute("SELECT url, classification, note, timestamp, sender FROM scan_results WHERE sender = %s ORDER BY timestamp DESC", (username,))
    results = cursor.fetchall()
    cursor.close()
    return render_template('archiveurl.html', results=results)


import csv

@app.route('/export_csv')
def export_csv():
    try:
        cursor = db.cursor(dictionary=True)
        cursor.execute("SELECT url, classification FROM scan_results ORDER BY timestamp DESC")
        rows = cursor.fetchall()
        cursor.close()

        csv_path = r'C:\xampp\htdocs\urlcheck\Dataset\dataset_baru.csv'

        with open(csv_path, mode='w', newline='', encoding='utf-8') as csvfile:
            fieldnames = ['url', 'type']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

            writer.writeheader()
            for row in rows:
                writer.writerow({'url': row['url'], 'type': row['classification']})

        flash(f'CSV file has been saved successfully at {csv_path}', 'success')
    except Exception as e:
        flash(f'Failed to export CSV file: {str(e)}', 'error')

    from_page = request.args.get('from')
    if from_page == 'admin':
        return redirect(url_for('admin_archiveurl'))
    else:
        return redirect(url_for('admin_archiveurl'))


# ADMIN LOGIN
@app.route('/login_admin', methods=['GET', 'POST'])
def login_admin():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Regular user login logic
        cursor.execute('SELECT * FROM admin WHERE username = %s AND password = %s', (username, password))
        user = cursor.fetchone()

        if user:
            session['username'] = username  # Store the logged-in user in session
            
            return redirect(url_for('dashboard_admin'))
        else:
            flash('Invalid username or password. Please try again.')
            return render_template('login_admin.html', message='Invalid username or password!')
           
    return render_template('login_admin.html')

@app.route('/dashboard_admin')
def dashboard_admin():
    if 'username' not in session:
        flash("Access denied. Please log in as admin.", "warning")
        return redirect(url_for('login_admin'))

    return render_template('admin_dashboard.html')

@app.template_filter('b64encode')
def b64encode_filter(data):
    if data is None:
        return ''
    return base64.b64encode(data).decode('utf-8')

# Allowed file types for profile picture upload
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}

# Check if file is allowed
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# ADMIN PROFILE
@app.route('/admin_profile', methods=['GET', 'POST'])
def admin_profile():
    if not db.is_connected():
        db.reconnect()
    cursor = db.cursor(dictionary=True)
    if 'username' not in session:
        return redirect(url_for('login'))

    username = session['username']

    # Fetch user details from the database
    cursor.execute("SELECT * FROM admin WHERE username = %s", (username,))
    user = cursor.fetchone()


    if user:
        profile_picture = user.get('profile_picture', None)

    if request.method == 'POST':
        # Handle Profile Picture Upload
        if 'profile_picture' in request.files:
            profile_picture_file = request.files['profile_picture']
            if profile_picture_file and allowed_file(profile_picture_file.filename):
                # Save the image as a BLOB in the database
                profile_picture_data = profile_picture_file.read()

                cursor.execute("UPDATE admin SET profile_picture = %s WHERE username = %s", 
                               (profile_picture_data, username))
                db.commit()
                flash("Profile picture updated successfully!", "success")

        # Handle Username Update
        new_username = request.form.get('username')
        if new_username:
            cursor.execute("UPDATE admin SET username = %s WHERE username = %s", (new_username, username))
            db.commit()
            session['username'] = new_username
            flash("Username updated successfully!", "success")  

        return redirect(url_for('admin_profile'))

    return render_template('admin_profile.html', username=user['username'], profile_picture=profile_picture)
   

@app.route('/manage_user', methods=['GET'])
def manage_user():
    username = session.get('username')
    if not username:
        flash("You must be logged in to access this page.", "warning")
        return redirect(url_for('login_admin'))

    cursor = db.cursor(dictionary=True)
    cursor.execute("SELECT * FROM admin WHERE username = %s", (username,))
    admin_user = cursor.fetchone()
    if not admin_user:
        flash("Access denied. Admins only.", "danger")
        return redirect(url_for('index'))

    # Join users and token tables to get token details
    cursor.execute("""
        SELECT u.id, u.username, u.email, u.profile_picture, t.token_number, t.start_date, t.expiry_date
        FROM users u
        LEFT JOIN token t ON u.token = t.token_number
    """)
    users = cursor.fetchall()

    cursor.close()

    return render_template('manageuser.html', users=users)

@app.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
def edit_user(user_id):
    username = session.get('username')
    if not username:
        flash("You must be logged in to access this page.", "warning")
        return redirect(url_for('login_admin'))

    cursor = db.cursor(dictionary=True)
    cursor.execute("SELECT * FROM admin WHERE username = %s", (username,))
    admin_user = cursor.fetchone()
    if not admin_user:
        flash("Access denied. Admins only.", "danger")
        return redirect(url_for('index'))

    if request.method == 'POST':
        new_username = request.form.get('username')
        new_email = request.form.get('email')
        new_token = request.form.get('token_number')

        if not new_username or not new_email:
            flash("Username and email cannot be empty.", "error")
            return redirect(url_for('edit_user', user_id=user_id))

        try:
            cursor.execute("UPDATE users SET username = %s, email = %s, token = %s WHERE id = %s",
                           (new_username, new_email, new_token, user_id))
            db.commit()
            flash("User updated successfully.", "success")
        except Exception as e:
            flash(f"Error updating user: {str(e)}", "error")
        return redirect(url_for('manage_user'))

    cursor.execute("""
        SELECT u.id, u.username, u.email, u.token, t.start_date, t.expiry_date
        FROM users u
        LEFT JOIN token t ON u.token = t.token_number
        WHERE u.id = %s
    """, (user_id,))
    user = cursor.fetchone()
    cursor.close()

    if not user:
        flash("User not found.", "error")
        return redirect(url_for('manage_user'))

    return render_template('edit_user.html', user=user)

@app.route('/delete_user/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    username = session.get('username')
    if not username:
        flash("You must be logged in to perform this action.", "warning")
        return redirect(url_for('login_admin'))

    cursor = db.cursor(dictionary=True)
    cursor.execute("SELECT * FROM admin WHERE username = %s", (username,))
    admin_user = cursor.fetchone()
    if not admin_user:
        flash("Access denied. Admins only.", "danger")
        return redirect(url_for('index'))

    try:
        cursor.execute("DELETE FROM users WHERE id = %s", (user_id,))
        db.commit()
        flash("User deleted successfully.", "success")
    except Exception as e:
        flash(f"Error deleting user: {str(e)}", "error")

    return redirect(url_for('manage_user'))

# ADMIN ARCHIVE
@app.route('/admin_archiveurl')
def admin_archiveurl():
    username = session.get('username')
    is_admin = False
    if username:
        cursor = db.cursor(dictionary=True)
        cursor.execute("SELECT * FROM admin WHERE username = %s", (username,))
        admin_user = cursor.fetchone()
        cursor.close()
        if admin_user:
            is_admin = True
    cursor = db.cursor(dictionary=True)
    cursor.execute("SELECT url, classification, note, sender FROM scan_results ORDER BY timestamp DESC")
    results = cursor.fetchall()
    cursor.close()
    print(results)  # 🔥 Add this line
    return render_template('admin_archiveurl.html', results=results, is_admin=is_admin)

# ADMIN TRAINING MODEL PAGE
@app.route('/update_trainingmodel')
def update_trainingmodel():
    username = session.get('username')
    is_admin = False
    if username:
        cursor = db.cursor(dictionary=True)
        cursor.execute("SELECT * FROM admin WHERE username = %s", (username,))
        admin_user = cursor.fetchone()
        if admin_user:
            is_admin = True
        else:
            cursor.close()
            return redirect(url_for('login_admin'))
    else:
        return redirect(url_for('login_admin'))

    if not is_admin:
        flash("Access denied. Admins only.", "danger")
        return redirect(url_for('index'))

    # List files in dataset_path
    try:
        files = os.listdir(dataset_path)
        # Filter only files (exclude directories)
        files = [f for f in files if os.path.isfile(os.path.join(dataset_path, f))]
    except Exception as e:
        flash(f"Error reading dataset directory: {str(e)}", "error")
        files = []

    # Query trainingmodel table for accuracy records
    try:
        cursor.execute("SELECT accuracy, timestamp, sender FROM trainingmodel ORDER BY timestamp DESC")
        records = cursor.fetchall()
        # Format timestamp as '%d-%m-%Y'
        trainingmodel_records = []
        for record in records:
            formatted_record = {
                'accuracy': record['accuracy'],
                'timestamp': record['timestamp'].strftime('%d-%m-%Y') if record['timestamp'] else '',
                'sender': record['sender']
            }
            trainingmodel_records.append(formatted_record)
    except Exception as e:
        flash(f"Error fetching training model records: {str(e)}", "error")
        trainingmodel_records = []

    cursor.close()

    return render_template('update_trainingmodel.html', dataset_files=files, is_admin=is_admin, trainingmodel_records=trainingmodel_records)

@app.route('/admin/delete_dataset_file/<filename>', methods=['POST'])
def delete_dataset_file(filename):
    username = session.get('username')
    if not username:
        return redirect(url_for('login_admin'))

    cursor = db.cursor(dictionary=True)
    cursor.execute("SELECT * FROM admin WHERE username = %s", (username,))
    admin_user = cursor.fetchone()
    cursor.close()
    if not admin_user:
        flash("Access denied. Admins only.", "danger")
        return redirect(url_for('index'))

    # Debug: log original filename
    print(f"Original filename: {filename}")

    # Security check: prevent path traversal
    if '..' in filename or filename.startswith('/') or filename.startswith('\\'):
        flash("Invalid filename.", "error")
        return redirect(url_for('update_trainingmodel'))

    file_path = os.path.join(dataset_path, filename)

    if os.path.exists(file_path) and os.path.isfile(file_path):
        try:
            os.remove(file_path)
            flash(f"File '{filename}' deleted successfully.", "success")
        except Exception as e:
            flash(f"Error deleting file '{filename}': {str(e)}", "error")
    else:
        flash(f"File '{filename}' not found.", "error")

    return redirect(url_for('update_trainingmodel'))

# ADMIN UPDATE DATASET
@app.route('/admin/upload_dataset', methods=['POST'])
def upload_dataset():
    if 'dataset' not in request.files:
        flash('No file part in the request', 'error')
        return redirect(url_for('update_trainingmodel'))

    file = request.files['dataset']
    if file.filename == '':
        flash('No selected file', 'error')
        return redirect(url_for('update_trainingmodel'))

    if file and file.filename.endswith('.csv'):
        file_path = os.path.join(dataset_path, file.filename)
        file.save(file_path)
        flash(f'Dataset uploaded successfully as {file.filename}', 'success')
        # Pass the uploaded dataset name to the template
        return render_template('update_trainingmodel.html', dataset_uploaded=file.filename)
    else:
        flash('Invalid file type. Only CSV files are allowed.', 'error')

    return redirect(url_for('update_trainingmodel'))

# ADMIN REGENERATE TRAINING MODEL
@app.route('/admin/regenerate_model', methods=['POST'])
def regenerate_model():
    try:
        # Call the urcheck.py script using subprocess
        result = subprocess.run(
            ['python', urcheck_script],
            capture_output=True,
            text=True
        )

        # Check script execution status
        if result.returncode == 0:
            output = result.stdout
            accuracy_line = next((line for line in output.splitlines() if "Accuracy:" in line), None)
            if accuracy_line:
                accuracy = accuracy_line.split(":")[1].strip()
                flash(f'Training model regenerated successfully! {accuracy}', 'success')
                # Save accuracy to trainingmodel table
                sender = session.get('username', 'unknown')
                try:
                    cursor = db.cursor()
                    cursor.execute(
                        "INSERT INTO trainingmodel (accuracy, sender) VALUES (%s, %s)",
                        (float(accuracy.strip('%')), sender)
                    )
                    db.commit()
                    cursor.close()
                except Exception as e:
                    flash(f"Failed to save accuracy to database: {str(e)}", "error")
            else:
                flash('Training model regenerated successfully, but accuracy could not be retrieved.', 'success')
        else:
            # Check for specific FileNotFoundError message in stderr
            if "No CSV file found in the specified folder" in result.stderr:
                flash("No CSV file found in the dataset folder. Please upload a CSV file before regenerating the model.", "error")
            else:
                raise RuntimeError(f"Error in script execution: {result.stderr}")
    except Exception as e:
        flash(f'Error during model regeneration: {str(e)}', 'error')

    return redirect(url_for('update_trainingmodel'))

# ADMIN DELETE ARCHIVE URL
@app.route('/delete_url/<int:id>')
def delete_url(id):
    if 'username' not in session or session['username'] != 'admin':
        return redirect(url_for('login_admin'))

    cursor.execute('DELETE FROM archive_urls WHERE id = %s', (id,))
    db.commit()


    return redirect(url_for('admin_archiveurl'))

# ---- Generate Token Route ----
@app.route('/generate_token', methods=['GET', 'POST'])
def generate_token():
    from datetime import datetime
    # Session check: redirect if user not logged in
    if 'username' not in session:
        flash("You must log in to access this page.", "danger")
        return redirect(url_for('login_admin'))  # Make sure you have a 'login' route

    if request.method == 'POST':
        rand1 = random.randint(1000, 9999)
        rand2 = random.randint(1000, 9999)
        md5part = hashlib.md5(str(random.random()).encode()).hexdigest()[:2]
        token_number = f"{rand1}-{md5part}-{rand2}"

        cursor = db.cursor()
        try:
            cursor.execute("INSERT INTO token (token_number) VALUES (%s)", (token_number,))
            db.commit()
            flash(f'New token generated: {token_number}', 'success')
        except Exception as e:
            flash(f'Failed to generate token. Error: {str(e)}', 'danger')
        finally:
            cursor.close()

        return redirect(url_for('generate_token'))

    cursor = db.cursor(dictionary=True)
    cursor.execute("SELECT token_number, start_date, expiry_date, timestamp FROM token ORDER BY timestamp DESC")
    tokens = cursor.fetchall()
    cursor.close()
    now = datetime.now()

    def get_status(token):
        if not token['start_date'] or not token['expiry_date']:
            return 1  # inactive
        elif token['expiry_date'] > now:
            return 0  # active
        else:
            return 2  # expired

    # Sort tokens by status and then by timestamp descending
    tokens_sorted = sorted(tokens, key=lambda t: (get_status(t), -t['timestamp'].timestamp()))

    return render_template('generate_token.html', tokens=tokens_sorted, now=now)

@app.route('/renew_token', methods=['GET', 'POST'])
def renew_token():
    username = request.args.get('username')

    if request.method == 'POST':
        token_input = request.form['token']

        cursor = db.cursor(dictionary=True)
        cursor.execute("SELECT * FROM token WHERE token_number = %s AND start_date IS NULL AND expiry_date IS NULL", (token_input,))
        new_token = cursor.fetchone()

        if new_token:
            start_date = datetime.now()
            expiry_date = start_date + relativedelta(months=3)

            cursor.execute("UPDATE users SET token = %s WHERE username = %s", (token_input, username))
            cursor.execute("UPDATE token SET start_date = %s, expiry_date = %s WHERE token_number = %s",
                           (start_date, expiry_date, token_input))
            db.commit()

            return redirect('/login')
        else:
            return render_template('renew_token.html', username=username, error="Invalid or used token")

    return render_template('renew_token.html', username=username)


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))



if __name__ == '__main__':
    app.run(debug=True)
