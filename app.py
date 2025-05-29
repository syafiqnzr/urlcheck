from dotenv import load_dotenv
import os
load_dotenv()
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
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
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

# Custom Jinja2 filter for date formatting
@app.template_filter('format_date')
def format_date_filter(date_string):
    """Format date string to DD.MM.YYYY HH:MM format"""
    if not date_string or date_string == 'None' or date_string.strip() == '':
        return 'N/A'

    try:
        # Try to parse the date string
        # Handle different possible formats
        if 'T' in date_string:
            # ISO format with T separator
            dt = datetime.strptime(date_string.split('.')[0], '%Y-%m-%dT%H:%M:%S')
        elif ' ' in date_string and ':' in date_string:
            # Format like "2004-06-04 13:37:18"
            dt = datetime.strptime(date_string, '%Y-%m-%d %H:%M:%S')
        elif ' ' in date_string:
            # Format like "2004-06-04"
            dt = datetime.strptime(date_string, '%Y-%m-%d')
        else:
            # Just date
            dt = datetime.strptime(date_string, '%Y-%m-%d')

        return dt.strftime('%d.%m.%Y %H:%M')
    except (ValueError, AttributeError):
        # If parsing fails, return the original string
        return date_string

# Paths
dataset_path = "dataset"
trainingmodel_path = "training_model"
urcheck_script = "urlcheck.py"


# Ensure necessary folders exist
os.makedirs(dataset_path, exist_ok=True)
os.makedirs(trainingmodel_path, exist_ok=True)

UPLOAD_FOLDER = 'static/uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

@app.context_processor
def inject_user():
    from flask import session
    profile_picture = None
    username = None

    # Check for admin session (uses username)
    if 'username' in session:
        username = session['username']
        ensure_db_connection()
        cursor = db.cursor(dictionary=True)
        # Check if user is admin
        cursor.execute("SELECT * FROM admin WHERE username = %s", (username,))
        admin_user = cursor.fetchone()
        if admin_user:
            # Fetch profile_picture from admin table
            profile_picture = admin_user.get('profile_picture', None)
        cursor.close()

    # Check for regular user session (uses email)
    elif 'email' in session:
        email = session['email']
        ensure_db_connection()
        cursor = db.cursor(dictionary=True)
        # Fetch user data from users table
        cursor.execute("SELECT username, profile_picture FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()
        if user:
            username = user['username']  # For display purposes
            profile_picture = user.get('profile_picture', None)
        cursor.close()

    return dict(profile_picture=profile_picture, username=username)

# ---- Database Config ----

db = mysql.connector.connect(
    host="localhost",
    user="root",
    password="yourpassword",
    database="urlscanner"
)


cursor = db.cursor(dictionary=True)

# Helper function to ensure database connection
def ensure_db_connection():
    global db
    try:
        if not db.is_connected():
            db.reconnect()
    except:
        # If reconnect fails, create a new connection
        db = mysql.connector.connect(
            host="localhost",
            user="root",
            password="",
            database="urlscanner"
        )

# Helper function to convert sender to username for display
def get_username_from_sender(sender):
    """Convert sender (email or username) to username for display purposes"""
    if not sender or sender == 'guest':
        return 'Guest'

    ensure_db_connection()
    cursor = db.cursor(dictionary=True)

    # First check if sender is admin username (direct match)
    cursor.execute("SELECT username FROM admin WHERE username = %s", (sender,))
    admin_result = cursor.fetchone()
    if admin_result:
        cursor.close()
        return admin_result['username']

    # Check if sender is user email
    cursor.execute("SELECT username FROM users WHERE email = %s", (sender,))
    user_result = cursor.fetchone()
    cursor.close()

    if user_result:
        return user_result['username']

    return 'Unknown User'


@app.route('/', methods=['GET'])
def index():
    is_admin = False

    # Check if admin is logged in (email session)
    if 'email' in session:
        email = session['email']
        ensure_db_connection()
        cursor = db.cursor(dictionary=True)
        cursor.execute("SELECT * FROM admin WHERE email = %s", (email,))
        admin_user = cursor.fetchone()
        cursor.close()
        if admin_user:
            is_admin = True

    return render_template('index.html', is_admin=is_admin)


@app.route('/result', methods=['POST'])
def result():
    is_admin = False

    # Check if admin is logged in (email session)
    if 'email' in session:
        email = session['email']
        ensure_db_connection()
        cursor = db.cursor(dictionary=True)
        cursor.execute("SELECT * FROM admin WHERE email = %s", (email,))
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
    final_result, note, breakdown, reasons, mitigation, domain, ip_address = classify_url(original_url, url)
    _, creation_date, age = get_domain_age(url)
    _, registrar = get_domain_registrar(url)
    _, _, updated_date, expiry_date = get_domain_details(url)
    url_length = get_url_length(url)

    # ML prediction label
    url_vector = vectorizer.transform([url])
    raw_prediction = trainedmodel.predict(url_vector)[0]
    ml_prediction = 'Safe' if raw_prediction == 0 else 'Suspicious'

    # Get sender - use email for both admin and regular users
    if 'email' in session:
        sender = session['email']     # User/Admin sender (email-based)
    else:
        sender = 'guest'              # Guest sender

    ensure_db_connection()
    cursor = db.cursor(dictionary=True)

    # Save scan summary
    insert_summary_query = """
    INSERT INTO scan_results (
        url, domain, ip_address, protocol, creation_date, updated_date,
        expiry_date, age, registrar, url_length, classification, ml_prediction, ml_note, note, sender
    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    """
    cursor.execute(insert_summary_query, (
        url, domain, ip_address, protocol, str(creation_date), str(updated_date),
        str(expiry_date), age, registrar, url_length, final_result, ml_prediction, note, note, sender
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
    # Check if user is logged in (either email for users or username for admin)
    if 'email' not in session and 'username' not in session:
        flash("Login to view detailed analysis", "warning")
        return redirect(url_for('login'))

    is_admin = False
    user = None

    # Check if admin is logged in (username session)
    if 'username' in session:
        username = session['username']
        ensure_db_connection()
        cursor = db.cursor(dictionary=True)
        cursor.execute("SELECT * FROM admin WHERE username = %s", (username,))
        admin_user = cursor.fetchone()
        if admin_user:
            is_admin = True
            user = username
        cursor.close()
    # Check if regular user is logged in (email session)
    elif 'email' in session:
        email = session['email']
        ensure_db_connection()
        cursor = db.cursor(dictionary=True)
        cursor.execute("SELECT username FROM users WHERE email = %s", (email,))
        user_data = cursor.fetchone()
        user = user_data['username'] if user_data else 'Unknown User'
        cursor.close()

    url = request.form.get('url')
    ensure_db_connection()
    cursor = db.cursor(dictionary=True)

    # Get scan result for the given URL
    cursor.execute("""
        SELECT url, domain, ip_address, protocol, creation_date, updated_date,
               expiry_date, age, registrar, url_length, classification, note, sender, ml_note, ml_prediction
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

    sender_raw = features[0]['sender'] if features else ''

    # Convert sender to username for display
    sender_username = get_username_from_sender(sender_raw)

    cursor.close()

    return render_template(
        'detail_result.html',
        user=user,
        scan=scan_result,
        ml_prediction=scan_result.get('ml_prediction', ''),
        ml_note=scan_result.get('ml_note', ''),
        scan_url=url,
        sender=sender_username,
        features=features,
        is_admin=is_admin
    )


@app.route('/loginn')
def loginn():
    return render_template('loginn.html')

@app.route('/details/<path:url_encoded>', methods=['GET'])
def details_by_url(url_encoded):
    # Check if user is logged in
    if 'email' not in session:
        flash("Login to view detailed analysis", "warning")
        return redirect(url_for('login'))

    url = unquote(url_encoded)
    is_admin = False
    user = None

    if 'email' in session:
        email = session['email']
        ensure_db_connection()
        cursor = db.cursor(dictionary=True)
        cursor.execute("SELECT * FROM admin WHERE email = %s", (email,))
        admin_user = cursor.fetchone()
        if admin_user:
            is_admin = True
            user = admin_user.get('username', 'Admin')
        else:
            cursor.execute("SELECT username FROM users WHERE email = %s", (email,))
            user_data = cursor.fetchone()
            user = user_data['username'] if user_data else 'Unknown User'
        cursor.close()

    ensure_db_connection()
    cursor = db.cursor(dictionary=True)

    # Get scan result for the given URL
    cursor.execute("""
        SELECT url, domain, ip_address, protocol, creation_date, updated_date,
               expiry_date, age, registrar, url_length, classification, note, sender, ml_prediction, ml_note
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

    sender_raw = features[0]['sender'] if features else ''

    # Convert sender to username for display
    sender_username = get_username_from_sender(sender_raw)

    cursor.close()

    return render_template(
        'detail_result.html',
        user=user,
        scan=scan_result,
        ml_prediction=scan_result.get('ml_prediction', ''),
        ml_note=scan_result.get('ml_note', ''),
        scan_url=url,
        sender=sender_username,
        features=features,
        is_admin=is_admin
    )

@app.route('/admin_details/<path:url_encoded>', methods=['GET'])
def admin_details_by_url(url_encoded):
    # Check if admin is logged in
    if 'username' not in session:
        flash("Admin access required.", "error")
        return redirect(url_for('login_admin'))

    # Verify admin credentials
    username = session.get('username')
    ensure_db_connection()
    cursor = db.cursor(dictionary=True)
    cursor.execute("SELECT * FROM admin WHERE username = %s", (username,))
    admin_user = cursor.fetchone()
    cursor.close()

    if not admin_user:
        flash("Admin access required.", "error")
        return redirect(url_for('login_admin'))

    url = unquote(url_encoded)
    user = admin_user.get('username', 'Admin')

    ensure_db_connection()
    cursor = db.cursor(dictionary=True)

    # Get scan result for the given URL
    cursor.execute("""
        SELECT url, domain, ip_address, protocol, creation_date, updated_date,
               expiry_date, age, registrar, url_length, classification, note, sender, ml_prediction, ml_note
        FROM scan_results
        WHERE url = %s
        ORDER BY id DESC
        LIMIT 1
    """, (url,))
    scan_result = cursor.fetchone()

    if not scan_result:
        flash("No scan result found for the specified URL.", "warning")
        return redirect(url_for('admin_archiveurl'))

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
        return redirect(url_for('admin_archiveurl'))

    latest_timestamp = latest['timestamp']

    # Fetch breakdown features for that timestamp and URL
    cursor.execute("""
        SELECT part, fragment_value, score, reason, mitigation, sender
        FROM url_breakdown
        WHERE scan_url = %s AND timestamp = %s
        ORDER BY FIELD(part, 'Scheme', 'Host', 'Path', 'Port', 'Query', 'Fragment')
    """, (url, latest_timestamp))
    features = cursor.fetchall()

    sender_raw = features[0]['sender'] if features else ''

    # Convert sender to username for display
    sender_username = get_username_from_sender(sender_raw)

    cursor.close()

    return render_template(
        'admin_detail_result.html',
        user=user,
        scan=scan_result,
        ml_prediction=scan_result.get('ml_prediction', ''),
        ml_note=scan_result.get('ml_note', ''),
        scan_url=url,
        sender=sender_username,
        features=features,
        is_admin=True
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
        email = request.form['email']
        password = request.form['password']

        if not email or not password:
            flash("Email and password are required.", "error")
            return render_template('login.html', is_admin=is_admin)

        ensure_db_connection()
        cursor = db.cursor(dictionary=True)

        # First check if user is admin (admin table should have email field)
        cursor.execute("SELECT * FROM admin WHERE email = %s", (email,))
        admin_user = cursor.fetchone()

        if admin_user and admin_user['password'] == password:  # Admin uses plain text password
            # Admin login successful
            session['email'] = email
            cursor.close()
            return redirect('/')

        # Check regular users table
        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()

        if user and check_password_hash(user['password'], password):
            cursor.execute("SELECT expiry_date FROM token WHERE token_number = %s", (user['token'],))
            token_data = cursor.fetchone()

            if token_data and token_data['expiry_date'] and datetime.now() > token_data['expiry_date']:
                cursor.close()
                # Store email in session for token renewal
                session['expired_email'] = email
                return render_template('login.html', is_admin=is_admin, token_expired=True, expired_username=user['username'])

            # Store email in session for regular users
            session['email'] = email
            cursor.close()
            return redirect('/')

        cursor.close()
        flash("Invalid email or password.", "error")
        return render_template('login.html', is_admin=is_admin)

    else:
        # For GET request, check if user in session is admin
        if 'email' in session:
            email = session['email']
            ensure_db_connection()
            cursor = db.cursor(dictionary=True)
            cursor.execute("SELECT * FROM admin WHERE email = %s", (email,))
            admin_user = cursor.fetchone()
            cursor.close()
            if admin_user:
                is_admin = True

    return render_template('login.html', is_admin=is_admin)


def generate_otp(length=6):
    import random
    return ''.join([str(random.randint(0, 9)) for _ in range(length)])


def send_otp_email(receiver_email, otp):
    import smtplib
    from email.message import EmailMessage

    sender_email = "urlcheckmy@gmail.com"  # Replace with your email
    app_password = "tevm peam ujqc zarn"  # NOT your Gmail password

    message = EmailMessage()
    message['Subject'] = 'Your OTP Code'
    message['From'] = sender_email
    message['To'] = receiver_email
    message.set_content("This is a fallback for non-HTML email clients.")
    message.add_alternative(
    f"""\
<html>
  <body>
    <p>Dear User,<br><br>
       Your One-Time Password (OTP) for verifying your account is:<br><br>
       <strong style="font-size: 16px;">{otp}</strong><br><br>
       Please enter this code on the website to complete your verification process.<br>
       This OTP is valid for 1 minute only and should not be shared with anyone.<br><br>
       If you did not request this OTP, please ignore this email.<br><br>
       Thank you,<br>
       <em>URLCHECK Team</em>
    </p>
  </body>
</html>
""",
    subtype='html'
)


    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
            smtp.login(sender_email, app_password)
            smtp.send_message(message)
    except Exception as e:
        print(f"Failed to send OTP email: {e}")


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        token = request.form.get('token', '').strip()

        if not username or not email or not password or not confirm_password or not token:
            flash("All fields are required")
            return render_template('register.html')

        if password != confirm_password:
            flash("Passwords do not match")
            return render_template('register.html')

        cursor = db.cursor(dictionary=True)

        # Check if email already exists in users table
        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        existing_user = cursor.fetchone()

        if existing_user:
            cursor.close()
            flash("Invalid token or invalid input")
            return render_template('register.html')

        # Check if email already exists in admin table
        cursor.execute("SELECT * FROM admin WHERE email = %s", (email,))
        existing_admin = cursor.fetchone()

        if existing_admin:
            cursor.close()
            flash("Invalid token or invalid input")
            return render_template('register.html')

        cursor.execute("SELECT * FROM token WHERE token_number = %s AND start_date IS NULL AND expiry_date IS NULL", (token,))
        token_data = cursor.fetchone()

        if token_data:
            # Store registration data and generate OTP
            otp = generate_otp()
            import hashlib
            otp_hash = hashlib.sha256(otp.encode()).hexdigest()
            from datetime import datetime
            session['registration_data'] = {
                'username': username,
                'email': email,
                'password': generate_password_hash(password),
                'token': token,
                'otp': otp,
                'otp_hash': otp_hash,
                'otp_verified': False,
            'otp_created_time': datetime.now().isoformat(),
                'otp_attempts': 0
            }
            try:
                send_otp_email(email, otp)
            except Exception as e:
                flash(f"Failed to send OTP email: {e}")
                return render_template('register.html')
            flash("OTP sent to your email. Please check and enter it below.")
            return redirect(url_for('otp'))
        else:
            cursor.close()
            flash("Invalid token or invalid input")
            return render_template('register.html')

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
    # Check if user is logged in
    if 'email' not in session:
        return redirect(url_for('login'))

    ensure_db_connection()
    cursor = db.cursor(dictionary=True)

    email = session['email']

    # First check if user is admin
    cursor.execute("SELECT * FROM admin WHERE email = %s", (email,))
    admin_user = cursor.fetchone()

    if admin_user:
        # Admin user - fetch from admin table
        user = admin_user
        is_admin = True
        token_info = None  # Admins don't have tokens
    else:
        # Regular user - fetch from users table
        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()
        is_admin = False
        if user:
            # Get token data for regular users
            cursor.execute("SELECT token_number, start_date, expiry_date FROM token WHERE token_number = %s", (user['token'],))
            token_info = cursor.fetchone()
        else:
            token_info = None

    if not user:
        flash("User not found!", "error")
        return redirect(url_for('login'))

    profile_picture = user.get('profile_picture', None)

    if request.method == 'POST':
        # Handle Password Change
        if request.form.get('action') == 'change_password':
            current_password = request.form.get('current_password')
            new_password = request.form.get('new_password')

            if not current_password or not new_password:
                return jsonify({
                    'success': False,
                    'message': 'Both current and new password are required.'
                })

            # Verify current password based on user type
            if is_admin:
                # Admin password verification (plain text)
                if user['password'] != current_password:
                    return jsonify({
                        'success': False,
                        'message': 'Current password is incorrect.'
                    })
            else:
                # Regular user password verification (hashed)
                cursor.execute("SELECT password FROM users WHERE email = %s", (email,))
                user_data = cursor.fetchone()
                if not user_data or not check_password_hash(user_data['password'], current_password):
                    return jsonify({
                        'success': False,
                        'message': 'Current password is incorrect.'
                    })

            # Validate new password (basic validation - frontend handles detailed validation)
            if len(new_password) < 8:
                return jsonify({
                    'success': False,
                    'message': 'New password must be at least 8 characters long.'
                })

            # Additional password validation
            import re
            if not re.search(r'[A-Z]', new_password):
                return jsonify({
                    'success': False,
                    'message': 'New password must contain at least one uppercase letter.'
                })

            if not re.search(r'[a-z]', new_password):
                return jsonify({
                    'success': False,
                    'message': 'New password must contain at least one lowercase letter.'
                })

            if not re.search(r'[0-9]', new_password):
                return jsonify({
                    'success': False,
                    'message': 'New password must contain at least one digit.'
                })

            if not re.search(r'[!@#$%^&*]', new_password):
                return jsonify({
                    'success': False,
                    'message': 'New password must contain at least one symbol (!@#$%^&*).'
                })

            try:
                # Update password based on user type
                if is_admin:
                    # Update admin password (plain text)
                    cursor.execute("UPDATE admin SET password = %s WHERE email = %s",
                                  (new_password, email))
                else:
                    # Update regular user password (hashed)
                    hashed_new_password = generate_password_hash(new_password)
                    cursor.execute("UPDATE users SET password = %s WHERE email = %s",
                                  (hashed_new_password, email))
                db.commit()
                return jsonify({
                    'success': True,
                    'message': 'Password updated successfully!'
                })
            except Exception as e:
                db.rollback()
                return jsonify({
                    'success': False,
                    'message': 'An error occurred while updating password. Please try again.'
                })

        # Handle Profile Picture Upload
        if 'profile_picture' in request.files:
            profile_picture_file = request.files['profile_picture']
            if profile_picture_file and allowed_file(profile_picture_file.filename):
                # Save the image as a BLOB in the database
                profile_picture_data = profile_picture_file.read()

                if is_admin:
                    cursor.execute("UPDATE admin SET profile_picture = %s WHERE email = %s",
                                   (profile_picture_data, email))
                else:
                    cursor.execute("UPDATE users SET profile_picture = %s WHERE email = %s",
                                   (profile_picture_data, email))
                db.commit()
                flash("Profile picture updated successfully!", "success")

        # Handle Username Update
        new_username = request.form.get('username')
        if new_username:
            if is_admin:
                cursor.execute("UPDATE admin SET username = %s WHERE email = %s", (new_username, email))
            else:
                cursor.execute("UPDATE users SET username = %s WHERE email = %s", (new_username, email))
            db.commit()
            flash("Username updated successfully!", "success")

        return redirect(url_for('profile'))

    return render_template('profile.html',
                               username=user['username'],
                               email=email,
                               token_number=token_info['token_number'] if token_info else '',
                               start_date=token_info['start_date'].strftime('%d-%m-%Y') if token_info and token_info['start_date'] else '',
                               expiry_date=token_info['expiry_date'].strftime('%d-%m-%Y') if token_info and token_info['expiry_date'] else '',
                               profile_picture=profile_picture)



@app.route('/plan', methods=['GET'])
def plan():
    is_admin = False

    if 'email' in session:
        email = session['email']
        ensure_db_connection()
        cursor = db.cursor(dictionary=True)
        cursor.execute("SELECT * FROM admin WHERE email = %s", (email,))
        admin_user = cursor.fetchone()
        cursor.close()
        if admin_user:
            is_admin = True

    return render_template('plan.html', is_admin=is_admin)

@app.route('/archiveurl')
def archiveurl():
    if 'email' not in session:
        flash("You must be logged in to view your scan history.", "warning")
        return redirect(url_for('login'))

    email = session['email']
    ensure_db_connection()
    cursor = db.cursor(dictionary=True)
    cursor.execute("SELECT url, classification, note, timestamp, sender FROM scan_results WHERE sender = %s ORDER BY timestamp DESC", (email,))
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

        # Remove duplicate URLs, keep first occurrence
        seen_urls = set()
        unique_rows = []
        for row in rows:
            if row['url'] not in seen_urls:
                unique_rows.append(row)
                seen_urls.add(row['url'])

        # Create CSV content in memory
        import io
        output = io.StringIO()
        fieldnames = ['url', 'type']
        writer = csv.DictWriter(output, fieldnames=fieldnames)

        writer.writeheader()
        for row in unique_rows:
            writer.writerow({'url': row['url'], 'type': row['classification']})

        # Get CSV content
        csv_content = output.getvalue()
        output.close()

        # Generate filename with current date and time
        from datetime import datetime
        current_datetime = datetime.now()
        # Format: DDMMYYYY_HHMMSS
        date_time_str = current_datetime.strftime('%d%m%Y_%H%M%S')
        new_filename = f'urlcheck_dataset_{date_time_str}.csv'

        # Create response for file download
        from flask import make_response
        response = make_response(csv_content)
        response.headers['Content-Type'] = 'text/csv'
        response.headers['Content-Disposition'] = f'attachment; filename="{new_filename}"'

        return response

    except Exception as e:
        flash(f'Failed to export CSV file: {str(e)}', 'error')
        # Check if request came from admin page
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

        # Admin login logic using username
        ensure_db_connection()
        cursor = db.cursor(dictionary=True)
        cursor.execute('SELECT * FROM admin WHERE username = %s AND password = %s', (username, password))
        user = cursor.fetchone()
        cursor.close()

        if user:
            session['username'] = username  # Store the logged-in admin username in session
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
        return redirect(url_for('login_admin'))

    username = session['username']

    # Fetch user details from the database
    cursor.execute("SELECT * FROM admin WHERE username = %s", (username,))
    user = cursor.fetchone()

    if not user:
        flash("Admin user not found.", "error")
        return redirect(url_for('login_admin'))

    profile_picture = user.get('profile_picture', None)
    email = user.get('email', None)

    if request.method == 'POST':
        # Handle password change via AJAX
        if request.form.get('action') == 'change_password':
            current_password = request.form.get('current_password')
            new_password = request.form.get('new_password')

            # Verify current password (admin uses plain text password)
            if current_password != user['password']:
                return jsonify({'success': False, 'message': 'Current password is incorrect.'})

            # Validate new password
            import re
            if len(new_password) < 8:
                return jsonify({'success': False, 'message': 'Password must be at least 8 characters long.'})
            if not re.search(r'[A-Z]', new_password):
                return jsonify({'success': False, 'message': 'Password must contain at least one uppercase letter.'})
            if not re.search(r'[a-z]', new_password):
                return jsonify({'success': False, 'message': 'Password must contain at least one lowercase letter.'})
            if not re.search(r'[0-9]', new_password):
                return jsonify({'success': False, 'message': 'Password must contain at least one digit.'})
            if not re.search(r'[!@#$%^&*]', new_password):
                return jsonify({'success': False, 'message': 'Password must contain at least one special character (!@#$%^&*).'})

            try:
                # Update password (admin uses plain text)
                cursor.execute("UPDATE admin SET password = %s WHERE username = %s", (new_password, username))
                db.commit()
                return jsonify({'success': True, 'message': 'Password updated successfully!'})
            except Exception as e:
                return jsonify({'success': False, 'message': f'Error updating password: {str(e)}'})

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
        if new_username and new_username != username:
            cursor.execute("UPDATE admin SET username = %s WHERE username = %s", (new_username, username))
            db.commit()
            session['username'] = new_username
            flash("Username updated successfully!", "success")

        # Handle Email Update
        new_email = request.form.get('email')
        if new_email is not None and new_email != email:
            # Basic email validation
            import re
            if new_email and not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', new_email):
                flash("Please enter a valid email address.", "error")
            else:
                cursor.execute("UPDATE admin SET email = %s WHERE username = %s", (new_email, username))
                db.commit()
                flash("Email updated successfully!", "success")

        return redirect(url_for('admin_profile'))

    cursor.close()
    return render_template('admin_profile.html', username=user['username'], email=email, profile_picture=profile_picture)


@app.route('/manage_user', methods=['GET'])
def manage_user():
    username = session.get('username')
    if not username:
        flash("You must be logged in to access this page.", "warning")
        return redirect(url_for('login_admin'))

    ensure_db_connection()
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

    # Add status calculation for each user
    from datetime import datetime
    now = datetime.now()

    for user in users:
        if not user['start_date'] or not user['expiry_date']:
            user['status'] = 'Inactive'
            user['status_color'] = '#6c757d'  # Gray
        elif user['expiry_date'] > now:
            user['status'] = 'Active'
            user['status_color'] = '#28a745'  # Green
        else:
            user['status'] = 'Expired'
            user['status_color'] = '#dc3545'  # Red

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

@app.route('/update_user', methods=['POST'])
def update_user():
    username = session.get('username')
    if not username:
        return jsonify({'success': False, 'message': 'You must be logged in to perform this action.'})

    cursor = db.cursor(dictionary=True)
    cursor.execute("SELECT * FROM admin WHERE username = %s", (username,))
    admin_user = cursor.fetchone()
    if not admin_user:
        return jsonify({'success': False, 'message': 'Access denied. Admins only.'})

    try:
        data = request.get_json()
        user_id = data.get('user_id')
        new_username = data.get('username')
        new_token = data.get('token_number')

        if not user_id or not new_username:
            return jsonify({'success': False, 'message': 'User ID and username are required.'})

        # Check if username already exists (excluding current user)
        cursor.execute("SELECT id FROM users WHERE username = %s AND id != %s", (new_username, user_id))
        existing_user = cursor.fetchone()
        if existing_user:
            return jsonify({'success': False, 'message': 'Username already exists.'})

        # Update user information
        if new_token:
            # Check if token exists and is available
            cursor.execute("SELECT * FROM token WHERE token_number = %s", (new_token,))
            token_data = cursor.fetchone()
            if not token_data:
                return jsonify({'success': False, 'message': 'Token does not exist.'})

            # Check if token is already assigned to another user
            cursor.execute("SELECT username FROM users WHERE token = %s AND id != %s", (new_token, user_id))
            token_user = cursor.fetchone()
            if token_user:
                return jsonify({'success': False, 'message': f'Token is already assigned to user: {token_user["username"]}'})

            # Update user with new token
            cursor.execute("UPDATE users SET username = %s, token = %s WHERE id = %s",
                          (new_username, new_token, user_id))

            # Update token dates when token is assigned
            from datetime import datetime, timedelta
            start_date = datetime.now()
            expiry_date = start_date + relativedelta(months=3)  # 1 hour expiry

            cursor.execute("UPDATE token SET start_date = %s, expiry_date = %s WHERE token_number = %s",
                          (start_date, expiry_date, new_token))

            db.commit()

            return jsonify({
                'success': True,
                'message': 'User updated successfully.',
                'start_date': start_date.strftime('%d.%m.%Y'),
                'expiry_date': expiry_date.strftime('%d.%m.%Y')
            })
        else:
            # Update user without token (remove token assignment)
            cursor.execute("UPDATE users SET username = %s, token = NULL WHERE id = %s",
                          (new_username, user_id))
            db.commit()

            return jsonify({
                'success': True,
                'message': 'User updated successfully.',
                'start_date': 'Not Set',
                'expiry_date': 'Not Set'
            })

    except Exception as e:
        db.rollback()
        return jsonify({'success': False, 'message': f'Error updating user: {str(e)}'})
    finally:
        cursor.close()

@app.route('/delete_user', methods=['POST'])
def delete_user():
    # Check if admin is logged in
    username = session.get('username')
    if not username:
        return jsonify({'success': False, 'message': 'You must be logged in to perform this action.'})

    ensure_db_connection()
    cursor = db.cursor(dictionary=True)
    cursor.execute("SELECT * FROM admin WHERE username = %s", (username,))
    admin_user = cursor.fetchone()
    if not admin_user:
        return jsonify({'success': False, 'message': 'Access denied. Admins only.'})

    try:
        # Get form data
        data = request.get_json()
        user_id = data.get('user_id')
        admin_password = data.get('admin_password')

        if not user_id or not admin_password:
            return jsonify({'success': False, 'message': 'Missing required information.'})

        # Verify admin password
        if admin_user['password'] != admin_password:
            return jsonify({'success': False, 'message': 'Incorrect admin password.'})

        # Get user info before deletion for confirmation message
        cursor.execute("SELECT username, token FROM users WHERE id = %s", (user_id,))
        user_to_delete = cursor.fetchone()

        if not user_to_delete:
            return jsonify({'success': False, 'message': 'User not found.'})

        # Delete the associated token first (if exists)
        if user_to_delete['token']:
            cursor.execute("DELETE FROM token WHERE token_number = %s", (user_to_delete['token'],))

        # Delete the user
        cursor.execute("DELETE FROM users WHERE id = %s", (user_id,))
        db.commit()

        return jsonify({
            'success': True,
            'message': f'User "{user_to_delete["username"]}" and associated token deleted successfully.'
        })

    except Exception as e:
        db.rollback()
        return jsonify({'success': False, 'message': f'Error deleting user: {str(e)}'})
    finally:
        cursor.close()

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
    cursor.execute("SELECT id, url, classification, note, sender FROM scan_results ORDER BY timestamp DESC")
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

# ADMIN DELETE SCAN RESULT URL
@app.route('/delete_scan_result', methods=['POST'])
def delete_scan_result():
    # Check if admin is logged in
    username = session.get('username')
    if not username:
        flash("You must be logged in to perform this action.", "error")
        return redirect(url_for('login_admin'))

    # Verify admin status
    cursor = db.cursor(dictionary=True)
    cursor.execute("SELECT * FROM admin WHERE username = %s", (username,))
    admin_user = cursor.fetchone()
    if not admin_user:
        flash("Access denied. Admins only.", "error")
        return redirect(url_for('index'))

    # Get form data
    scan_id = request.form.get('scan_id')
    admin_password = request.form.get('admin_password')

    if not scan_id or not admin_password:
        flash("Missing required information.", "error")
        return redirect(url_for('admin_archiveurl'))

    # Verify admin password
    if admin_user['password'] != admin_password:
        flash("Incorrect admin password.", "error")
        return redirect(url_for('admin_archiveurl'))

    try:
        # First get the URL to delete related breakdown entries
        cursor.execute("SELECT url FROM scan_results WHERE id = %s", (scan_id,))
        url_result = cursor.fetchone()

        if url_result:
            url_to_delete = url_result['url']

            # Delete related url_breakdown entries first
            cursor.execute("DELETE FROM url_breakdown WHERE scan_url = %s", (url_to_delete,))

            # Then delete from scan_results table
            cursor.execute("DELETE FROM scan_results WHERE id = %s", (scan_id,))

            db.commit()
            flash("URL deleted successfully.", "success")
        else:
            flash("URL not found.", "error")

    except Exception as e:
        db.rollback()
        flash(f"Error deleting URL: {str(e)}", "error")
    finally:
        cursor.close()

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

# ADMIN DELETE TOKEN
@app.route('/delete_token', methods=['POST'])
def delete_token():
    # Check if admin is logged in
    username = session.get('username')
    if not username:
        flash("You must be logged in to perform this action.", "error")
        return redirect(url_for('login_admin'))

    # Verify admin status
    cursor = db.cursor(dictionary=True)
    cursor.execute("SELECT * FROM admin WHERE username = %s", (username,))
    admin_user = cursor.fetchone()
    if not admin_user:
        flash("Access denied. Admins only.", "error")
        return redirect(url_for('index'))

    # Get form data
    token_number = request.form.get('token_number')
    admin_password = request.form.get('admin_password')

    if not token_number or not admin_password:
        flash("Missing required information.", "error")
        return redirect(url_for('generate_token'))

    # Verify admin password
    if admin_user['password'] != admin_password:
        flash("Incorrect admin password.", "error")
        return redirect(url_for('generate_token'))

    try:
        # Check if token is being used by any user
        cursor.execute("SELECT username FROM users WHERE token = %s", (token_number,))
        user_with_token = cursor.fetchone()

        if user_with_token:
            flash(f"Cannot delete token. It is currently assigned to user: {user_with_token['username']}", "error")
            return redirect(url_for('generate_token'))

        # Delete the token
        cursor.execute("DELETE FROM token WHERE token_number = %s", (token_number,))

        if cursor.rowcount > 0:
            db.commit()
            flash(f"Token {token_number} deleted successfully.", "success")
        else:
            flash("Token not found.", "error")

    except Exception as e:
        db.rollback()
        flash(f"Error deleting token: {str(e)}", "error")
    finally:
        cursor.close()

    return redirect(url_for('generate_token'))

# Get token owner information
@app.route('/get_token_owner/<token_number>')
def get_token_owner(token_number):
    # Check if admin is logged in
    if 'username' not in session:
        return jsonify({'success': False, 'message': 'Access denied. Please log in as admin.'})

    try:
        ensure_db_connection()
        cursor = db.cursor(dictionary=True)

        # Fetch user information for the given token
        cursor.execute("""
            SELECT u.username, u.email
            FROM users u
            WHERE u.token = %s
        """, (token_number,))

        user = cursor.fetchone()
        cursor.close()

        if user:
            return jsonify({
                'success': True,
                'owner': {
                    'username': user['username'],
                    'email': user['email']
                }
            })
        else:
            return jsonify({
                'success': True,
                'owner': None,
                'message': 'No owner assigned to this token'
            })

    except Exception as e:
        return jsonify({'success': False, 'message': f'Error fetching token owner: {str(e)}'})

# ADMIN UPDATE SCAN RESULT
@app.route('/update_scan_result', methods=['POST'])
def update_scan_result():
    # Check if admin is logged in
    username = session.get('username')
    if not username:
        flash("You must be logged in to perform this action.", "error")
        return redirect(url_for('login_admin'))

    # Verify admin status
    cursor = db.cursor(dictionary=True)
    cursor.execute("SELECT * FROM admin WHERE username = %s", (username,))
    admin_user = cursor.fetchone()
    if not admin_user:
        flash("Access denied. Admins only.", "error")
        return redirect(url_for('index'))

    # Get form data
    scan_id = request.form.get('scan_id')
    classification = request.form.get('classification')
    note = request.form.get('note')
    admin_password = request.form.get('admin_password')

    if not scan_id or not classification or not admin_password:
        flash("Missing required information.", "error")
        return redirect(url_for('admin_archiveurl'))

    # Verify admin password
    if admin_user['password'] != admin_password:
        flash("Incorrect admin password.", "error")
        return redirect(url_for('admin_archiveurl'))

    try:
        # Update the scan result
        cursor.execute("""
            UPDATE scan_results
            SET classification = %s, note = %s
            WHERE id = %s
        """, (classification, note, scan_id))

        db.commit()
        flash("URL information updated successfully.", "success")

    except Exception as e:
        db.rollback()
        flash(f"Error updating URL information: {str(e)}", "error")
    finally:
        cursor.close()

    return redirect(url_for('admin_archiveurl'))

@app.route('/renew_token', methods=['GET', 'POST'])
def renew_token():
    # Get email from session (for expired token flow) or URL parameter (for direct access)
    email = session.get('expired_email') or request.args.get('email')

    if not email:
        flash("Access denied. Please log in first.", "error")
        return redirect(url_for('login'))

    # Get username for display purposes
    ensure_db_connection()
    cursor = db.cursor(dictionary=True)
    cursor.execute("SELECT username FROM users WHERE email = %s", (email,))
    user = cursor.fetchone()
    username = user['username'] if user else 'Unknown User'

    if request.method == 'POST':
        token_input = request.form['token']

        cursor.execute("SELECT * FROM token WHERE token_number = %s AND start_date IS NULL AND expiry_date IS NULL", (token_input,))
        new_token = cursor.fetchone()

        if new_token:
            start_date = datetime.now()
            from dateutil.relativedelta import relativedelta
            expiry_date = start_date + relativedelta(months=3)  # 3 months expiry

            # Activate the original token by setting start_date and expiry_date
            cursor.execute("UPDATE token SET start_date = %s, expiry_date = %s WHERE token_number = %s",
                           (start_date, expiry_date, token_input))

            # Update user's token to the original token
            cursor.execute("UPDATE users SET token = %s WHERE email = %s", (token_input, email))

            db.commit()

            # Clear the expired email from session
            session.pop('expired_email', None)

            cursor.close()
            return redirect('/login')
        else:
            cursor.close()
            return render_template('renew_token.html', username=username, error="Invalid or used token")

    cursor.close()
    return render_template('renew_token.html', username=username)


@app.route('/logout')
def logout():
    session.clear()
    flash("You have been logged out successfully.", "success")
    return redirect(url_for('index'))



import hashlib
from datetime import datetime, timedelta

@app.route('/otp', methods=['GET', 'POST'])
def otp():
    registration_data = session.get('registration_data')
    if not registration_data or registration_data.get('otp_verified', False):
        return redirect(url_for('register'))

    # Check OTP expiration
    otp_created_time = registration_data.get('otp_created_time')
    if otp_created_time:
        from datetime import datetime
        otp_created_time_dt = datetime.fromisoformat(otp_created_time)
        otp_age = datetime.now() - otp_created_time_dt
        if otp_age > timedelta(minutes=1):
            session.pop('registration_data', None)
            flash("OTP expired. Please register again.", "error")
            return redirect(url_for('register'))

    # Initialize or get OTP attempt count
    otp_attempts = registration_data.get('otp_attempts', 0)

    if request.method == 'POST':
        entered_otp = request.form.get('otp', '').strip()

        if not entered_otp:
            flash("Please enter the OTP.", "error")
            return render_template('otp.html')

        # Hash entered OTP for comparison
        entered_otp_hash = hashlib.sha256(entered_otp.encode()).hexdigest()
        stored_otp_hash = registration_data.get('otp_hash')

        if otp_attempts >= 3:
            session.pop('registration_data', None)
            flash("Too many invalid attempts. Please register again.", "error")
            return redirect(url_for('register'))

        if entered_otp_hash == stored_otp_hash:
            # OTP verified, save user to DB
            cursor = db.cursor(dictionary=True)
            try:
                # Use the original token directly and activate it
                original_token = registration_data['token']

                start_date = datetime.now()
                from dateutil.relativedelta import relativedelta
                expiry_date = start_date + relativedelta(months=3)  # 3 months expiry

                # Activate the original token by setting start_date and expiry_date
                cursor.execute("UPDATE token SET start_date = %s, expiry_date = %s WHERE token_number = %s",
                               (start_date, expiry_date, original_token))

                # Insert user with the original token
                cursor.execute("INSERT INTO users (username, email, password, token) VALUES (%s, %s, %s, %s)",
                               (registration_data['username'], registration_data['email'], registration_data['password'], original_token))
                db.commit()
            except Exception as e:
                db.rollback()
                flash(f"Failed to complete registration: {e}", "error")
                return render_template('otp.html')
            finally:
                cursor.close()

            # Mark OTP as verified in session
            registration_data['otp_verified'] = True
            session['registration_data'] = registration_data

            session.pop('registration_data', None)
            flash("Registration complete. Please log in.", "success")
            return redirect(url_for('login'))
        else:
            otp_attempts += 1
            registration_data['otp_attempts'] = otp_attempts
            session['registration_data'] = registration_data
            flash(f"Invalid OTP. Attempts left: {3 - otp_attempts}", "error")
            return render_template('otp.html')

    return render_template('otp.html')

import hashlib
from datetime import datetime, timedelta
from flask import session, flash, redirect

# Route to send OTP for password reset
@app.route('/send_reset_otp', methods=['POST'])
def send_reset_otp():
    email = request.form.get('email', '').strip()
    if not email:
        flash("Email is required to send OTP.", "error")
        return redirect(url_for('confirmation'))

    # Create a new local connection to avoid unread result error
    local_db = mysql.connector.connect(
        host="localhost",
        user="root",
        password="",
        database="urlscanner"
    )
    cursor = local_db.cursor(buffered=True, dictionary=True)
    cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
    user = cursor.fetchone()
    cursor.close()
    local_db.close()

    if not user:
        flash("Email not found in our records.", "error")
        return redirect(url_for('confirmation'))

    otp = generate_otp()
    otp_hash = hashlib.sha256(otp.encode()).hexdigest()
    otp_created_time = datetime.now().isoformat()

    session['password_reset'] = {
        'email': email,
        'otp_hash': otp_hash,
        'otp_created_time': otp_created_time,
        'otp_attempts': 0
    }

    try:
        send_otp_email(email, otp)
        flash("OTP sent to your email. Please check and enter it below.")
    except Exception as e:
        flash(f"Failed to send OTP email: {e}", "error")

    return redirect(url_for('confirmation'))

# Confirmation page to input email and OTP
@app.route('/confirmation', methods=['GET', 'POST'])
def confirmation():
    if request.method == 'POST':
        password_reset = session.get('password_reset')
        if not password_reset or 'email' not in password_reset:
            flash("Please request a new OTP for this email.", "error")
            return redirect(url_for('confirmation'))

        entered_otp = request.form.get('otp', '').strip()

        if not entered_otp:
            flash("OTP is required.", "error")
            return render_template('confirmation.html')

        # Check OTP expiration (1 minute)
        otp_created_time = password_reset.get('otp_created_time')
        if otp_created_time:
            otp_created_time_dt = datetime.fromisoformat(otp_created_time)
            if datetime.now() - otp_created_time_dt > timedelta(minutes=1):
                session.pop('password_reset', None)
                flash("OTP expired. Please request a new one.", "error")
                return redirect(url_for('confirmation'))

        otp_attempts = password_reset.get('otp_attempts', 0)
        if otp_attempts >= 3:
            session.pop('password_reset', None)
            flash("Too many invalid attempts. Please request a new OTP.", "error")
            return redirect(url_for('confirmation'))

        entered_otp_hash = hashlib.sha256(entered_otp.encode()).hexdigest()
        if entered_otp_hash == password_reset.get('otp_hash'):
            # OTP verified, mark as verified and proceed to forgot password page
            password_reset['otp_verified'] = True
            session['password_reset'] = password_reset
            return redirect(url_for('forgotpassword'))
        else:
            otp_attempts += 1
            password_reset['otp_attempts'] = otp_attempts
            session['password_reset'] = password_reset
            flash(f"Invalid OTP. Attempts left: {3 - otp_attempts}", "error")
            return render_template('confirmation.html')

    return render_template('confirmation.html')

# Forgot password page to input new password
@app.route('/forgotpassword', methods=['GET', 'POST'])
def forgotpassword():
    password_reset = session.get('password_reset')
    if not password_reset or 'email' not in password_reset or not password_reset.get('otp_verified', False):
        flash("Unauthorized access. Please verify your email and OTP first.", "error")
        return redirect(url_for('index'))

    if request.method == 'POST':
        new_password = request.form.get('new_password', '')
        confirm_password = request.form.get('confirm_password', '')

        if not new_password or not confirm_password:
            flash("Both password fields are required.", "error")
            return render_template('forgotpassword.html')

        if new_password != confirm_password:
            flash("Passwords do not match.", "error")
            return render_template('forgotpassword.html')

        hashed_password = generate_password_hash(new_password)
        email = password_reset['email']

        cursor = db.cursor()
        try:
            cursor.execute("UPDATE users SET password = %s WHERE email = %s", (hashed_password, email))
            db.commit()
            flash("Password updated successfully. Please log in.", "success")
            session.pop('password_reset', None)
            return redirect(url_for('login'))
        except Exception as e:
            db.rollback()
            flash(f"Failed to update password: {e}", "error")
            return render_template('forgotpassword.html')
        finally:
            cursor.close()

    return render_template('forgotpassword.html')

# Contact Us Routes
@app.route('/contact_us', methods=['GET', 'POST'])
def contact_us():
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip()
        subject = request.form.get('subject', '').strip()
        message = request.form.get('message', '').strip()

        # Validation
        if not all([name, email, subject, message]):
            flash("All fields are required.", "error")
            return render_template('contact_us.html')

        # Basic email validation
        import re
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_pattern, email):
            flash("Please enter a valid email address.", "error")
            return render_template('contact_us.html')

        try:
            ensure_db_connection()
            cursor = db.cursor()

            # Insert contact message into database
            insert_query = """
            INSERT INTO contact_us (name, email, subject, message)
            VALUES (%s, %s, %s, %s)
            """
            cursor.execute(insert_query, (name, email, subject, message))
            db.commit()
            cursor.close()

            flash("Your message has been sent successfully! We'll get back to you soon.", "success")
            return redirect(url_for('contact_us'))

        except Exception as e:
            flash("An error occurred while sending your message. Please try again.", "error")
            return render_template('contact_us.html')

    return render_template('contact_us.html')

@app.route('/manage_contact_us')
def manage_contact_us():
    # Check if admin is logged in
    if 'username' not in session:
        flash("Access denied. Please log in as admin.", "warning")
        return redirect(url_for('login_admin'))

    try:
        ensure_db_connection()
        cursor = db.cursor(dictionary=True)

        # Fetch all contact messages ordered by newest first
        cursor.execute("""
            SELECT id, name, email, subject, message,
                   DATE_FORMAT(created_at, '%d.%m.%Y %H:%i') as formatted_date
            FROM contact_us
            ORDER BY id DESC
        """)
        messages = cursor.fetchall()
        cursor.close()

        return render_template('manage_contact_us.html', messages=messages)

    except Exception as e:
        flash("Error loading contact messages.", "error")
        return render_template('manage_contact_us.html', messages=[])

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
