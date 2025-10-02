# ==============================================================================
# IMPORTS AND INITIAL SETUP
# ==============================================================================
import os
import pickle
import json
import pandas as pd
import random
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, render_template, request, flash, redirect, url_for, abort, session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import (
    LoginManager, login_user, logout_user, login_required,
    current_user, UserMixin
)
from dotenv import load_dotenv
import os

load_dotenv()  # loads variables from .env

from smtplib import SMTP
from email.mime.text import MIMEText

# Local imports
from models import db, User, GuidanceResult, Goal
from career_data import get_career_details

# ==============================================================================
# FLASK APPLICATION CONFIGURATION
# ==============================================================================
app = Flask(__name__)
load_dotenv()
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY")

# Detect base directory properly
try:
    basedir = os.path.abspath(os.path.dirname(__file__))
except NameError:
    basedir = os.getcwd()

# Ensure instance folder exists
instance_dir = os.path.join(basedir, "instance")
os.makedirs(instance_dir, exist_ok=True)

# Database path inside instance/
db_path = os.path.join(instance_dir, "compass.db")
app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{db_path}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# ==============================================================================
# EXTENSIONS INITIALIZATION
# ==============================================================================
db.init_app(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = 'You must be logged in to access this page.'
login_manager.login_message_category = 'info'

# ==============================================================================
# LOAD MACHINE LEARNING MODEL AND ENCODER
# ==============================================================================
import joblib

model = None
label_encoder = None
MODEL_DIR = os.path.join(basedir, "model")
os.makedirs(MODEL_DIR, exist_ok=True)

model_path = os.path.join(MODEL_DIR, "model")
encoder_path = os.path.join(MODEL_DIR, "label_encoder.pkl")

if os.path.exists(model_path) and os.path.exists(encoder_path):
    try:
        model = joblib.load(model_path)
        label_encoder = joblib.load(encoder_path)
        print("✅ Machine Learning model and encoder loaded successfully from model/ directory.")
    except Exception as e:
        print(f"⚠️ Could not load ML model. Error: {e}")
else:
    print("⚠️ No model or encoder found in model/. Please run train.py first.")

# ==============================================================================
# USER LOADER AND DECORATORS
# ==============================================================================
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            flash("You do not have permission to access this page.", "danger")
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

# ==============================================================================
# AUTHENTICATION ROUTES
# ==============================================================================
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        email = request.form.get('email')  # now we use email
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()  # query by email
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user, remember=True)
            flash(f"Welcome back, {user.username}!", "success")
            return redirect(url_for('dashboard'))
        else:
            flash('Login failed. Please check your email and password.', 'danger')
    return render_template('auth/login.html')  # make sure your form input name is "email"

@app.route('/signup', methods=['POST'])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    username = request.form.get('username')
    email = request.form.get('email')
    password = request.form.get('password')

    if len(password) < 8:
        flash('Password must be at least 8 characters.', 'warning')
        return redirect(url_for('login'))

    if User.query.filter((User.username==username)|(User.email==email)).first():
        flash('Username or email already exists.', 'warning')
        return redirect(url_for('login'))

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    role = 'admin' if User.query.count() == 0 else 'user'
    new_user = User(username=username, email=email, password=hashed_password, role=role)
    db.session.add(new_user)
    db.session.commit()
    flash('Account created! You can now log in.', 'success')
    return redirect(url_for('login'))

# Email OTP login
@app.route('/login_email', methods=['GET', 'POST'])
def login_email():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        if user:
            otp = generate_otp()
            user.otp = otp
            user.otp_expiry = datetime.utcnow() + timedelta(minutes=5)
            db.session.commit()
            send_email(email, "Your OTP", f"Your login OTP is: {otp}")
            session['otp_email'] = email
            flash('OTP sent to your email!', 'info')
            return redirect(url_for('verify_otp'))
        else:
            flash('Email not found. Signup first.', 'danger')
    return render_template('auth/login_email.html')

@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    email = session.get('otp_email')
    if not email:
        flash('Session expired. Try again.', 'warning')
        return redirect(url_for('login_email'))
    user = User.query.filter_by(email=email).first_or_404()
    if request.method == 'POST':
        otp_input = request.form.get('otp')
        if user.otp == otp_input and user.otp_expiry > datetime.utcnow():
            login_user(user)
            user.otp = None
            user.otp_expiry = None
            db.session.commit()
            session.pop('otp_email', None)
            flash(f"Welcome back, {user.username}!", "success")
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid or expired OTP.', 'danger')
    return render_template('auth/verify_otp.html', email=email)

# Forgot password
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        if user:
            otp = generate_otp()
            user.otp = otp
            user.otp_expiry = datetime.utcnow() + timedelta(minutes=5)
            db.session.commit()
            send_email(email, "Reset Password OTP", f"Your password reset OTP is: {otp}")
            session['reset_email'] = email
            flash('OTP sent to your email!', 'info')
            return redirect(url_for('reset_password'))
        else:
            flash('Email not found.', 'danger')
    return render_template('auth/forgot_password.html')

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    email = session.get('reset_email')
    if not email:
        flash('Session expired. Try again.', 'warning')
        return redirect(url_for('forgot_password'))
    user = User.query.filter_by(email=email).first_or_404()
    if request.method == 'POST':
        otp_input = request.form.get('otp')
        new_pass = request.form.get('password')
        if user.otp == otp_input and user.otp_expiry > datetime.utcnow():
            if len(new_pass) < 8:
                flash('Password must be at least 8 characters.', 'warning')
            else:
                user.password = bcrypt.generate_password_hash(new_pass).decode('utf-8')
                user.otp = None
                user.otp_expiry = None
                db.session.commit()
                session.pop('reset_email', None)
                flash('Password reset successful!', 'success')
                return redirect(url_for('login'))
        else:
            flash('Invalid or expired OTP.', 'danger')
    return render_template('auth/reset_password.html', email=email)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("You have been successfully logged out.", "info")
    return redirect(url_for('landing'))

# ==============================================================================
# MAIN APPLICATION ROUTES
# ==============================================================================
@app.route('/')
def landing():
    return render_template('landing.html')

@app.route('/dashboard')
@login_required
def dashboard():
    last_result = GuidanceResult.query.filter_by(user_id=current_user.id).order_by(GuidanceResult.timestamp.desc()).first()
    active_goals_count = Goal.query.filter_by(user_id=current_user.id, is_completed=False).count()
    completed_goals_count = Goal.query.filter_by(user_id=current_user.id, is_completed=True).count()
    total_assessments = GuidanceResult.query.filter_by(user_id=current_user.id).count()
    stats = {
        'active_goals': active_goals_count,
        'completed_goals': completed_goals_count,
        'total_assessments': total_assessments
    }
    return render_template('main/dashboard.html', name=current_user.username, last_result=last_result, stats=stats)

@app.route('/profile')
@login_required
def profile():
    return render_template('main/profile.html', user=current_user)

@app.route('/assessment')
@login_required
def assessment():
    if model is None:
        flash("The prediction model is not available. Please contact admin.", "danger")
        return redirect(url_for('dashboard'))
    form_fields = getattr(model, "feature_names_in_", [])
    return render_template('main/assessment.html', fields=form_fields)

@app.route('/process_assessment', methods=['POST'])
@login_required
def process_assessment():
    if model is None or label_encoder is None:
        flash("Model is not available.", "danger")
        return redirect(url_for('dashboard'))
    form_data = request.form.to_dict()
    try:
        input_data = [int(value) for value in form_data.values()]
    except ValueError:
        flash("Invalid input.", "danger")
        return redirect(url_for('assessment'))
    input_df = pd.DataFrame([input_data], columns=form_data.keys())
    prediction_encoded = model.predict(input_df)[0]
    career_prediction = label_encoder.inverse_transform([prediction_encoded])[0]
    new_result = GuidanceResult(user_id=current_user.id, inputs_json=json.dumps(form_data), recommended_career=career_prediction)
    db.session.add(new_result)
    db.session.commit()
    flash('Your AI-powered career recommendation is ready!', 'success')
    return render_template('main/results.html', career=career_prediction)

# ==============================================================================
# HISTORY, CAREER, SEARCH, GOALS, ADMIN ROUTES
# ==============================================================================
# IMPORTS AND INITIAL SETUP
# ==============================================================================
import os
import pickle
import json
import pandas as pd
import random
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, render_template, request, flash, redirect, url_for, abort, session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import (
    LoginManager, login_user, logout_user, login_required,
    current_user, UserMixin
)
from smtplib import SMTP
from email.mime.text import MIMEText

# Local imports
from models import db, User, GuidanceResult, Goal
from career_data import get_career_details

# ==============================================================================
# FLASK APPLICATION CONFIGURATION
# ==============================================================================
app = Flask(__name__)
app.config['SECRET_KEY'] = 'this_is_a_very_long_and_secure_secret_key_for_the_mega_app'

# Detect base directory properly
try:
    basedir = os.path.abspath(os.path.dirname(__file__))
except NameError:
    basedir = os.getcwd()

# Ensure instance folder exists
instance_dir = os.path.join(basedir, "instance")
os.makedirs(instance_dir, exist_ok=True)

# Database path inside instance/
db_path = os.path.join(instance_dir, "compass.db")
app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{db_path}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# ==============================================================================
# EXTENSIONS INITIALIZATION
# ==============================================================================
db.init_app(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = 'You must be logged in to access this page.'
login_manager.login_message_category = 'info'

# ==============================================================================
# HELPER FUNCTIONS
# ==============================================================================
def generate_otp():
    return str(random.randint(100000, 999999))


# ==============================================================================
# LOAD MACHINE LEARNING MODEL AND ENCODER
# ==============================================================================
import joblib

model = None
label_encoder = None
MODEL_DIR = os.path.join(basedir, "model")
os.makedirs(MODEL_DIR, exist_ok=True)

model_path = os.path.join(MODEL_DIR, "model")
encoder_path = os.path.join(MODEL_DIR, "label_encoder.pkl")

if os.path.exists(model_path) and os.path.exists(encoder_path):
    try:
        model = joblib.load(model_path)
        label_encoder = joblib.load(encoder_path)
        print("✅ Machine Learning model and encoder loaded successfully from model/ directory.")
    except Exception as e:
        print(f"⚠️ Could not load ML model. Error: {e}")
else:
    print("⚠️ No model or encoder found in model/. Please run train.py first.")

# ==============================================================================
# USER LOADER AND DECORATORS
# ==============================================================================
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            flash("You do not have permission to access this page.", "danger")
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

# ==============================================================================
# AUTHENTICATION ROUTES
# ==============================================================================
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        email = request.form.get('email')  # now we use email
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()  # query by email
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user, remember=True)
            flash(f"Welcome back, {user.username}!", "success")
            return redirect(url_for('dashboard'))
        else:
            flash('Login failed. Please check your email and password.', 'danger')
    return render_template('auth/login.html')  # make sure your form input name is "email"

@app.route('/signup', methods=['POST'])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    username = request.form.get('username')
    email = request.form.get('email')
    password = request.form.get('password')

    if len(password) < 8:
        flash('Password must be at least 8 characters.', 'warning')
        return redirect(url_for('login'))

    if User.query.filter((User.username==username)|(User.email==email)).first():
        flash('Username or email already exists.', 'warning')
        return redirect(url_for('login'))

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    role = 'admin' if User.query.count() == 0 else 'user'
    new_user = User(username=username, email=email, password=hashed_password, role=role)
    db.session.add(new_user)
    db.session.commit()
    flash('Account created! You can now log in.', 'success')
    return redirect(url_for('login'))

# Email OTP login
@app.route('/login_email', methods=['GET', 'POST'])
def login_email():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        if user:
            otp = generate_otp()
            user.otp = otp
            user.otp_expiry = datetime.utcnow() + timedelta(minutes=5)
            db.session.commit()
            send_email(email, "Your OTP", f"Your login OTP is: {otp}")
            session['otp_email'] = email
            flash('OTP sent to your email!', 'info')
            return redirect(url_for('verify_otp'))
        else:
            flash('Email not found. Signup first.', 'danger')
    return render_template('auth/login_email.html')

@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    email = session.get('otp_email')
    if not email:
        flash('Session expired. Try again.', 'warning')
        return redirect(url_for('login_email'))
    user = User.query.filter_by(email=email).first_or_404()
    if request.method == 'POST':
        otp_input = request.form.get('otp')
        if user.otp == otp_input and user.otp_expiry > datetime.utcnow():
            login_user(user)
            user.otp = None
            user.otp_expiry = None
            db.session.commit()
            session.pop('otp_email', None)
            flash(f"Welcome back, {user.username}!", "success")
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid or expired OTP.', 'danger')
    return render_template('auth/verify_otp.html', email=email)
# Import at the top if not already
import os
from smtplib import SMTP, SMTPException
from email.message import EmailMessage

def send_email(to_email, subject, otp=None, purpose="login"):
    """
    Sends a professional-looking email.
    
    :param to_email: Recipient email
    :param subject: Email subject
    :param otp: Optional OTP to include
    :param purpose: Reason for sending (login, reset password, etc.)
    """
    app_name = os.getenv("APP_NAME", "Student Career Guidance")
    
    # Construct professional email body
    if otp:
        body = f"""
Hello,

You are receiving this email because you are trying to {purpose} to your account at {app_name}.

Your One-Time Password (OTP) is: {otp}

⚠️ This code is valid for 5 minutes only. Do not share this OTP with anyone.

If you did not request this {purpose}, please ignore this email.

Thank you,
{app_name} Team
"""
    else:
        body = "Hello,\n\nThis is a notification from your application.\n\nThank you,\nTeam"
    
    # Create EmailMessage object
    msg = EmailMessage()
    msg['Subject'] = subject
    msg['From'] = os.getenv('MAIL_USERNAME')
    msg['To'] = to_email
    msg.set_content(body)

    try:
        with SMTP(os.getenv('MAIL_SERVER'), int(os.getenv('MAIL_PORT'))) as server:
            if os.getenv("MAIL_USE_TLS", "False").lower() == "true":
                server.starttls()
            server.login(os.getenv('MAIL_USERNAME'), os.getenv('MAIL_PASSWORD'))
            server.send_message(msg)
        print(f"✅ Email sent to {to_email}")
    except Exception as e:
        print(f"❌ Error sending email: {e}")

# Forgot password
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        if user:
            otp = generate_otp()
            user.otp = otp
            user.otp_expiry = datetime.utcnow() + timedelta(minutes=5)
            db.session.commit()
            send_email(email, "Reset Password OTP", f"Your password reset OTP is: {otp}")
            session['reset_email'] = email
            flash('OTP sent to your email!', 'info')
            return redirect(url_for('reset_password'))
        else:
            flash('Email not found.', 'danger')
    return render_template('auth/forgot_password.html')

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    email = session.get('reset_email')
    if not email:
        flash('Session expired. Try again.', 'warning')
        return redirect(url_for('forgot_password'))
    user = User.query.filter_by(email=email).first_or_404()
    if request.method == 'POST':
        otp_input = request.form.get('otp')
        new_pass = request.form.get('password')
        if user.otp == otp_input and user.otp_expiry > datetime.utcnow():
            if len(new_pass) < 8:
                flash('Password must be at least 8 characters.', 'warning')
            else:
                user.password = bcrypt.generate_password_hash(new_pass).decode('utf-8')
                user.otp = None
                user.otp_expiry = None
                db.session.commit()
                session.pop('reset_email', None)
                flash('Password reset successful!', 'success')
                return redirect(url_for('login'))
        else:
            flash('Invalid or expired OTP.', 'danger')
    return render_template('auth/reset_password.html', email=email)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("You have been successfully logged out.", "info")
    return redirect(url_for('landing'))

# ==============================================================================
# MAIN APPLICATION ROUTES
# ==============================================================================
@app.route('/')
def landing():
    return render_template('landing.html')

@app.route('/dashboard')
@login_required
def dashboard():
    last_result = GuidanceResult.query.filter_by(user_id=current_user.id).order_by(GuidanceResult.timestamp.desc()).first()
    active_goals_count = Goal.query.filter_by(user_id=current_user.id, is_completed=False).count()
    completed_goals_count = Goal.query.filter_by(user_id=current_user.id, is_completed=True).count()
    total_assessments = GuidanceResult.query.filter_by(user_id=current_user.id).count()
    stats = {
        'active_goals': active_goals_count,
        'completed_goals': completed_goals_count,
        'total_assessments': total_assessments
    }
    return render_template('main/dashboard.html', name=current_user.username, last_result=last_result, stats=stats)

@app.route('/profile')
@login_required
def profile():
    return render_template('main/profile.html', user=current_user)

@app.route('/assessment')
@login_required
def assessment():
    if model is None:
        flash("The prediction model is not available. Please contact admin.", "danger")
        return redirect(url_for('dashboard'))
    form_fields = getattr(model, "feature_names_in_", [])
    return render_template('main/assessment.html', fields=form_fields)

@app.route('/process_assessment', methods=['POST'])
@login_required
def process_assessment():
    if model is None or label_encoder is None:
        flash("Model is not available.", "danger")
        return redirect(url_for('dashboard'))
    form_data = request.form.to_dict()
    try:
        input_data = [int(value) for value in form_data.values()]
    except ValueError:
        flash("Invalid input.", "danger")
        return redirect(url_for('assessment'))
    input_df = pd.DataFrame([input_data], columns=form_data.keys())
    prediction_encoded = model.predict(input_df)[0]
    career_prediction = label_encoder.inverse_transform([prediction_encoded])[0]
    new_result = GuidanceResult(user_id=current_user.id, inputs_json=json.dumps(form_data), recommended_career=career_prediction)
    db.session.add(new_result)
    db.session.commit()
    flash('Your AI-powered career recommendation is ready!', 'success')
    return render_template('main/results.html', career=career_prediction)

# ==============================================================================
# HISTORY, CAREER, SEARCH, GOALS, ADMIN ROUTES
# (keep your existing code unchanged)
from flask import request, render_template, redirect, url_for
from flask_login import login_required, current_user
from career_data import CAREER_DETAILS  # your career info dictionary

@app.route('/search')
@login_required
def search():
    query = request.args.get('query', '').strip()
    if not query:
        return redirect(url_for('dashboard'))  # or 'landing' if you want
    # Filter careers matching the query
    results = {name: data for name, data in CAREER_DETAILS.items() if query.lower() in name.lower()}
    return render_template('main/search_results.html', query=query, results=results)
from flask_login import login_required, current_user
from flask import render_template, redirect, url_for, flash

@app.route('/admin_dashboard')
@login_required
def admin_dashboard():
    if current_user.role != 'admin':
        flash("Access denied: Admins only.", "danger")
        return redirect(url_for('dashboard'))

    users = User.query.all()  # Fetch all users
    return render_template('admin/dashboard.html', users=users)

@app.route('/admin/user/<int:user_id>')
@login_required
def admin_user_detail(user_id):
    if current_user.role != 'admin':
        flash("Access denied: Admins only.", "danger")
        return redirect(url_for('dashboard'))

    user = User.query.get_or_404(user_id)
    page = request.args.get('page', 1, type=int)
    history_pages = GuidanceResult.query.filter_by(user_id=user.id).order_by(GuidanceResult.timestamp.desc()).paginate(page=page, per_page=5)
    
    return render_template('admin/user_detail.html', user=user, history_pages=history_pages)


from flask import render_template, request
from flask_login import current_user
from sqlalchemy import func
from app import db
from models import GuidanceResult

@app.route('/history')
@app.route('/history/page/<int:page>')
def history(page=1):
    # Subquery to get the latest timestamp per recommended_career
    latest_results_subq = (db.session.query(
                                GuidanceResult.recommended_career,
                                func.max(GuidanceResult.timestamp).label('latest_time')
                            )
                            .filter_by(user_id=current_user.id)
                            .group_by(GuidanceResult.recommended_career)
                            .subquery())
    
    # Join with the original table to get full records of latest results
    latest_results = (db.session.query(GuidanceResult)
                      .join(latest_results_subq,
                            (GuidanceResult.recommended_career == latest_results_subq.c.recommended_career) &
                            (GuidanceResult.timestamp == latest_results_subq.c.latest_time))
                      .order_by(GuidanceResult.timestamp.desc())
                      .paginate(page=page, per_page=10))
    
    return render_template('main/history.html', history_pages=latest_results)


from urllib.parse import unquote

@app.route('/career/<career_name>')
@login_required
def career_detail(career_name):
    # Decode URL to get the proper career name
    career_name = unquote(career_name).strip()  # strip removes accidental spaces

    # Try exact match first
    career_info = CAREER_DETAILS.get(career_name)

    # Optional: Case-insensitive match if exact fails
    if not career_info:
        for key in CAREER_DETAILS:
            if key.lower() == career_name.lower():
                career_name = key
                career_info = CAREER_DETAILS[key]
                break

    if not career_info:
        flash(f"No details found for career: {career_name}", "warning")
        return redirect(url_for('dashboard'))

    return render_template('main/career_detail.html', career_name=career_name, career_info=career_info)



from flask_login import login_required, current_user
from flask import render_template

from flask import request, redirect, url_for, flash

@app.route('/goals', methods=['GET', 'POST'])
@login_required
def goals():
    if request.method == 'POST':
        content = request.form.get('content').strip()
        if not content or len(content) < 10:
            flash("Goal description must be at least 10 characters long.", "warning")
            return redirect(url_for('goals'))

        # Save the goal to your database (example using SQLAlchemy)
        new_goal = Goal(user_id=current_user.id, content=content)
        db.session.add(new_goal)
        db.session.commit()
        flash("Goal added successfully!", "success")
        return redirect(url_for('goals'))

    # For GET request, show existing goals
    user_goals = Goal.query.filter_by(user_id=current_user.id).order_by(Goal.date_created.desc()).all()
    return render_template('main/goals.html', goals=user_goals)
@app.route('/goals/toggle/<int:goal_id>')
@login_required
def toggle_goal(goal_id):
    goal = Goal.query.get_or_404(goal_id)
    if goal.user_id != current_user.id:
        flash("You are not authorized to edit this goal.", "danger")
        return redirect(url_for('goals'))

    # Toggle the completion status
    goal.is_completed = not goal.is_completed
    db.session.commit()
    flash("Goal updated successfully.", "success")
    return redirect(url_for('goals'))
@app.route('/goals/delete/<int:goal_id>')
@login_required
def delete_goal(goal_id):
    goal = Goal.query.get_or_404(goal_id)
    if goal.user_id != current_user.id:
        flash("You are not authorized to delete this goal.", "danger")
        return redirect(url_for('goals'))

    db.session.delete(goal)
    db.session.commit()
    flash("Goal deleted successfully.", "success")
    return redirect(url_for('goals'))


# ==============================================================================
# MAIN EXECUTION POINT
# ==============================================================================
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        print(f"✅ Database ready at: {db_path}")
    app.run(debug=True)
