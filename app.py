from flask import (
    Flask, render_template, jsonify, send_from_directory,
    request, redirect, url_for, flash
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin, login_user, logout_user,
    login_required, current_user
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
from functools import wraps
import os, uuid

from flask_jwt_extended import (
    JWTManager, create_access_token, create_refresh_token,
    jwt_required, get_jwt_identity
)
from flask_cors import CORS

# -----------------------------
# App setup
# -----------------------------
app = Flask(_name_, static_folder='static', template_folder='templates')

CORS(app, resources={r"/api/*": {"origins": "*"}})

app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-change-me')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///gassight.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'super-secret-key')

app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_SAMESITE'] = "None"
app.config['REMEMBER_COOKIE_SECURE'] = True
app.config['REMEMBER_COOKIE_SAMESITE'] = "None"

app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=2)
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(days=7)

jwt = JWTManager(app)
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

app.config['UPLOAD_FOLDER'] = os.path.join(app.static_folder, 'uploads')
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

ADMIN_CODE = os.environ.get('ADMIN_CODE', 'GASSIGHT_ADMIN')

# -----------------------------
# Models
# -----------------------------
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)

    full_name = db.Column(db.String(200))
    email = db.Column(db.String(200), unique=True)
    contact = db.Column(db.String(100))
    address = db.Column(db.String(255))

    is_admin = db.Column(db.Boolean, default=False)

    def set_password(self, pw):
        self.password_hash = generate_password_hash(pw)

    def check_password(self, pw):
        return check_password_hash(self.password_hash, pw)


class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.DateTime, default=datetime.utcnow)
    reporter = db.Column(db.String(120))
    barangay = db.Column(db.String(120))
    municipality = db.Column(db.String(120))
    province = db.Column(db.String(120))
    severity = db.Column(db.String(50))
    status = db.Column(db.String(50), default="Pending")
    action_status = db.Column(db.String(50), default="Not Resolved")
    photo = db.Column(db.String(255))
    lat = db.Column(db.Float)
    lng = db.Column(db.Float)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# -----------------------------
# Static Routes
# -----------------------------
@app.route('/service-worker.js')
def service_worker():
    return send_from_directory('static', 'service-worker.js')


@app.route('/static/<path:filename>')
def static_files(filename):
    return send_from_directory(app.static_folder, filename)


# -----------------------------
# Helpers
# -----------------------------
def admin_required(view_func):
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for('login'))
        if not current_user.is_admin:
            flash("⚠️ Admin access required.", "danger")
            return redirect(url_for('no_access'))
        return view_func(*args, **kwargs)
    wrapper.__name__ = view_func.__name__
    return wrapper


# -----------------------------
# Pages
# -----------------------------
@app.route('/')
def home():
    if not current_user.is_authenticated:
        return redirect(url_for('login'))
    return redirect(url_for('dashboard' if current_user.is_admin else 'no_access'))


@app.route('/dashboard')
@login_required
@admin_required
def dashboard():
    return render_template('dashboard.html')


@app.route('/no-access')
@login_required
def no_access():
    return render_template('no_access.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard' if current_user.is_admin else 'no_access'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            login_user(user, remember=True)
            return redirect(url_for('dashboard' if user.is_admin else 'no_access'))

        flash("Invalid username or password.", "danger")

    return render_template('login.html', datetime=datetime)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard' if current_user.is_admin else 'no_access'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password')
        full_name = request.form.get('full_name', '').strip()
        email = request.form.get('email', '').strip()
        contact = request.form.get('contact_number', '').strip()
        address = request.form.get('address', '').strip()
        admin_code = request.form.get('admin_code', '').strip()

        if User.query.filter_by(username=username).first():
            flash("Username already taken.", "warning")
            return render_template('register.html', datetime=datetime)

        user = User(
            username=username,
            full_name=full_name,
            email=email,
            contact=contact,
            address=address,
            is_admin=(admin_code == ADMIN_CODE)
        )
        user.set_password(password)

        db.session.add(user)
        db.session.commit()

        login_user(user)
        return redirect(url_for('dashboard' if user.is_admin else 'no_access'))

    return render_template('register.html', datetime=datetime)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


# -----------------------------
# API – Mobile Auth
# -----------------------------
@app.route('/api/register', methods=['POST'])
def api_register():
    try:
        data = request.get_json(force=True)

        username = data.get('username', '').strip()
        password = data.get('password', '').strip()
        full_name = data.get('fullName', '').strip()
        email = data.get('email', '').strip()
        contact = data.get('contact', '').strip()
        address = data.get('address', '').strip()
        admin_code = data.get('adminCode', '').strip()

        if User.query.filter_by(username=username).first():
            return jsonify({"error": "Username already exists"}), 409

        user = User(
            username=username,
            full_name=full_name,
            email=email,
            contact=contact,
            address=address,
            is_admin=(admin_code == ADMIN_CODE)
        )
        user.set_password(password)

        db.session.add(user)
        db.session.commit()

        return jsonify({"message": "Account created successfully!"}), 201

    except Exception as e:
        return jsonify({"error": "Server error", "details": str(e)}), 500


@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.get_json()
    username = data.get('username', '').strip()
    password = data.get('password', '')

    user = User.query.filter_by(username=username).first()
    if not user or not user.check_password(password):
        return jsonify({"error": "Invalid username or password"}), 401

    access_token = create_access_token(identity=str(user.id))
    refresh_token = create_refresh_token(identity=str(user.id))

    return jsonify({
        "message": "Login successful",
        "username": user.username,
        "access_token": access_token,
        "refresh_token": refresh_token
    }), 200


# -----------------------------
# API – Dashboard Report Filtering
# -----------------------------
@app.route('/api/reports')
def get_reports():
    try:
        barangay = request.args.get("barangay", "").strip()
        severity = request.args.get("severity", "").strip()
        start_date = request.args.get("start_date")
        end_date = request.args.get("end_date")

        q = Report.query

        # --- Barangay filter (case-insensitive + trimmed) ---
        if barangay and barangay != "All":
            q = q.filter(db.func.lower(db.func.trim(Report.barangay)) ==
                         db.func.lower(barangay.strip()))

        # --- Severity filter ---
        if severity and severity != "All":
            q = q.filter(Report.severity == severity)

        # --- Date range ---
        if start_date and end_date:
            try:
                s = datetime.strptime(start_date, "%Y-%m-%d")
                e = datetime.strptime(end_date, "%Y-%m-%d")
                q = q.filter(Report.date >= s, Report.date <= e)
            except:
                pass

        reports = q.order_by(Report.date.desc()).all()

        data = []
        for r in reports:
            data.append({
                "id": r.id,
                "date": r.date.strftime("%Y-%m-%d %H:%M"),
                "reporter": r.reporter,
                "barangay": (r.barangay or "").strip(),
                "municipality": r.municipality,
                "province": r.province,
                "severity": r.severity,
                "status": r.status,
                "action_status": r.action_status,
                "photo": r.photo,
                "lat": r.lat,
                "lng": r.lng
            })

        return jsonify(data), 200

    except Exception as e:
        print("get_reports error:", e)
        return jsonify({"error": "Failed to fetch reports", "details": str(e)}), 500


# -----------------------------
# Run
# -----------------------------
if _name_ == '_main_':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)