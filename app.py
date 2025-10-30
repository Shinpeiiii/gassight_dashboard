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
from functools import wraps
from datetime import datetime
import os, random, uuid

from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required, get_jwt_identity
)
from flask_cors import CORS

# -----------------------------
# App setup
# -----------------------------
app = Flask(__name__, static_folder='static', template_folder='templates')

# ✅ CORS fix for all /api routes
CORS(app, resources={r"/api/*": {"origins": "*"}})

app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-change-me')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///gassight.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'super-secret-key')

# ✅ Fix session cookie for Render HTTPS handling
app.config['SESSION_COOKIE_SECURE'] = False
app.config['SESSION_COOKIE_SAMESITE'] = "Lax"

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
    photo = db.Column(db.String(255))
    lat = db.Column(db.Float)
    lng = db.Column(db.Float)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

with app.app_context():
    db.create_all()

# -----------------------------
# Helpers
# -----------------------------
def admin_required(view_func):
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for('login'))
        if not current_user.is_admin:
            flash("⚠️ Admin access required.", "danger")
            return redirect(url_for('no_access'))
        return view_func(*args, **kwargs)
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
    return render_template('no_access.html', message="You must be an admin to access the dashboard.")

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
            flash("✅ Welcome back!", "success")
            return redirect(url_for('dashboard' if user.is_admin else 'no_access'))
        flash("❌ Invalid username or password.", "danger")
    return render_template('login.html', datetime=datetime)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard' if current_user.is_admin else 'no_access'))
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        admin_code = request.form.get('admin_code', '').strip()
        if not username or not password:
            flash("Username and password required.", "danger")
            return render_template('register.html', datetime=datetime)
        if User.query.filter_by(username=username).first():
            flash("Username already taken.", "warning")
            return render_template('register.html', datetime=datetime)
        user = User(username=username)
        user.set_password(password)
        user.is_admin = (admin_code == ADMIN_CODE)
        db.session.add(user)
        db.session.commit()
        login_user(user)
        flash("🎉 Account created successfully!", "success")
        return redirect(url_for('dashboard' if user.is_admin else 'no_access'))
    return render_template('register.html', datetime=datetime)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("You’ve been logged out.", "info")
    return redirect(url_for('login'))

@app.route('/static/<path:filename>')
def static_files(filename):
    return send_from_directory(app.static_folder, filename)

@app.route('/offline')
def offline():
    return render_template('offline.html')

@app.route('/loading')
def loading():
    return render_template('loading.html')

# -----------------------------
# API – Mobile Auth
# -----------------------------
@app.route('/api/signup', methods=['POST'])
def api_signup():
    try:
        data = request.get_json(force=True)
        username = data.get('username', '').strip()
        password = data.get('password', '').strip()
        if not username or not password:
            return jsonify({"error": "Username and password required"}), 400
        if User.query.filter_by(username=username).first():
            return jsonify({"error": "Username already exists"}), 409
        user = User(username=username)
        user.set_password(password)
        user.is_admin = False
        db.session.add(user)
        db.session.commit()
        return jsonify({"message": "Account created successfully!"}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.get_json()
    username = data.get('username', '').strip()
    password = data.get('password', '').strip()
    if not username or not password:
        return jsonify({"error": "Missing credentials"}), 400
    user = User.query.filter_by(username=username).first()
    if not user or not user.check_password(password):
        return jsonify({"error": "Invalid username or password"}), 401
    access_token = create_access_token(identity=str(user.id))
    return jsonify({
        "message": "Login successful",
        "username": user.username,
        "token": access_token
    }), 200

# -----------------------------
# API – Submit report
# -----------------------------
@app.route('/api/report', methods=['POST'])
@jwt_required()
def submit_report():
    try:
        user_id = int(get_jwt_identity())
        data = request.get_json(force=True)
        new_report = Report(
            reporter=data.get("reporter", ""),
            barangay=data.get("barangay", ""),
            municipality=data.get("municipality", ""),
            province=data.get("province", ""),
            severity=data.get("severity", "Low"),
            lat=data.get("lat"),
            lng=data.get("lng"),
            photo=data.get("photo_url", ""),
            status="Pending",
            user_id=user_id
        )
        db.session.add(new_report)
        db.session.commit()
        return jsonify({"message": "Report submitted", "report_id": new_report.id}), 201
    except Exception as e:
        print("⚠️ submit_report error:", e)
        return jsonify({"error": str(e)}), 422

# -----------------------------
# API – Dashboard Data
# -----------------------------
@app.route('/api/reports')
def get_reports():
    reports = Report.query.order_by(Report.date.desc()).all()
    data = [{
        "id": r.id,
        "date": r.date.strftime("%Y-%m-%d %H:%M") if r.date else "",
        "reporter": r.reporter or "Unknown",
        "barangay": r.barangay or "",
        "municipality": r.municipality or "",
        "province": r.province or "",
        "severity": r.severity or "Low",
        "status": r.status or "Pending",
        "photo": r.photo or "",
        "lat": r.lat,
        "lng": r.lng
    } for r in reports]
    return jsonify(data)

@app.route('/api/barangays')
def api_barangays():
    barangays = sorted(set(r.barangay for r in Report.query.all() if r.barangay))
    return jsonify(barangays)

@app.route('/api/severity-distribution')
def api_severity_distribution():
    severities = ["Low", "Moderate", "High"]
    data = {s: Report.query.filter_by(severity=s).count() for s in severities}
    return jsonify(data)

@app.route('/api/barangay-reports')
def api_barangay_reports():
    barangays = {}
    for r in Report.query.all():
        if r.barangay:
            barangays[r.barangay] = barangays.get(r.barangay, 0) + 1
    data = [{"name": b, "reports": c} for b, c in barangays.items()]
    return jsonify(data)

@app.route('/api/trend')
def api_trend():
    trend = {}
    for r in Report.query.all():
        week = r.date.strftime("%Y-%W")
        trend[week] = trend.get(week, 0) + 1
    data = [{"week": k, "sightings": v} for k, v in sorted(trend.items())]
    return jsonify(data)

@app.route('/api/kpis')
def get_kpis():
    total_sightings = Report.query.count()
    active_hotspots = Report.query.filter_by(severity="High").count()
    active_reporters = len(set(r.reporter for r in Report.query.all() if r.reporter))
    avg_response_time = 18
    return jsonify({
        'total_sightings': total_sightings,
        'active_hotspots': active_hotspots,
        'active_reporters': active_reporters,
        'avg_response_time': avg_response_time
    })

@app.route('/api/report/<int:report_id>/status', methods=['PUT'])
def update_report_status(report_id):
    report = Report.query.get(report_id)
    if not report:
        return jsonify({"error": "Report not found"}), 404
    data = request.get_json()
    new_status = data.get("status")
    if not new_status:
        return jsonify({"error": "Missing status"}), 400
    report.status = new_status
    db.session.commit()
    return jsonify({"message": f"Report {report_id} updated to {new_status}"}), 200

# -----------------------------
# Run
# -----------------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
