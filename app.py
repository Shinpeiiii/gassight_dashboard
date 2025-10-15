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
import os
from flask import Flask
from datetime import datetime

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = os.path.join('static', 'uploads')


# -----------------------------
# App setup
# -----------------------------
app = Flask(__name__, static_folder='static', template_folder='templates')
CORS(app)  # allow mobile/web to call /api/*

app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-change-me')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///gassight.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'super-secret-key')
jwt = JWTManager(app)

# uploads
app.config['UPLOAD_FOLDER'] = os.path.join(app.static_folder, 'uploads')
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

ADMIN_CODE = os.environ.get('ADMIN_CODE', 'GASSIGHT_ADMIN')

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

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
            return login_manager.unauthorized()
        if not current_user.is_admin:
            flash("Admin access required.", "danger")
            return redirect(url_for('login'))
        return view_func(*args, **kwargs)
    return wrapper

# -----------------------------
# Pages
# -----------------------------
@app.route('/')
@login_required
@admin_required
def index():
    # dashboard pulls data via /api/*, so just render template
    return render_template('dashboard.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user, remember=True)
            flash("Welcome back!", "success")
            return redirect(request.args.get('next') or url_for('index'))
        flash("Invalid username or password.", "danger")
    
    # ✅ Pass datetime explicitly here
    return render_template('login.html', datetime=datetime)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        admin_code = request.form.get('admin_code', '').strip()

        if not username or not password:
            flash("Username and password are required.", "danger")
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
        flash("Account created.", "success")
        return redirect(url_for('index'))

    # 👇 FIX: Pass datetime to the template here
    return render_template('register.html', datetime=datetime)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("Logged out.", "info")
    return redirect(url_for('login'))

@app.route('/offline')
def offline():
    return render_template('offline.html')

@app.route('/loading')
def loading():
    return render_template('loading.html')

@app.route('/static/<path:filename>')
def static_files(filename):
    return send_from_directory(app.static_folder, filename)

# -----------------------------
# API – Auth for mobile
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
# API – Submit report (mobile/web)
# -----------------------------
@app.route('/api/report', methods=['POST'])
@jwt_required()
def submit_report():
    """Accepts JSON (web) or multipart/form-data (mobile)."""
    try:
        user_id = int(get_jwt_identity())

        # JSON (Flutter web)
        if request.is_json:
            data = request.get_json(force=True)
            reporter     = data.get("reporter", "")
            barangay     = data.get("barangay", "")
            municipality = data.get("municipality", "")
            province     = data.get("province", "")
            severity     = data.get("severity", "Low")
            lat          = data.get("lat")
            lng          = data.get("lng")
            photo_path   = data.get("photo_url", "")

        # Multipart (Flutter mobile)
        elif request.content_type and "multipart/form-data" in request.content_type:
            reporter     = request.form.get("reporter", "")
            barangay     = request.form.get("barangay", "")
            municipality = request.form.get("municipality", "")
            province     = request.form.get("province", "")
            severity     = request.form.get("severity", "Low")
            lat          = request.form.get("lat")
            lng          = request.form.get("lng")

            photo_file = request.files.get("photo")
            photo_path = ""
            if photo_file:
                filename  = secure_filename(f"{uuid.uuid4().hex}_{photo_file.filename}")
                save_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                photo_file.save(save_path)
                photo_path = f"/static/uploads/{filename}"

        else:
            return jsonify({"error": "Unsupported content type"}), 415

        if not reporter or not barangay or not municipality or not province:
            return jsonify({"error": "Missing required fields"}), 400

        try:
            lat = float(lat) if lat not in [None, ""] else None
            lng = float(lng) if lng not in [None, ""] else None
        except ValueError:
            lat, lng = None, None

        new_report = Report(
            reporter=reporter,
            barangay=barangay,
            municipality=municipality,
            province=province,
            severity=severity,
            status="Pending",
            lat=lat, lng=lng,
            photo=photo_path,
            user_id=user_id
        )
        db.session.add(new_report)
        db.session.commit()

        return jsonify({"message": "Report submitted", "report_id": new_report.id}), 201

    except Exception as e:
        print("⚠️ submit_report error:", e)
        return jsonify({"error": str(e)}), 422

# -----------------------------
# API – Dashboard data
# -----------------------------
@app.route('/api/reports')
def get_reports():
    try:
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
    except Exception as e:
        print("⚠️ Error in /api/reports:", e)
        return jsonify({"error": str(e)}), 500

@app.route('/api/report/<int:report_id>/status', methods=['PUT'])
def update_report_status(report_id):
    data = request.get_json(force=True)
    new_status = (data.get('status') or '').strip()
    if new_status not in ('Verified', 'Rejected', 'Pending'):
        return jsonify({"error": "Invalid status"}), 400
    report = Report.query.get_or_404(report_id)
    report.status = new_status
    db.session.commit()
    return jsonify({"message": f"Report {report_id} updated to {new_status}"}), 200

@app.route('/api/kpis')
def get_kpis():
    total_sightings = Report.query.count()
    active_hotspots = Report.query.filter_by(severity="High").count()
    active_reporters = len(set(r.reporter for r in Report.query.all() if r.reporter))
    avg_response_time = 18  # placeholder
    return jsonify({
        'total_sightings': total_sightings,
        'active_hotspots': active_hotspots,
        'active_reporters': active_reporters,
        'avg_response_time': avg_response_time
    })

@app.route('/api/severity-distribution')
def severity_distribution():
    counts = {"Low": 0, "Moderate": 0, "High": 0}
    for r in Report.query.all():
        if r.severity in counts:
            counts[r.severity] += 1
    return jsonify(counts)

@app.route('/api/barangay-reports')
def barangay_reports():
    barangay_data = {}
    for r in Report.query.all():
        barangay_data[r.barangay] = barangay_data.get(r.barangay, 0) + 1
    data = [{"name": b, "reports": c} for b, c in barangay_data.items()]
    return jsonify(data)

# 👇 NEW: used by your filter dropdown, prevents 404
@app.route('/api/barangays')
def api_barangays():
    rows = db.session.execute(db.select(Report.barangay).distinct()).scalars().all()
    # filter out empty/null
    return jsonify([b for b in rows if b])

@app.route('/api/trend')
def trend():
    data = [{"week": f"W{i}", "sightings": random.randint(10, 50)} for i in range(1, 8)]
    return jsonify(data)

# -----------------------------
# Run
# -----------------------------
if __name__ == '__main__':
    import os
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)

