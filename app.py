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
app = Flask(__name__, static_folder='static', template_folder='templates')

# CORS for all /api routes
CORS(app, resources={r"/api/*": {"origins": "*"}})

app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-change-me')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///gassight.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'super-secret-key')

# Cookies (Render runs behind HTTPS)
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_SAMESITE'] = "None"
app.config['REMEMBER_COOKIE_SECURE'] = True
app.config['REMEMBER_COOKIE_SAMESITE'] = "None"

# JWT lifetimes
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
    is_admin = db.Column(db.Boolean, default=False)

    # 👇 Basic info
    full_name = db.Column(db.String(200))
    contact_number = db.Column(db.String(50))
    address = db.Column(db.String(255))
    email = db.Column(db.String(120))

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
    status = db.Column(db.String(50), default="Pending")          # Pending / Approved / Rejected
    action_status = db.Column(db.String(50), default="Not Resolved")
    photo = db.Column(db.String(255))
    lat = db.Column(db.Float)
    lng = db.Column(db.Float)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# Create tables and ensure action_status exists for legacy DBs
with app.app_context():
    db.create_all()
    try:
        insp = db.engine.execute("PRAGMA table_info(user)").fetchall()
        cols = {row[1] for row in insp}
        for col in ["full_name", "contact_number", "address", "email"]:
            if col not in cols:
                db.engine.execute(f"ALTER TABLE user ADD COLUMN {col} VARCHAR(255)")
    except Exception:
        pass


# -----------------------------
# Static & PWA helpers
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
        full_name = request.form.get('full_name', '').strip()
        contact = request.form.get('contact_number', '').strip()
        address = request.form.get('address', '').strip()
        email = request.form.get('email', '').strip()
        admin_code = request.form.get('admin_code', '').strip()

        if not username or not password:
            flash("Username and password required.", "danger")
            return render_template('register.html', datetime=datetime)

        if User.query.filter_by(username=username).first():
            flash("Username already taken.", "warning")
            return render_template('register.html', datetime=datetime)

        user = User(
            username=username,
            full_name=full_name,
            contact_number=contact,
            address=address,
            email=email,
            is_admin=(admin_code == ADMIN_CODE)
        )
        user.set_password(password)
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
        full_name = data.get('full_name', '').strip()
        contact = data.get('contact_number', '').strip()
        address = data.get('address', '').strip()
        email = data.get('email', '').strip()

        if not username or not password:
            return jsonify({"error": "Username and password required"}), 400
        if User.query.filter_by(username=username).first():
            return jsonify({"error": "Username already exists"}), 409

        user = User(
            username=username,
            full_name=full_name,
            contact_number=contact,
            address=address,
            email=email,
            is_admin=False
        )
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        return jsonify({"message": "Account created successfully!"}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.get_json(force=True)
    username = data.get('username', '').strip()
    password = data.get('password', '').strip()
    if not username or not password:
        return jsonify({"error": "Missing credentials"}), 400

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

@app.route('/api/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh_token():
    current_user_id = get_jwt_identity()
    new_access_token = create_access_token(identity=current_user_id)
    return jsonify({"access_token": new_access_token}), 200

@app.route('/api/check_token', methods=['GET'])
@jwt_required()
def check_token():
    # If we got here, token is valid
    return jsonify({"ok": True}), 200

# -----------------------------
# API – Submit report
# -----------------------------
@app.route('/api/report', methods=['POST'])
@jwt_required()
def submit_report():
    try:
        user_id = int(get_jwt_identity())

        # Cooldown 10s per user
        last = Report.query.filter_by(user_id=user_id).order_by(Report.date.desc()).first()
        if last and last.date:
            delta = (datetime.utcnow() - last.date).total_seconds()
            if delta < 10:
                wait = int(10 - delta)
                return jsonify({"error": f"Please wait {wait} seconds before submitting another report."}), 429

        # Parse payload
        lat = lng = None
        reporter = barangay = municipality = province = ''
        severity = 'Low'
        photo_url = ''

        if request.content_type and request.content_type.startswith('multipart/form-data'):
            form = request.form
            reporter     = form.get('reporter', '')
            barangay     = form.get('barangay', '')
            municipality = form.get('municipality', '')
            province     = form.get('province', '')
            severity     = form.get('severity', 'Low')
            lat          = float(form.get('lat')) if form.get('lat') else None
            lng          = float(form.get('lng')) if form.get('lng') else None

            if 'photo' in request.files and request.files['photo'].filename:
                f = request.files['photo']
                fname = secure_filename(f"{uuid.uuid4().hex}_{f.filename}")
                f.save(os.path.join(app.config['UPLOAD_FOLDER'], fname))
                photo_url = f"/static/uploads/{fname}"
        else:
            data = request.get_json(force=True)
            reporter     = data.get('reporter', '')
            barangay     = data.get('barangay', '')
            municipality = data.get('municipality', '')
            province     = data.get('province', '')
            severity     = data.get('severity', 'Low')
            lat          = float(data.get('lat')) if data.get('lat') else None
            lng          = float(data.get('lng')) if data.get('lng') else None
            photo_url    = data.get('photo_url', '')

        # Duplicate location within 15s
        if lat and lng:
            recent_same = Report.query.filter_by(user_id=user_id, lat=lat, lng=lng)\
                .order_by(Report.date.desc()).first()
            if recent_same and (datetime.utcnow() - recent_same.date).total_seconds() < 15:
                return jsonify({"error": "Duplicate report detected. Please wait a few seconds before resubmitting."}), 429

        new_report = Report(
            reporter=reporter,
            barangay=barangay,
            municipality=municipality,
            province=province,
            severity=severity,
            lat=lat, lng=lng,
            photo=photo_url,
            status="Pending",
            action_status="Not Resolved",
            user_id=user_id,
            date=datetime.utcnow()
        )
        db.session.add(new_report)
        db.session.commit()

        return jsonify({"message": "Report submitted successfully!", "report_id": new_report.id}), 201

    except Exception as e:
        print("submit_report error:", e)
        return jsonify({"error": "Failed to submit report.", "details": str(e)}), 500

# -----------------------------
# API – Dashboard Data
# -----------------------------
@app.route('/api/reports')
def get_reports():
    """
    Return ALL reports for the dashboard.
    Optional filters via query string:
      - barangay=All|<name>
      - severity=All|Low|Moderate|High|Critical
      - start_date=YYYY-MM-DD
      - end_date=YYYY-MM-DD
    """
    try:
        barangay = request.args.get('barangay')
        severity = request.args.get('severity')
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')

        q = Report.query

        if barangay and barangay != "All":
            q = q.filter(Report.barangay == barangay)
        if severity and severity != "All":
            q = q.filter(Report.severity == severity)
        if start_date and end_date:
            try:
                s = datetime.strptime(start_date, "%Y-%m-%d")
                e = datetime.strptime(end_date, "%Y-%m-%d")
                q = q.filter(Report.date >= s, Report.date <= e)
            except Exception:
                pass

        reports = q.order_by(Report.date.desc()).all()

        data = []
        for r in reports:
            data.append({
                "id": r.id,
                "date": r.date.strftime("%Y-%m-%d %H:%M") if r.date else "",
                "reporter": r.reporter or "Unknown",
                "barangay": r.barangay or "",
                "municipality": r.municipality or "",
                "province": r.province or "",
                "severity": r.severity or "Low",
                "status": r.status or "Pending",
                "action_status": r.action_status or "Not Resolved",
                "photo": r.photo or "",
                "lat": r.lat,
                "lng": r.lng
            })
        return jsonify(data), 200
    except Exception as e:
        print("get_reports error:", e)
        return jsonify({"error": "Failed to fetch reports", "details": str(e)}), 500


@app.route('/api/barangays')
def api_barangays():
    barangays = sorted(set(r.barangay for r in Report.query.all() if r.barangay))
    return jsonify(barangays)

@app.route('/api/severity-distribution')
def api_severity_distribution():
    severities = ["Low", "Moderate", "High", "Critical"]
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
    active_hotspots = Report.query.filter(Report.severity.in_(["High", "Critical"])).count()
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
    r = Report.query.get(report_id)
    if not r:
        return jsonify({"error": "Report not found"}), 404
    new_status = (request.get_json() or {}).get("status")

    # Normalize legacy/typo statuses
    if new_status == "Accepted":
        new_status = "Approved"

    if new_status not in {"Pending", "Approved", "Rejected"}:
        return jsonify({"error": "Invalid status"}), 400

    r.status = new_status
    db.session.commit()
    return jsonify({"message": "Status updated"}), 200

@app.route('/api/report/<int:report_id>/action_status', methods=['PUT'])
def update_report_action_status(report_id):
    r = Report.query.get(report_id)
    if not r:
        return jsonify({"error": "Report not found"}), 404
    new_state = (request.get_json() or {}).get("action_status")
    if new_state not in {"Resolved", "Not Resolved"}:
        return jsonify({"error": "Invalid action_status"}), 400
    r.action_status = new_state
    db.session.commit()
    return jsonify({"message": "Action updated"}), 200

# -----------------------------
# Run
# -----------------------------
if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
