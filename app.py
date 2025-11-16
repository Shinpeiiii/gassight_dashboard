import os
import uuid
from datetime import datetime, timedelta
import io
import csv
import random

import requests
from flask import (
    Flask, render_template, jsonify, send_from_directory,
    request, redirect, url_for, flash, send_file, make_response
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin, login_user, logout_user,
    login_required, current_user
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_jwt_extended import (
    JWTManager, create_access_token, create_refresh_token,
    jwt_required, get_jwt_identity, get_jwt
)
from flask_cors import CORS

# optional Excel support
try:
    from openpyxl import Workbook
except ImportError:  # optional dependency
    Workbook = None

# -------------------------------------------------
# APP INITIALIZATION
# -------------------------------------------------
app = Flask(__name__, static_folder="static", template_folder="templates")

CORS(app, resources={r"/api/*": {"origins": "*"}})

app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-key")
app.config["JWT_SECRET_KEY"] = os.environ.get("JWT_SECRET_KEY", "jwt-secret")

# cookies (for web login)
app.config["SESSION_COOKIE_SECURE"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "None"
app.config["REMEMBER_COOKIE_SECURE"] = True
app.config["REMEMBER_COOKIE_SAMESITE"] = "None"

# token lifetime
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(minutes=30)
app.config["JWT_REFRESH_TOKEN_EXPIRES"] = timedelta(days=30)

jwt = JWTManager(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"

# token blocklist (for logout)
BLOCKLIST = set()


@jwt.token_in_blocklist_loader
def is_token_revoked(jwt_header, jwt_payload):
    return jwt_payload.get("jti") in BLOCKLIST


# -------------------------------------------------
# DATABASE CONFIGURATION
# -------------------------------------------------
db_url = os.environ.get("DATABASE_URL")

if db_url and db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)

if not db_url:
    print("⚠️ WARNING: No DATABASE_URL found. Using SQLite.")
    db_url = "sqlite:///gassight.db"

app.config["SQLALCHEMY_DATABASE_URI"] = db_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

# -------------------------------------------------
# UPLOADS
# -------------------------------------------------
app.config["UPLOAD_FOLDER"] = os.path.join(app.static_folder, "uploads")
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

ADMIN_CODE = os.environ.get("ADMIN_CODE", "GASSIGHT_ADMIN")
FIREBASE_SERVER_KEY = os.environ.get("FIREBASE_SERVER_KEY")  # optional for push

ALLOWED_IMAGE_EXT = {"jpg", "jpeg", "png"}


# -------------------------------------------------
# MODELS
# -------------------------------------------------
class Province(db.Model):
    __tablename__ = "provinces"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), unique=True, nullable=False)


class Municipality(db.Model):
    __tablename__ = "municipalities"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    province_id = db.Column(db.Integer, db.ForeignKey("provinces.id"), nullable=False)

    province = db.relationship("Province")


class Barangay(db.Model):
    __tablename__ = "barangays"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    municipality_id = db.Column(db.Integer, db.ForeignKey("municipalities.id"), nullable=False)

    municipality = db.relationship("Municipality")


class User(db.Model, UserMixin):
    __tablename__ = "user"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)

    # basic info
    full_name = db.Column(db.String(200))
    email = db.Column(db.String(200), unique=True)
    contact = db.Column(db.String(100))
    address = db.Column(db.String(255))

    # role: admin / farmer
    is_admin = db.Column(db.Boolean, default=False)

    # home location for notifications
    province = db.Column(db.String(120))
    municipality = db.Column(db.String(120))
    barangay = db.Column(db.String(120))

    def set_password(self, pw: str):
        self.password_hash = generate_password_hash(pw)

    def check_password(self, pw: str) -> bool:
        return check_password_hash(self.password_hash, pw)


class Report(db.Model):
    __tablename__ = "report"

    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.DateTime, default=datetime.utcnow)

    reporter = db.Column(db.String(120))

    province = db.Column(db.String(120))
    municipality = db.Column(db.String(120))
    barangay = db.Column(db.String(120))

    severity = db.Column(db.String(50))
    status = db.Column(db.String(50), default="Pending")
    action_status = db.Column(db.String(50), default="Not Resolved")

    # infestation type (GAS, RBB, etc.)
    infestation_type = db.Column(db.String(120))

    photo = db.Column(db.String(255))

    # GEO-TAGGING
    lat = db.Column(db.Float)   # latitude
    lng = db.Column(db.Float)   # longitude

    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))


class Notification(db.Model):
    __tablename__ = "notification"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)

    title = db.Column(db.String(200), nullable=False)
    body = db.Column(db.String(500), nullable=False)

    province = db.Column(db.String(120))
    municipality = db.Column(db.String(120))
    barangay = db.Column(db.String(120))

    severity = db.Column(db.String(50))
    infestation_type = db.Column(db.String(120))

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_read = db.Column(db.Boolean, default=False)


class FcmToken(db.Model):
    __tablename__ = "fcm_token"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    token = db.Column(db.String(512), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# Create tables and run simple migrations (lat/lng/infestation_type + user home location)
with app.app_context():
    db.create_all()

    # safe ALTERs – ignore errors if columns already exist
    try:
        db.session.execute("ALTER TABLE report ADD COLUMN lat DOUBLE PRECISION;")
    except Exception:
        pass
    try:
        db.session.execute("ALTER TABLE report ADD COLUMN lng DOUBLE PRECISION;")
    except Exception:
        pass
    try:
        db.session.execute("ALTER TABLE report ADD COLUMN infestation_type TEXT;")
    except Exception:
        pass
    try:
        db.session.execute("ALTER TABLE user ADD COLUMN province VARCHAR(120);")
    except Exception:
        pass
    try:
        db.session.execute("ALTER TABLE user ADD COLUMN municipality VARCHAR(120);")
    except Exception:
        pass
    try:
        db.session.execute("ALTER TABLE user ADD COLUMN barangay VARCHAR(120);")
    except Exception:
        pass

    db.session.commit()


# -------------------------------------------------
# HELPERS
# -------------------------------------------------
def sanitize(text):
    if text is None:
        return None
    return text.strip()


def allowed_image(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_IMAGE_EXT


def require_admin():
    if not current_user.is_authenticated or not current_user.is_admin:
        return redirect(url_for("no_access"))


def send_fcm_notification(user, notif, extra_data=None):
    """Send FCM push if FIREBASE_SERVER_KEY is configured and user has tokens."""
    if not FIREBASE_SERVER_KEY:
        # If you haven't set the key, we silently skip push.
        return

    tokens = [t.token for t in FcmToken.query.filter_by(user_id=user.id).all()]
    if not tokens:
        return

    headers = {
        "Authorization": f"key={FIREBASE_SERVER_KEY}",
        "Content-Type": "application/json",
    }
    payload = {
        "registration_ids": tokens,
        "notification": {
            "title": notif.title,
            "body": notif.body,
        },
        "data": extra_data or {
            "type": "HOTSPOT_ALERT",
            "notification_id": notif.id,
            "severity": notif.severity,
            "infestation_type": notif.infestation_type,
        },
    }

    try:
        requests.post(
            "https://fcm.googleapis.com/fcm/send",
            headers=headers,
            json=payload,
            timeout=5,
        )
    except Exception as e:
        print("⚠️ FCM send error:", e)


def create_location_notifications(report: Report):
    """Create notifications for farmers near the report location."""
    if not report.severity:
        return

    # Only notify for High / Critical
    sev = report.severity.lower()
    if sev not in ("high", "critical"):
        return

    # Target: same barangay first, then same municipality, then same province.
    q = User.query.filter(User.is_admin.is_(False))

    if report.barangay:
        q = q.filter(User.barangay == report.barangay)
    elif report.municipality:
        q = q.filter(User.municipality == report.municipality)
    elif report.province:
        q = q.filter(User.province == report.province)
    else:
        # no location info -> don't spam everyone
        return

    farmers = q.all()
    if not farmers:
        return

    title = f"High {report.infestation_type or 'infestation'} in {report.barangay or report.municipality or report.province}"
    body = f"A {report.severity} level report was submitted in {report.barangay or report.municipality or report.province}."

    for farmer in farmers:
        notif = Notification(
            user_id=farmer.id,
            title=title,
            body=body,
            province=report.province,
            municipality=report.municipality,
            barangay=report.barangay,
            severity=report.severity,
            infestation_type=report.infestation_type,
        )
        db.session.add(notif)
        db.session.flush()  # to get notif.id for data payload
        send_fcm_notification(
            farmer,
            notif,
            extra_data={
                "type": "HOTSPOT_ALERT",
                "notification_id": notif.id,
                "report_id": report.id,
                "severity": report.severity,
                "infestation_type": report.infestation_type,
                "province": report.province,
                "municipality": report.municipality,
                "barangay": report.barangay,
            },
        )

    db.session.commit()


def apply_report_filters(q, args):
    """Reuse filters for JSON, CSV, Excel, and print views."""
    province_name = args.get("province")
    municipality_name = args.get("municipality")
    barangay_name = args.get("barangay")
    severity = args.get("severity")
    infestation_type = args.get("infestation_type")
    start_date = args.get("start_date")
    end_date = args.get("end_date")

    if province_name and province_name != "All":
        q = q.filter(Report.province == province_name)

    if municipality_name and municipality_name != "All":
        q = q.filter(Report.municipality == municipality_name)

    if barangay_name and barangay_name != "All":
        q = q.filter(Report.barangay == barangay_name)

    if severity and severity != "All":
        q = q.filter(Report.severity == severity)

    if infestation_type and infestation_type != "All":
        q = q.filter(Report.infestation_type == infestation_type)

    if start_date and end_date:
        try:
            s = datetime.strptime(start_date, "%Y-%m-%d")
            e = datetime.strptime(end_date, "%Y-%m-%d")
            q = q.filter(Report.date >= s, Report.date <= e)
        except ValueError:
            pass

    return q


# -------------------------------------------------
# STATIC (PWA)
# -------------------------------------------------
@app.route("/service-worker.js")
def service_worker():
    return send_from_directory("static", "service-worker.js")


# -------------------------------------------------
# PAGE ROUTES (ADMIN WEB)
# -------------------------------------------------
@app.route("/")
def home():
    if not current_user.is_authenticated:
        return redirect(url_for("login"))
    return redirect(url_for("dashboard" if current_user.is_admin else "no_access"))


@app.route("/dashboard")
@login_required
def dashboard():
    if not current_user.is_admin:
        return redirect(url_for("no_access"))
    return render_template("dashboard.html")


@app.route("/no-access")
@login_required
def no_access():
    return render_template("no_access.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard" if current_user.is_admin else "no_access"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password")

        user = User.query.filter_by(username=username).first()
        if not user or not user.check_password(password):
            flash("Invalid username or password.", "danger")
            return render_template("login.html")

        login_user(user)
        return redirect(url_for("dashboard" if user.is_admin else "no_access"))

    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password")
        full_name = request.form.get("full_name")
        email = request.form.get("email")
        contact = request.form.get("contact_number")
        address = request.form.get("address")
        admin_code = request.form.get("admin_code", "").strip()

        if User.query.filter_by(username=username).first():
            flash("Username already exists.", "warning")
            return render_template("register.html")

        if email and User.query.filter_by(email=email).first():
            flash("Email already exists.", "warning")
            return render_template("register.html")

        user = User(
            username=username,
            full_name=full_name,
            email=email,
            contact=contact,
            address=address,
            is_admin=(admin_code == ADMIN_CODE),
        )
        user.set_password(password)

        db.session.add(user)
        db.session.commit()

        login_user(user)
        return redirect(url_for("dashboard" if user.is_admin else "no_access"))

    return render_template("register.html")


@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for("login"))


# -------------------------------------------------
# API — LOCATION (FOR DROPDOWNS)
# -------------------------------------------------
@app.route("/api/provinces")
def api_provinces():
    data = Province.query.order_by(Province.name.asc()).all()
    return jsonify([p.name for p in data])


@app.route("/api/municipalities")
def api_municipalities():
    province_name = request.args.get("province")
    q = Municipality.query
    if province_name:
        q = q.join(Province).filter(Province.name == province_name)
    data = q.order_by(Municipality.name.asc()).all()
    return jsonify([m.name for m in data])


@app.route("/api/barangays")
def api_barangays():
    municipality_name = request.args.get("municipality")
    q = Barangay.query
    if municipality_name:
        q = q.join(Municipality).filter(Municipality.name == municipality_name)
    data = q.order_by(Barangay.name.asc()).all()
    return jsonify([b.name for b in data])


# -------------------------------------------------
# MOBILE API — SIGNUP / LOGIN / TOKEN CHECK
# -------------------------------------------------
@app.route("/api/signup", methods=["POST"])
def api_signup():
    """
    Body JSON:
      {
        username, password,
        fullName?, email?, contact?, address?,
        province?, municipality?, barangay?
      }
    Returns tokens on success.
    """
    data = request.get_json() or {}

    username = sanitize(data.get("username", ""))
    password = data.get("password", "")

    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400

    if User.query.filter_by(username=username).first():
        return jsonify({"error": "Username exists"}), 409

    full_name = sanitize(data.get("fullName"))
    email = sanitize(data.get("email"))
    contact = sanitize(data.get("contact"))
    address = sanitize(data.get("address"))
    province = sanitize(data.get("province"))
    municipality = sanitize(data.get("municipality"))
    barangay = sanitize(data.get("barangay"))

    if email and User.query.filter_by(email=email).first():
        return jsonify({"error": "Email exists"}), 409

    user = User(
        username=username,
        full_name=full_name,
        email=email,
        contact=contact,
        address=address,
        is_admin=False,
        province=province,
        municipality=municipality,
        barangay=barangay,
    )
    user.set_password(password)

    db.session.add(user)
    db.session.commit()

    access_token = create_access_token(identity=str(user.id))
    refresh_token = create_refresh_token(identity=str(user.id))

    return jsonify({
        "message": "Signup success",
        "token": access_token,
        "access_token": access_token,
        "refresh_token": refresh_token,
        "username": username,
    }), 200


@app.route("/api/login", methods=["POST"])
def api_login():
    """
    Body JSON: {username, password}
    Returns: {message, token, access_token, refresh_token}
    """
    data = request.get_json() or {}
    username = sanitize(data.get("username", ""))
    password = data.get("password", "")

    user = User.query.filter_by(username=username).first()

    if not user or not user.check_password(password):
        return jsonify({"error": "Invalid credentials"}), 401

    access_token = create_access_token(identity=str(user.id))
    refresh_token = create_refresh_token(identity=str(user.id))

    return jsonify({
        "message": "Login success",
        "token": access_token,
        "access_token": access_token,
        "refresh_token": refresh_token,
        "username": user.username,
    }), 200


@app.route("/api/refresh", methods=["POST"])
@jwt_required(refresh=True)
def api_refresh():
    user_id = get_jwt_identity()
    access_token = create_access_token(identity=str(user_id))
    return jsonify({
        "message": "Token refreshed",
        "token": access_token,
        "access_token": access_token,
    }), 200


@app.route("/api/check_token", methods=["GET"])
@jwt_required()
def api_check_token():
    user_id = get_jwt_identity()
    return jsonify({"valid": True, "user_id": int(user_id)}), 200


@app.route("/api/logout", methods=["POST"])
@jwt_required()
def api_logout():
    jti = get_jwt()["jti"]
    BLOCKLIST.add(jti)
    return jsonify({"message": "Logged out"}), 200


# -------------------------------------------------
# MOBILE API — SAVE FCM TOKEN
# -------------------------------------------------
@app.route("/api/fcm-token", methods=["POST"])
@jwt_required()
def api_fcm_token():
    """
    Body JSON: { "token": "<device_fcm_token>" }
    """
    user_id = int(get_jwt_identity())
    data = request.get_json() or {}
    token = (data.get("token") or "").strip()
    if not token:
        return jsonify({"error": "Missing token"}), 400

    existing = FcmToken.query.filter_by(user_id=user_id, token=token).first()
    if existing:
        existing.last_seen = datetime.utcnow()
    else:
        db.session.add(FcmToken(user_id=user_id, token=token))

    db.session.commit()
    return jsonify({"message": "FCM token saved"}), 200


# -------------------------------------------------
# MOBILE API — SUBMIT REPORT (GEO-TAGGED + INFESTATION TYPE)
# -------------------------------------------------
@app.route("/api/report", methods=["POST"])
@jwt_required()
def submit_report():
    """
    Accepts:
    - multipart/form-data (with optional photo) from mobile app
    - application/json (offline sync)
    Fields:
      reporter, province, municipality, barangay, severity,
      infestation_type, lat, lng, photo
    """
    user_id = int(get_jwt_identity())

    if request.content_type and request.content_type.startswith("multipart/form-data"):
        form = request.form

        reporter = sanitize(form.get("reporter"))
        province = sanitize(form.get("province"))
        municipality = sanitize(form.get("municipality"))
        barangay = sanitize(form.get("barangay"))
        severity = sanitize(form.get("severity")) or "Low"
        infestation_type = sanitize(form.get("infestation_type")) or "Other"

        try:
            lat = float(form.get("lat")) if form.get("lat") else None
            lng = float(form.get("lng")) if form.get("lng") else None
        except (TypeError, ValueError):
            lat = None
            lng = None

        photo = ""
        if "photo" in request.files:
            f = request.files["photo"]
            if f and f.filename and allowed_image(f.filename):
                fname = secure_filename(f"{uuid.uuid4().hex}_{f.filename}")
                f.save(os.path.join(app.config["UPLOAD_FOLDER"], fname))
                photo = f"/static/uploads/{fname}"

    else:
        data = request.get_json() or {}

        reporter = sanitize(data.get("reporter"))
        province = sanitize(data.get("province"))
        municipality = sanitize(data.get("municipality"))
        barangay = sanitize(data.get("barangay"))
        severity = sanitize(data.get("severity")) or "Low"
        infestation_type = sanitize(data.get("infestation_type")) or "Other"

        lat = data.get("lat")
        lng = data.get("lng")
        try:
            lat = float(lat) if lat is not None else None
            lng = float(lng) if lng is not None else None
        except (TypeError, ValueError):
            lat = None
            lng = None

        photo = sanitize(data.get("photo_url")) or ""

    report = Report(
        reporter=reporter,
        province=province,
        municipality=municipality,
        barangay=barangay,
        severity=severity,
        infestation_type=infestation_type,
        lat=lat,
        lng=lng,
        photo=photo,
        user_id=user_id,
    )

    db.session.add(report)
    db.session.commit()

    # create notifications for nearby farmers (High / Critical only)
    create_location_notifications(report)

    return jsonify({
        "message": "Report submitted successfully",
        "id": report.id,
        "severity": report.severity,
        "infestation_type": report.infestation_type,
    }), 201


# -------------------------------------------------
# MOBILE API — NOTIFICATIONS INBOX
# -------------------------------------------------
@app.route("/api/notifications", methods=["GET"])
@jwt_required()
def api_notifications():
    user_id = int(get_jwt_identity())

    notifs = Notification.query.filter_by(user_id=user_id).order_by(
        Notification.created_at.desc()
    ).all()

    return jsonify([
        {
            "id": n.id,
            "title": n.title,
            "body": n.body,
            "province": n.province,
            "municipality": n.municipality,
            "barangay": n.barangay,
            "severity": n.severity,
            "infestation_type": n.infestation_type,
            "created_at": n.created_at.isoformat(),
            "is_read": n.is_read,
        }
        for n in notifs
    ])


@app.route("/api/notifications/read", methods=["POST"])
@jwt_required()
def api_notifications_read():
    """
    Body JSON: { "ids": [1,2,3] }  # optional; if omitted -> mark all as read
    """
    user_id = int(get_jwt_identity())
    data = request.get_json() or {}
    ids = data.get("ids")

    q = Notification.query.filter_by(user_id=user_id)
    if ids:
        q = q.filter(Notification.id.in_(ids))

    for n in q.all():
        n.is_read = True

    db.session.commit()
    return jsonify({"message": "Notifications marked as read"}), 200


# -------------------------------------------------
# DASHBOARD API — FILTERED REPORTS (JSON)
# -------------------------------------------------
@app.route("/api/reports")
def get_reports():
    q = apply_report_filters(Report.query, request.args)
    reports = q.order_by(Report.date.desc()).all()

    return jsonify([
        {
            "id": r.id,
            "date": r.date.strftime("%Y-%m-%d %H:%M"),
            "reporter": r.reporter,
            "province": r.province,
            "municipality": r.municipality,
            "barangay": r.barangay,
            "severity": r.severity,
            "infestation_type": r.infestation_type,
            "status": r.status,
            "action_status": r.action_status,
            "photo": r.photo,
            "lat": r.lat,
            "lng": r.lng,
        }
        for r in reports
    ])


# -------------------------------------------------
# DASHBOARD EXPORT — CSV (no extra dependency)
# -------------------------------------------------
@app.route("/api/reports/export/csv")
@login_required
def export_reports_csv():
    if not current_user.is_admin:
        return redirect(url_for("no_access"))

    q = apply_report_filters(Report.query, request.args)
    reports = q.order_by(Report.date.desc()).all()

    output = io.StringIO()
    writer = csv.writer(output)

    header = [
        "ID", "Date", "Reporter",
        "Province", "Municipality", "Barangay",
        "Severity", "Infestation Type",
        "Status", "Action Status",
        "Latitude", "Longitude", "Photo URL"
    ]
    writer.writerow(header)

    for r in reports:
        writer.writerow([
            r.id,
            r.date.strftime("%Y-%m-%d %H:%M") if r.date else "",
            r.reporter or "",
            r.province or "",
            r.municipality or "",
            r.barangay or "",
            r.severity or "",
            r.infestation_type or "",
            r.status or "",
            r.action_status or "",
            r.lat or "",
            r.lng or "",
            r.photo or "",
        ])

    resp = make_response(output.getvalue())
    resp.headers["Content-Type"] = "text/csv"
    resp.headers["Content-Disposition"] = "attachment; filename=reports.csv"
    return resp


# -------------------------------------------------
# DASHBOARD EXPORT — EXCEL (openpyxl, optional)
# -------------------------------------------------
@app.route("/api/reports/export/excel")
@login_required
def export_reports_excel():
    if not current_user.is_admin:
        return redirect(url_for("no_access"))

    if Workbook is None:
        return jsonify({
            "error": "Excel export not available. Install openpyxl on the server."
        }), 500

    q = apply_report_filters(Report.query, request.args)
    reports = q.order_by(Report.date.desc()).all()

    wb = Workbook()
    ws = wb.active
    ws.title = "Reports"

    header = [
        "ID", "Date", "Reporter",
        "Province", "Municipality", "Barangay",
        "Severity", "Infestation Type",
        "Status", "Action Status",
        "Latitude", "Longitude", "Photo URL"
    ]
    ws.append(header)

    for r in reports:
        ws.append([
            r.id,
            r.date.strftime("%Y-%m-%d %H:%M") if r.date else "",
            r.reporter or "",
            r.province or "",
            r.municipality or "",
            r.barangay or "",
            r.severity or "",
            r.infestation_type or "",
            r.status or "",
            r.action_status or "",
            r.lat or "",
            r.lng or "",
            r.photo or "",
        ])

    file_io = io.BytesIO()
    wb.save(file_io)
    file_io.seek(0)

    return send_file(
        file_io,
        as_attachment=True,
        download_name="reports.xlsx",
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    )


# -------------------------------------------------
# DASHBOARD PRINT VIEW — HTML (for “PDF” via browser print)
# -------------------------------------------------
@app.route("/reports/print")
@login_required
def print_reports_view():
    if not current_user.is_admin:
        return redirect(url_for("no_access"))

    q = apply_report_filters(Report.query, request.args)
    reports = q.order_by(Report.date.desc()).all()

    return render_template("reports_print.html", reports=reports)


# -------------------------------------------------
# ADMIN — POPULATE SAMPLE REPORTS FOR TESTING
# -------------------------------------------------
@app.route("/admin/reports/populate", methods=["POST"])
@login_required
def populate_reports():
    if not current_user.is_admin:
        return redirect(url_for("no_access"))

    severities = ["Low", "Moderate", "High", "Critical"]
    infestations = [
        "Golden Apple Snail (GAS)",
        "Rice Black Bug (RBB)",
        "Brown Plant Hopper (BPH)",
        "Others",
    ]

    sample_provinces = ["Pangasinan", "Nueva Ecija", "Isabela"]
    sample_muns = ["Binalonan", "Urdaneta", "Sta. Maria", "Aliaga"]
    sample_brgy = ["Brgy 1", "Brgy 2", "Brgy 3", "Brgy 4"]

    for _ in range(30):
        prov = random.choice(sample_provinces)
        mun = random.choice(sample_muns)
        brgy = random.choice(sample_brgy)
        sev = random.choice(severities)
        infest = random.choice(infestations)

        r = Report(
            date=datetime.utcnow() - timedelta(days=random.randint(0, 14)),
            reporter=f"Farmer {random.randint(1, 20)}",
            province=prov,
            municipality=mun,
            barangay=brgy,
            severity=sev,
            status="Pending" if sev in ("High", "Critical") else "In Progress",
            action_status="Not Resolved",
            infestation_type=infest,
            lat=16.0 + random.random(),
            lng=120.0 + random.random(),
            photo="",
            user_id=current_user.id,
        )
        db.session.add(r)

    db.session.commit()
    return jsonify({"message": "Sample reports populated"}), 201


# -------------------------------------------------
# RUN
# -------------------------------------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
