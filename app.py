import os
import uuid
import io
import csv
import json
import random
from datetime import datetime, timedelta

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
from sqlalchemy import text, inspect  # for simple migrations

# optional Excel support
try:
    from openpyxl import Workbook
except ImportError:  # optional dependency
    Workbook = None

# =================================================
# DEMO REPORTS DATA (from demo_reports.json)
# =================================================

DEMO_REPORTS = [
    {
        "reporter": "DemoUser1",
        "province": "Ilocos Sur",
        "municipality": "Vigan City",
        "barangay": "Pantay Daya",
        "severity": "Moderate",
        "infestation_type": "Golden Apple Snail (GAS)",
        "lat": 17.5741,
        "lng": 120.3869,
        "description": "Snail activity observed near irrigation canal.",
        "gps_metadata": {
            "lat": 17.5741,
            "lng": 120.3869,
            "timestamp": "2025-01-10T08:45:00Z"
        }
    },
    {
        "reporter": "DemoUser2",
        "province": "Ilocos Sur",
        "municipality": "Caoayan",
        "barangay": "Don Alejandro Quirol",
        "severity": "High",
        "infestation_type": "Rice Black Bug (RBB)",
        "lat": 17.5643,
        "lng": 120.3794,
        "description": "Heavy RBB presence in rice paddies.",
        "gps_metadata": {
            "lat": 17.5643,
            "lng": 120.3794,
            "timestamp": "2025-01-09T14:22:00Z"
        }
    },
    {
        "reporter": "DemoUser3",
        "province": "Ilocos Sur",
        "municipality": "Bantay",
        "barangay": "Cabaroan",
        "severity": "Low",
        "infestation_type": "Golden Apple Snail (GAS)",
        "lat": 17.5857,
        "lng": 120.3881,
        "description": "Few snails detected in drainage area.",
        "gps_metadata": {
            "lat": 17.5857,
            "lng": 120.3881,
            "timestamp": "2025-01-12T10:00:00Z"
        }
    },
    {
        "reporter": "DemoUser4",
        "province": "Ilocos Sur",
        "municipality": "San Vicente",
        "barangay": "Poblacion",
        "severity": "Critical",
        "infestation_type": "Brown Plant Hopper (BPH)",
        "lat": 17.5803,
        "lng": 120.3982,
        "description": "Severe BPH infestation damaging multiple fields.",
        "gps_metadata": {
            "lat": 17.5803,
            "lng": 120.3982,
            "timestamp": "2025-01-08T16:30:00Z"
        }
    },
    {
        "reporter": "DemoUser5",
        "province": "Ilocos Sur",
        "municipality": "Santa Catalina",
        "barangay": "Paratong",
        "severity": "Moderate",
        "infestation_type": "Others",
        "lat": 17.5749,
        "lng": 120.4054,
        "description": "Unidentified pest damaging rice seedlings.",
        "gps_metadata": {
            "lat": 17.5749,
            "lng": 120.4054,
            "timestamp": "2025-01-15T07:55:00Z"
        }
    },
    {
        "reporter": "DemoUser6",
        "province": "Ilocos Sur",
        "municipality": "Santa",
        "barangay": "Quinarayan",
        "severity": "High",
        "infestation_type": "Rice Black Bug (RBB)",
        "lat": 17.5412,
        "lng": 120.3921,
        "description": "Widespread infestation affecting vegetation.",
        "gps_metadata": {
            "lat": 17.5412,
            "lng": 120.3921,
            "timestamp": "2025-01-11T11:40:00Z"
        }
    },
    {
        "reporter": "DemoUser7",
        "province": "Ilocos Sur",
        "municipality": "Santa Maria",
        "barangay": "Poblacion Norte",
        "severity": "Low",
        "infestation_type": "Golden Apple Snail (GAS)",
        "lat": 17.3701,
        "lng": 120.4641,
        "description": "Minor GAS presence found.",
        "gps_metadata": {
            "lat": 17.3701,
            "lng": 120.4641,
            "timestamp": "2025-01-13T09:10:00Z"
        }
    },
    {
        "reporter": "DemoUser8",
        "province": "Ilocos Sur",
        "municipality": "Narvacan",
        "barangay": "Quinarayan",
        "severity": "Moderate",
        "infestation_type": "Brown Plant Hopper (BPH)",
        "lat": 17.4178,
        "lng": 120.4742,
        "description": "BPH density increasing.",
        "gps_metadata": {
            "lat": 17.4178,
            "lng": 120.4742,
            "timestamp": "2025-01-14T13:25:00Z"
        }
    },
    {
        "reporter": "DemoUser9",
        "province": "Ilocos Sur",
        "municipality": "Santa Cruz",
        "barangay": "Poblacion Sur",
        "severity": "Critical",
        "infestation_type": "Rice Black Bug (RBB)",
        "lat": 17.0581,
        "lng": 120.4783,
        "description": "RBB infestation affecting 4 hectares.",
        "gps_metadata": {
            "lat": 17.0581,
            "lng": 120.4783,
            "timestamp": "2025-01-06T15:45:00Z"
        }
    },
    {
        "reporter": "DemoUser10",
        "province": "Ilocos Sur",
        "municipality": "Tagudin",
        "barangay": "Farola",
        "severity": "High",
        "infestation_type": "Golden Apple Snail (GAS)",
        "lat": 16.9341,
        "lng": 120.4411,
        "description": "Large clusters of snails spotted.",
        "gps_metadata": {
            "lat": 16.9341,
            "lng": 120.4411,
            "timestamp": "2025-01-04T08:30:00Z"
        }
    },
    {
        "reporter": "DemoUser11",
        "province": "Ilocos Sur",
        "municipality": "Candon City",
        "barangay": "Bagani Gabor",
        "severity": "Moderate",
        "infestation_type": "Brown Plant Hopper (BPH)",
        "lat": 17.1964,
        "lng": 120.4521,
        "description": "BPH causing leaf discoloration.",
        "gps_metadata": {
            "lat": 17.1964,
            "lng": 120.4521,
            "timestamp": "2025-01-05T11:10:00Z"
        }
    },
    {
        "reporter": "DemoUser12",
        "province": "Ilocos Sur",
        "municipality": "Santa",
        "barangay": "Purok Centro",
        "severity": "Low",
        "infestation_type": "Golden Apple Snail (GAS)",
        "lat": 17.5220,
        "lng": 120.3890,
        "description": "Low snail activity.",
        "gps_metadata": {
            "lat": 17.5220,
            "lng": 120.3890,
            "timestamp": "2025-01-03T09:20:00Z"
        }
    },
    {
        "reporter": "DemoUser13",
        "province": "Ilocos Sur",
        "municipality": "Nagbukel",
        "barangay": "Casilagan",
        "severity": "High",
        "infestation_type": "Rice Black Bug (RBB)",
        "lat": 17.2242,
        "lng": 120.4877,
        "description": "RBB clusters detected in 3 locations.",
        "gps_metadata": {
            "lat": 17.2242,
            "lng": 120.4877,
            "timestamp": "2025-01-02T17:15:00Z"
        }
    },
    {
        "reporter": "DemoUser14",
        "province": "Ilocos Sur",
        "municipality": "San Ildefonso",
        "barangay": "Poblacion East",
        "severity": "Moderate",
        "infestation_type": "Golden Apple Snail (GAS)",
        "lat": 17.6381,
        "lng": 120.4072,
        "description": "Snails damaging early seedlings.",
        "gps_metadata": {
            "lat": 17.6381,
            "lng": 120.4072,
            "timestamp": "2025-01-18T06:45:00Z"
        }
    },
    {
        "reporter": "DemoUser15",
        "province": "Ilocos Sur",
        "municipality": "San Esteban",
        "barangay": "Poblacion",
        "severity": "Low",
        "infestation_type": "Others",
        "lat": 17.3332,
        "lng": 120.4503,
        "description": "Possible early-stage pest but unconfirmed.",
        "gps_metadata": {
            "lat": 17.3332,
            "lng": 120.4503,
            "timestamp": "2025-01-17T08:10:00Z"
        }
    }
]

# =================================================
# APP INITIALIZATION
# =================================================

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


# =================================================
# DATABASE CONFIGURATION
# =================================================

db_url = os.environ.get("DATABASE_URL")

if db_url and db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)

if not db_url:
    print("⚠️ WARNING: No DATABASE_URL found. Using SQLite.")
    db_url = "sqlite:///gassight.db"

app.config["SQLALCHEMY_DATABASE_URI"] = db_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

# =================================================
# UPLOADS
# =================================================

app.config["UPLOAD_FOLDER"] = os.path.join(app.static_folder, "uploads")
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

ADMIN_CODE = os.environ.get("ADMIN_CODE", "GASSIGHT_ADMIN")
FIREBASE_SERVER_KEY = os.environ.get("FIREBASE_SERVER_KEY")  # optional for push

ALLOWED_IMAGE_EXT = {"jpg", "jpeg", "png"}


# =================================================
# MODELS
# =================================================

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
    __tablename__ = "user"  # reserved word, will be quoted in Postgres

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

    infestation_type = db.Column(db.String(120))

    photo = db.Column(db.String(255))

    lat = db.Column(db.Float)
    lng = db.Column(db.Float)

    # NEW: extra fields to match your JSON
    description = db.Column(db.Text)
    gps_metadata = db.Column(db.Text)  # stored as JSON string

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


# =================================================
# SIMPLE AUTO-MIGRATIONS
# =================================================

def run_simple_migrations():
    """
    Adds missing columns (lat, lng, infestation_type, description, gps_metadata,
    province, municipality, barangay) if they are not present yet.
    Works for Postgres and SQLite.
    """
    engine = db.engine
    inspector = inspect(engine)
    dialect = engine.dialect.name

    def has_column(table_name: str, col_name: str) -> bool:
        try:
            cols = [c["name"] for c in inspector.get_columns(table_name)]
            return col_name in cols
        except Exception as e:
            print(f"⚠️ INSPECT ERROR for {table_name}.{col_name}: {e}")
            return False

    # report table
    try:
        if not has_column("report", "lat"):
            db.session.execute(text("ALTER TABLE report ADD COLUMN lat DOUBLE PRECISION"))
            print("✅ MIGRATION: added report.lat")

        if not has_column("report", "lng"):
            db.session.execute(text("ALTER TABLE report ADD COLUMN lng DOUBLE PRECISION"))
            print("✅ MIGRATION: added report.lng")

        if not has_column("report", "infestation_type"):
            db.session.execute(text("ALTER TABLE report ADD COLUMN infestation_type TEXT"))
            print("✅ MIGRATION: added report.infestation_type")

        if not has_column("report", "description"):
            db.session.execute(text("ALTER TABLE report ADD COLUMN description TEXT"))
            print("✅ MIGRATION: added report.description")

        if not has_column("report", "gps_metadata"):
            db.session.execute(text("ALTER TABLE report ADD COLUMN gps_metadata TEXT"))
            print("✅ MIGRATION: added report.gps_metadata")

    except Exception as e:
        print("⚠️ MIGRATION ERROR for report table:", e)

    # user table
    user_table_sql = '"user"' if dialect == "postgresql" else "user"

    try:
        if not has_column("user", "province"):
            db.session.execute(
                text(f"ALTER TABLE {user_table_sql} ADD COLUMN province VARCHAR(120)")
            )
            print("✅ MIGRATION: added user.province")

        if not has_column("user", "municipality"):
            db.session.execute(
                text(f"ALTER TABLE {user_table_sql} ADD COLUMN municipality VARCHAR(120)")
            )
            print("✅ MIGRATION: added user.municipality")

        if not has_column("user", "barangay"):
            db.session.execute(
                text(f"ALTER TABLE {user_table_sql} ADD COLUMN barangay VARCHAR(120)")
            )
            print("✅ MIGRATION: added user.barangay")
    except Exception as e:
        print("⚠️ MIGRATION ERROR for user table:", e)

    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        print("⚠️ MIGRATION COMMIT ERROR:", e)


with app.app_context():
    db.create_all()
    run_simple_migrations()


# =================================================
# HELPERS
# =================================================

def sanitize(text_val):
    if text_val is None:
        return None
    return text_val.strip()


def allowed_image(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_IMAGE_EXT


def require_admin():
    if not current_user.is_authenticated or not current_user.is_admin:
        return redirect(url_for("no_access"))


def send_fcm_notification(user, notif, extra_data=None):
    """Send FCM push if FIREBASE_SERVER_KEY is configured and user has tokens."""
    if not FIREBASE_SERVER_KEY:
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

    sev = report.severity.lower()
    if sev not in ("high", "critical"):
        return

    q = User.query.filter(User.is_admin.is_(False))

    if report.barangay:
        q = q.filter(User.barangay == report.barangay)
    elif report.municipality:
        q = q.filter(User.municipality == report.municipality)
    elif report.province:
        q = q.filter(User.province == report.province)
    else:
        return

    farmers = q.all()
    if not farmers:
        return

    loc = report.barangay or report.municipality or report.province
    title = f"High {report.infestation_type or 'infestation'} in {loc}"
    body = f"A {report.severity} level report was submitted in {loc}."

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
        db.session.flush()
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


# =================================================
# STATIC (PWA)
# =================================================

@app.route("/service-worker.js")
def service_worker():
    return send_from_directory("static", "service-worker.js")


# =================================================
# PAGE ROUTES (ADMIN WEB)
# =================================================

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


# =================================================
# API — LOCATION (FOR DROPDOWNS)
# =================================================

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


# =================================================
# MOBILE API — SIGNUP / LOGIN / TOKEN CHECK
# =================================================

@app.route("/api/signup", methods=["POST"])
def api_signup():
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


# =================================================
# MOBILE API — SAVE FCM TOKEN
# Path matches AuthService: /api/fcm_token
# =================================================

@app.route("/api/fcm_token", methods=["POST"])
@jwt_required()
def api_fcm_token():
    user_id = int(get_jwt_identity())
    data = request.get_json() or {}
    token = (data.get("fcm_token") or "").strip()
    if not token:
        return jsonify({"error": "Missing token"}), 400

    existing = FcmToken.query.filter_by(user_id=user_id, token=token).first()
    if existing:
        existing.last_seen = datetime.utcnow()
    else:
        db.session.add(FcmToken(user_id=user_id, token=token))

    db.session.commit()
    return jsonify({"message": "FCM token saved"}), 200


# =================================================
# MOBILE API — SUBMIT REPORT
# =================================================

@app.route("/api/report", methods=["POST"])
@jwt_required()
def submit_report():
    user_id = int(get_jwt_identity())

    if request.content_type and request.content_type.startswith("multipart/form-data"):
        form = request.form

        reporter = sanitize(form.get("reporter"))
        province = sanitize(form.get("province"))
        municipality = sanitize(form.get("municipality"))
        barangay = sanitize(form.get("barangay"))
        severity = sanitize(form.get("severity")) or "Low"
        infestation_type = sanitize(form.get("infestation_type")) or "Other"
        description = sanitize(form.get("description"))

        gps_metadata_raw = form.get("gps_metadata")
        gps_metadata = gps_metadata_raw if gps_metadata_raw else None

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
        description = sanitize(data.get("description"))

        gps_md = data.get("gps_metadata")
        gps_metadata = json.dumps(gps_md) if gps_md is not None else None

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
        description=description,
        gps_metadata=gps_metadata,
        user_id=user_id,
    )

    db.session.add(report)
    db.session.commit()

    create_location_notifications(report)

    return jsonify({
        "message": "Report submitted successfully",
        "id": report.id,
        "severity": report.severity,
        "infestation_type": report.infestation_type,
    }), 201


# =================================================
# MOBILE API — NOTIFICATIONS INBOX
# =================================================

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


# =================================================
# DASHBOARD API — FILTERED REPORTS (JSON)
# =================================================

@app.route("/api/reports")
def get_reports():
    q = apply_report_filters(Report.query, request.args)
    reports = q.order_by(Report.date.desc()).all()

    return jsonify([
        {
            "id": r.id,
            "date": r.date.strftime("%Y-%m-%d %H:%M") if r.date else "",
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
            "description": r.description,
        }
        for r in reports
    ])


# =================================================
# DASHBOARD EXPORT — CSV
# =================================================

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
        "Latitude", "Longitude", "Photo URL",
        "Description"
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
            r.description or "",
        ])

    resp = make_response(output.getvalue())
    resp.headers["Content-Type"] = "text/csv"
    resp.headers["Content-Disposition"] = "attachment; filename=reports.csv"
    return resp


# =================================================
# DASHBOARD EXPORT — EXCEL
# =================================================

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
        "Latitude", "Longitude", "Photo URL",
        "Description"
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
            r.description or "",
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


# =================================================
# DASHBOARD PRINT VIEW — HTML
# =================================================

@app.route("/reports/print")
@login_required
def print_reports_view():
    if not current_user.is_admin:
        return redirect(url_for("no_access"))

    q = apply_report_filters(Report.query, request.args)
    reports = q.order_by(Report.date.desc()).all()

    return render_template("reports_print.html", reports=reports)


# =================================================
# ADMIN — RANDOM SAMPLE REPORTS (optional)
# =================================================

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



# =================================================
# ADMIN — SEED DEMO REPORTS FROM DEMO_REPORTS CONSTANT
# =================================================

@app.route("/admin/seed-demo", methods=["GET"])
@login_required
def seed_demo():
    """
    Seed the Ilocos Sur demo reports + location tables.

    Usage (once):
      1. Log in as admin in the web dashboard.
      2. Visit /admin/seed-demo in your browser:
         https://gassight.onrender.com/admin/seed-demo
    """
    if not current_user.is_admin:
        return redirect(url_for("no_access"))

    # avoid double-inserting
    existing = Report.query.filter(Report.reporter.like("DemoUser%")).count()
    if existing > 0:
        return jsonify({
            "message": "Demo reports already exist",
            "existing_demo_reports": existing
        })

    # prepare caches
    prov_cache = {}
    mun_cache = {}

    for entry in DEMO_REPORTS:
        prov_name = entry["province"]
        mun_name = entry["municipality"]
        brgy_name = entry["barangay"]

        # Province
        if prov_name in prov_cache:
            prov = prov_cache[prov_name]
        else:
            prov = Province.query.filter_by(name=prov_name).first()
            if not prov:
                prov = Province(name=prov_name)
                db.session.add(prov)
                db.session.flush()
            prov_cache[prov_name] = prov

        # Municipality
        mun_key = (mun_name, prov.id)
        if mun_key in mun_cache:
            mun = mun_cache[mun_key]
        else:
            mun = Municipality.query.filter_by(name=mun_name, province_id=prov.id).first()
            if not mun:
                mun = Municipality(name=mun_name, province_id=prov.id)
                db.session.add(mun)
                db.session.flush()
            mun_cache[mun_key] = mun

        # Barangay
        brgy = Barangay.query.filter_by(name=brgy_name, municipality_id=mun.id).first()
        if not brgy:
            brgy = Barangay(name=brgy_name, municipality_id=mun.id)
            db.session.add(brgy)
            db.session.flush()

        # Parse date from gps_metadata timestamp if present
        ts = entry.get("gps_metadata", {}).get("timestamp")
        if ts:
            try:
                # handle trailing Z
                ts_clean = ts.replace("Z", "+00:00")
                report_date = datetime.fromisoformat(ts_clean)
            except Exception:
                report_date = datetime.utcnow()
        else:
            report_date = datetime.utcnow()

        gps_md = json.dumps(entry.get("gps_metadata")) if entry.get("gps_metadata") else None

        r = Report(
            date=report_date,
            reporter=entry["reporter"],
            province=prov_name,
            municipality=mun_name,
            barangay=brgy_name,
            severity=entry["severity"],
            infestation_type=entry["infestation_type"],
            lat=entry["lat"],
            lng=entry["lng"],
            description=entry["description"],
            gps_metadata=gps_md,
            status="Pending",
            action_status="Not Resolved",
            photo="",
            user_id=current_user.id,
        )
        db.session.add(r)

    db.session.commit()

    return jsonify({
        "message": "Demo reports seeded successfully",
        "inserted": len(DEMO_REPORTS)
    }), 201


# =================================================
# RUN
# =================================================

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
