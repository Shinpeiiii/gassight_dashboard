import os
import uuid
from datetime import datetime, timedelta

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
from flask_jwt_extended import (
    JWTManager, create_access_token, create_refresh_token,
    jwt_required, get_jwt_identity
)
from flask_cors import CORS

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

app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=2)
app.config["JWT_REFRESH_TOKEN_EXPIRES"] = timedelta(days=7)

jwt = JWTManager(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"

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
    full_name = db.Column(db.String(200))
    email = db.Column(db.String(200), unique=True)
    contact = db.Column(db.String(100))
    address = db.Column(db.String(255))
    is_admin = db.Column(db.Boolean, default=False)

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

    # NEW: infestation type (e.g. GAS, RBB, etc.)
    infestation_type = db.Column(db.String(120))

    photo = db.Column(db.String(255))

    # GEO-TAGGING
    lat = db.Column(db.Float)   # latitude
    lng = db.Column(db.Float)   # longitude

    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# Create tables (dev)
with app.app_context():
    db.create_all()

    # OPTIONAL one-time migration helper (lat, lng, infestation_type)
    try:
        db.session.execute("ALTER TABLE report ADD COLUMN lat DOUBLE PRECISION;")
        print("✔ Added column: lat")
    except Exception as e:
        print("ℹ lat column already exists or could not be added:", e)

    try:
        db.session.execute("ALTER TABLE report ADD COLUMN lng DOUBLE PRECISION;")
        print("✔ Added column: lng")
    except Exception as e:
        print("ℹ lng column already exists or could not be added:", e)

    try:
        db.session.execute("ALTER TABLE report ADD COLUMN infestation_type TEXT;")
        print("✔ Added column: infestation_type")
    except Exception as e:
        print("ℹ infestation_type column already exists or could not be added:", e)

    db.session.commit()

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
# API — LOCATION (FOR DASHBOARD FILTER DROPDOWNS)
# (returns names, not IDs)
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
    Body JSON: {username, password}
    Returns tokens on success.
    """
    data = request.get_json() or {}

    username = data.get("username", "").strip()
    password = data.get("password", "").strip()

    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400

    if User.query.filter_by(username=username).first():
        return jsonify({"error": "Username exists"}), 409

    user = User(username=username)
    user.set_password(password)

    db.session.add(user)
    db.session.commit()

    access_token = create_access_token(identity=str(user.id))
    refresh_token = create_refresh_token(identity=str(user.id))

    # return both 'token' and 'access_token' for compatibility
    return jsonify({
        "message": "Signup success",
        "token": access_token,
        "access_token": access_token,
        "refresh_token": refresh_token,
        "username": username,
    }), 200


@app.route("/api/register", methods=["POST"])
def api_register_legacy():
    """
    Legacy register endpoint (if old app uses it).
    Body JSON: {username, password, fullName, email, contact, address, adminCode}
    """
    data = request.get_json() or {}

    username = data.get("username", "").strip()
    password = data.get("password", "").strip()
    full_name = data.get("fullName", "")
    email = data.get("email", "")
    contact = data.get("contact", "")
    address = data.get("address", "")
    admin_code = data.get("adminCode", "").strip()

    if User.query.filter_by(username=username).first():
        return jsonify({"error": "Username exists"}), 409

    if email and User.query.filter_by(email=email).first():
        return jsonify({"error": "Email exists"}), 409

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

    return jsonify({"message": "Account created"}), 201


@app.route("/api/login", methods=["POST"])
def api_login():
    """
    Body JSON: {username, password}
    Returns: {message, token, access_token, refresh_token}
    """
    data = request.get_json() or {}
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()

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


@app.route("/api/check_token", methods=["GET"])
@jwt_required()
def api_check_token():
    """
    Used by Flutter _verifyToken() to auto-login if token still valid.
    """
    user_id = get_jwt_identity()
    return jsonify({"valid": True, "user_id": int(user_id)}), 200

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

        reporter = form.get("reporter")
        province = form.get("province")
        municipality = form.get("municipality")
        barangay = form.get("barangay")
        severity = form.get("severity", "Low")
        infestation_type = form.get("infestation_type", "Other")

        try:
            lat = float(form.get("lat")) if form.get("lat") else None
            lng = float(form.get("lng")) if form.get("lng") else None
        except (TypeError, ValueError):
            lat = None
            lng = None

        photo = ""
        if "photo" in request.files:
            f = request.files["photo"]
            if f and f.filename:
                fname = secure_filename(f"{uuid.uuid4().hex}_{f.filename}")
                f.save(os.path.join(app.config["UPLOAD_FOLDER"], fname))
                photo = f"/static/uploads/{fname}"

    else:
        data = request.get_json() or {}

        reporter = data.get("reporter")
        province = data.get("province")
        municipality = data.get("municipality")
        barangay = data.get("barangay")
        severity = data.get("severity", "Low")
        infestation_type = data.get("infestation_type", "Other")

        lat = data.get("lat")
        lng = data.get("lng")
        try:
            lat = float(lat) if lat is not None else None
            lng = float(lng) if lng is not None else None
        except (TypeError, ValueError):
            lat = None
            lng = None

        photo = data.get("photo_url", "")

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

    return jsonify({
        "message": "Report submitted successfully",
        "id": report.id,
        "severity": report.severity,
        "infestation_type": report.infestation_type,
    }), 201

# -------------------------------------------------
# DASHBOARD API — FILTERED REPORTS
# -------------------------------------------------
@app.route("/api/reports")
def get_reports():
    province_name = request.args.get("province")
    municipality_name = request.args.get("municipality")
    barangay_name = request.args.get("barangay")
    severity = request.args.get("severity")
    infestation_type = request.args.get("infestation_type")
    start_date = request.args.get("start_date")
    end_date = request.args.get("end_date")

    q = Report.query

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
# RUN
# -------------------------------------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
