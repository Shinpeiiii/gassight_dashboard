import os
import uuid
from datetime import datetime, timedelta

from flask import (
    Flask, render_template, jsonify, send_from_directory,
    request, redirect, url_for, flash, abort
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

# -------------------------------------------------
# APP INITIALIZATION
# -------------------------------------------------
app = Flask(__name__, static_folder="static", template_folder="templates")

# Allow mobile app to call /api/*
CORS(app, resources={r"/api/*": {"origins": "*"}})

app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-key")
app.config["JWT_SECRET_KEY"] = os.environ.get("JWT_SECRET_KEY", "jwt-secret")

# Cookies for web admin session
app.config["SESSION_COOKIE_SECURE"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "None"

# JWT lifetimes
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(minutes=15)
app.config["JWT_REFRESH_TOKEN_EXPIRES"] = timedelta(days=30)

jwt = JWTManager(app)

# Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# In-memory revoked tokens (simple blocklist)
revoked_tokens = set()

@jwt.token_in_blocklist_loader
def check_revoked(jwt_header, jwt_payload):
    return jwt_payload["jti"] in revoked_tokens

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

ALLOWED_IMAGE_EXT = {"jpg", "jpeg", "png"}
ADMIN_CODE = os.environ.get("ADMIN_CODE", "GASSIGHT_ADMIN")

# -------------------------------------------------
# MODELS (USING ORIGINAL TABLE NAMES)
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

    # optional fields for web register
    full_name = db.Column(db.String(200))
    email = db.Column(db.String(200), unique=True)
    contact = db.Column(db.String(100))
    address = db.Column(db.String(255))

    # role: admin or farmer
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

    # infestation type (GAS, RBB, etc.)
    infestation_type = db.Column(db.String(120))

    photo = db.Column(db.String(255))

    # GEO-TAGGING
    lat = db.Column(db.Float)   # latitude
    lng = db.Column(db.Float)   # longitude

    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# Create tables if they don't exist yet
with app.app_context():
    db.create_all()

# -------------------------------------------------
# HELPERS
# -------------------------------------------------
def allowed_image(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_IMAGE_EXT

def sanitize_text(value: str | None) -> str:
    if not value:
        return ""
    return value.replace("<", "&lt;").replace(">", "&gt;")

def require_admin():
    if not current_user.is_authenticated or not current_user.is_admin:
        abort(403)

# -------------------------------------------------
# OPTIONAL: FORCE HTTPS IN PRODUCTION
# -------------------------------------------------
@app.before_request
def enforce_https():
    if not app.debug and request.headers.get("X-Forwarded-Proto", "http") == "http":
        # On Render, X-Forwarded-Proto is usually set
        url = request.url.replace("http://", "https://", 1)
        return redirect(url)

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
# API — LOCATION (FOR DASHBOARD & MOBILE DROPDOWNS)
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
# MOBILE API — SIGNUP / LOGIN / REFRESH / CHECK TOKEN
# -------------------------------------------------
@app.route("/api/signup", methods=["POST"])
def api_signup():
    """
    Body JSON: {username, password}
    Returns tokens on success.
    """
    data = request.get_json() or {}

    username = sanitize_text(data.get("username", "").strip())
    password = data.get("password", "").strip()

    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400

    if User.query.filter_by(username=username).first():
        return jsonify({"error": "Username exists"}), 409

    user = User(username=username, is_admin=False)
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


@app.route("/api/refresh", methods=["POST"])
@jwt_required(refresh=True)
def api_refresh():
    """
    Mobile can call this with the refresh token to get a new access token.
    """
    user_id = get_jwt_identity()
    access_token = create_access_token(identity=str(user_id))
    return jsonify({"access_token": access_token, "token": access_token}), 200


@app.route("/api/check_token", methods=["GET"])
@jwt_required()
def api_check_token():
    """
    Used by Flutter _verifyToken() to auto-login if token still valid.
    """
    user_id = get_jwt_identity()
    return jsonify({"valid": True, "user_id": int(user_id)}), 200


@app.route("/api/logout", methods=["POST"])
@jwt_required()
def api_logout():
    """
    Revoke current token (simple in-memory blocklist).
    """
    jti = get_jwt()["jti"]
    revoked_tokens.add(jti)
    return jsonify({"message": "Logged out"}), 200


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
      infestation_type, lat, lng, photo, description (optional)
    """
    user_id = int(get_jwt_identity())

    if request.content_type and request.content_type.startswith("multipart/form-data"):
        form = request.form

        reporter = sanitize_text(form.get("reporter"))
        province = sanitize_text(form.get("province"))
        municipality = sanitize_text(form.get("municipality"))
        barangay = sanitize_text(form.get("barangay"))
        severity = sanitize_text(form.get("severity", "Low"))
        infestation_type = sanitize_text(form.get("infestation_type", "Other"))

        description = sanitize_text(form.get("description", ""))

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
                photo = ""
    else:
        data = request.get_json() or {}

        reporter = sanitize_text(data.get("reporter"))
        province = sanitize_text(data.get("province"))
        municipality = sanitize_text(data.get("municipality"))
        barangay = sanitize_text(data.get("barangay"))
        severity = sanitize_text(data.get("severity", "Low"))
        infestation_type = sanitize_text(data.get("infestation_type", "Other"))
        description = sanitize_text(data.get("description", ""))

        lat = data.get("lat")
        lng = data.get("lng")
        try:
            lat = float(lat) if lat is not None else None
            lng = float(lng) if lng is not None else None
        except (TypeError, ValueError):
            lat = None
            lng = None

        photo = sanitize_text(data.get("photo_url", ""))

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
@login_required
def get_reports():
    require_admin()

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
