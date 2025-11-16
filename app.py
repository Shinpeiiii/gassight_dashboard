import os
import uuid
from datetime import datetime, timedelta

from flask import (
    Flask, render_template, jsonify, send_from_directory,
    request, redirect, url_for, flash, abort
)
from flask_sqlalchemy import SQLAlchemy

from werkzeug.utils import secure_filename

from flask_jwt_extended import (
    JWTManager, create_access_token, create_refresh_token,
    jwt_required, get_jwt_identity, get_jwt
)
from flask_cors import CORS

from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman

# -------------------------------------------------
# APP SECURITY INITIALIZATION
# -------------------------------------------------
app = Flask(__name__, static_folder="static", template_folder="templates")

CORS(app, resources={r"/api/*": {"origins": "*"}})

csrf = CSRFProtect(app)
limiter = Limiter(key_func=get_remote_address)
limiter.init_app(app)

Talisman(app, content_security_policy=None)

app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-key")
app.config["JWT_SECRET_KEY"] = os.environ.get("JWT_SECRET_KEY", "jwt-secret")

app.config["SESSION_COOKIE_SECURE"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "None"

app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(minutes=15)
app.config["JWT_REFRESH_TOKEN_EXPIRES"] = timedelta(days=30)

jwt = JWTManager(app)
login_manager = LoginManager(app)

# TOKEN REVOCATION LIST
revoked_tokens = set()

@jwt.token_in_blocklist_loader
def check_revoked(jwt_headers, jwt_payload):
    return jwt_payload["jti"] in revoked_tokens

# -------------------------------------------------
# DB CONFIG
# -------------------------------------------------
db_url = os.environ.get("DATABASE_URL")
if db_url and db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://")

if not db_url:
    print("⚠ Using SQLite fallback.")
    db_url = "sqlite:///gassight.db"

app.config["SQLALCHEMY_DATABASE_URI"] = db_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)

ALLOWED_IMAGE_EXT = {"jpg", "jpeg", "png"}
ADMIN_CODE = os.environ.get("ADMIN_CODE", "GASSIGHT_ADMIN")

# -------------------------------------------------
# MODELS
# -------------------------------------------------
class Province(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), unique=True)

class Municipality(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200))
    province_id = db.Column(db.Integer, db.ForeignKey("province.id"))

class Barangay(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200))
    municipality_id = db.Column(db.Integer, db.ForeignKey("municipality.id"))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(200), unique=True)
    password_hash = db.Column(db.String(200))
    role = db.Column(db.String(20), default="farmer")

    def set_password(self, pw): self.password_hash = generate_password_hash(pw)
    def check_password(self, pw): return check_password_hash(self.password_hash, pw)

class RevokedToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    jti = db.Column(db.String(200), unique=True)
    time_revoked = db.Column(db.DateTime, default=datetime.utcnow)

class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.DateTime, default=datetime.utcnow)

    reporter = db.Column(db.String(150))
    province = db.Column(db.String(200))
    municipality = db.Column(db.String(200))
    barangay = db.Column(db.String(200))

    severity = db.Column(db.String(50))
    infestation_type = db.Column(db.String(200))
    status = db.Column(db.String(100), default="Pending")

    lat = db.Column(db.Float)
    lng = db.Column(db.Float)

    photo = db.Column(db.String(300))
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))

@login_manager.user_loader
def load_user(uid): return User.query.get(int(uid))

with app.app_context():
    db.create_all()

# -------------------------------------------------
# HELPERS
# -------------------------------------------------
def allowed_image(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_IMAGE_EXT

def sanitize_text(value):
    if not value: return ""
    return value.replace("<", "&lt;").replace(">", "&gt;")

def require_admin():
    if not current_user.is_authenticated or current_user.role != "admin":
        abort(403)

# -------------------------------------------------
# FORCE HTTPS
# -------------------------------------------------
@app.before_request
def enforce_https():
    if request.url.startswith("http://") and not app.debug:
        return redirect(request.url.replace("http://", "https://"))

# -------------------------------------------------
# WEB AUTH
# -------------------------------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        user = User.query.filter_by(username=request.form["username"]).first()
        if not user or not user.check_password(request.form["password"]):
            flash("Invalid credentials", "danger")
            return render_template("login.html")

        login_user(user)
        return redirect("/dashboard")
    return render_template("login.html")

@app.route("/logout")
def logout():
    logout_user()
    return redirect("/login")

# -------------------------------------------------
# DASHBOARD
# -------------------------------------------------
@app.route("/dashboard")
@login_required
def dashboard():
    if current_user.role != "admin":
        return render_template("no_access.html")
    return render_template("dashboard.html")

# -------------------------------------------------
# MOBILE API — SIGNUP / LOGIN
# -------------------------------------------------
@app.route("/api/signup", methods=["POST"])
@limiter.limit("5/minute")
def api_signup():
    data = request.get_json() or {}
    username = sanitize_text(data.get("username", "").strip())
    password = data.get("password")

    if User.query.filter_by(username=username).first():
        return jsonify({"error": "Username exists"}), 409

    user = User(username=username, role="farmer")
    user.set_password(password)
    db.session.add(user)
    db.session.commit()

    access = create_access_token(identity=str(user.id))
    refresh = create_refresh_token(identity=str(user.id))

    return jsonify({"token": access, "refresh_token": refresh}), 200

@app.route("/api/login", methods=["POST"])
@limiter.limit("10/minute")
def api_login():
    data = request.get_json() or {}
    user = User.query.filter_by(username=data.get("username")).first()

    if not user or not user.check_password(data.get("password")):
        return jsonify({"error": "Invalid login"}), 401

    access = create_access_token(identity=str(user.id))
    refresh = create_refresh_token(identity=str(user.id))
    return jsonify({"token": access, "refresh_token": refresh}), 200

@app.route("/api/refresh", methods=["POST"])
@jwt_required(refresh=True)
def refresh_token():
    user_id = get_jwt_identity()
    new_access = create_access_token(identity=user_id)
    return jsonify({"token": new_access})

@app.route("/api/logout", methods=["POST"])
@jwt_required()
def api_logout():
    jti = get_jwt()["jti"]
    revoked_tokens.add(jti)
    return jsonify({"message": "Logged out"}), 200

# -------------------------------------------------
# MOBILE — SUBMIT REPORT
# -------------------------------------------------
@app.route("/api/report", methods=["POST"])
@jwt_required()
@limiter.limit("30/minute")
def submit_report():
    user_id = int(get_jwt_identity())

    if request.content_type.startswith("multipart/form-data"):
        form = request.form
        reporter = sanitize_text(form.get("reporter"))
        province = sanitize_text(form.get("province"))
        municipality = sanitize_text(form.get("municipality"))
        barangay = sanitize_text(form.get("barangay"))
        severity = sanitize_text(form.get("severity", "Low"))
        infestation_type = sanitize_text(form.get("infestation_type", "Unknown"))

        lat = float(form.get("lat", 0))
        lng = float(form.get("lng", 0))

        photo_path = ""
        if "photo" in request.files:
            f = request.files["photo"]
            if allowed_image(f.filename):
                new_name = f"{uuid.uuid4().hex}.jpg"
                save_path = os.path.join("static/uploads", new_name)
                f.save(save_path)
                photo_path = f"/static/uploads/{new_name}"

    else:
        data = request.get_json() or {}
        reporter = sanitize_text(data.get("reporter"))
        province = sanitize_text(data.get("province"))
        municipality = sanitize_text(data.get("municipality"))
        barangay = sanitize_text(data.get("barangay"))
        severity = sanitize_text(data.get("severity"))
        infestation_type = sanitize_text(data.get("infestation_type"))
        lat = data.get("lat")
        lng = data.get("lng")
        photo_path = sanitize_text(data.get("photo_url", ""))

    report = Report(
        reporter=reporter,
        province=province,
        municipality=municipality,
        barangay=barangay,
        severity=severity,
        infestation_type=infestation_type,
        lat=lat,
        lng=lng,
        photo=photo_path,
        user_id=user_id,
    )
    db.session.add(report)
    db.session.commit()
    return jsonify({"message": "Report submitted"}), 201

# -------------------------------------------------
# DASHBOARD — FILTERED REPORTS
# -------------------------------------------------
@app.route("/api/reports")
@login_required
def get_reports():
    require_admin()

    q = Report.query
    args = request.args

    for field in ["province", "municipality", "barangay", "severity", "infestation_type"]:
        value = args.get(field)
        if value and value != "All":
            q = q.filter(getattr(Report, field) == value)

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
            "lat": r.lat,
            "lng": r.lng,
            "photo": r.photo,
        } for r in reports
    ])

# -------------------------------------------------
# RUN
# -------------------------------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
