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
# DATABASE CONFIGURATION (RENDER SAFE)
# -------------------------------------------------
db_url = os.environ.get("DATABASE_URL")

# Fix old Heroku DB URLs
if db_url and db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)

# Fallback to SQLite if DB is missing
if not db_url:
    print("⚠️ WARNING: No DATABASE_URL found. Using SQLite instead.")
    db_url = "sqlite:///gassight.db"

app.config["SQLALCHEMY_DATABASE_URI"] = db_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

# -------------------------------------------------
# UPLOADS FOLDER
# -------------------------------------------------
app.config["UPLOAD_FOLDER"] = os.path.join(app.static_folder, "uploads")
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

ADMIN_CODE = os.environ.get("ADMIN_CODE", "GASSIGHT_ADMIN")


# -------------------------------------------------
# MODELS
# -------------------------------------------------
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

    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# Create DB tables on startup
with app.app_context():
    db.create_all()


# -------------------------------------------------
# STATIC FILES (PWA)
# -------------------------------------------------
@app.route("/service-worker.js")
def service_worker():
    return send_from_directory("static", "service-worker.js")


# -------------------------------------------------
# PAGE ROUTES
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
        username = request.form.get("username").strip()
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
        username = request.form.get("username").strip()
        password = request.form.get("password")
        full_name = request.form.get("full_name")
        email = request.form.get("email")
        contact = request.form.get("contact_number")
        address = request.form.get("address")
        admin_code = request.form.get("admin_code", "").strip()

        if User.query.filter_by(username=username).first():
            flash("Username already exists.", "warning")
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
# MOBILE API — REGISTER / LOGIN
# -------------------------------------------------
@app.route("/api/register", methods=["POST"])
def api_register():
    data = request.get_json()

    username = data.get("username", "").strip()
    password = data.get("password", "").strip()
    full_name = data.get("fullName", "")
    email = data.get("email", "")
    contact = data.get("contact", "")
    address = data.get("address", "")
    admin_code = data.get("adminCode", "").strip()

    if User.query.filter_by(username=username).first():
        return jsonify({"error": "Username exists"}), 409

    if User.query.filter_by(email=email).first():
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
    data = request.get_json()
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()

    user = User.query.filter_by(username=username).first()

    if not user or not user.check_password(password):
        return jsonify({"error": "Invalid credentials"}), 401

    return jsonify({
        "message": "Login success",
        "access_token": create_access_token(identity=str(user.id)),
        "refresh_token": create_refresh_token(identity=str(user.id))
    })


# -------------------------------------------------
# MOBILE API — SUBMIT REPORT
# -------------------------------------------------
@app.route("/api/report", methods=["POST"])
@jwt_required()
def submit_report():
    user_id = int(get_jwt_identity())

    if request.content_type.startswith("multipart/form-data"):
        form = request.form
        reporter = form.get("reporter")
        barangay = form.get("barangay")
        municipality = form.get("municipality")
        province = form.get("province")
        severity = form.get("severity", "Low")
        lat = float(form.get("lat"))
        lng = float(form.get("lng"))
        photo = ""

        if "photo" in request.files:
            f = request.files["photo"]
            fname = secure_filename(f"{uuid.uuid4().hex}_{f.filename}")
            f.save(os.path.join(app.config["UPLOAD_FOLDER"], fname))
            photo = f"/static/uploads/{fname}"

    else:
        data = request.get_json()
        reporter = data.get("reporter")
        barangay = data.get("barangay")
        municipality = data.get("municipality")
        province = data.get("province")
        severity = data.get("severity", "Low")
        lat = data.get("lat")
        lng = data.get("lng")
        photo = data.get("photo_url", "")

    r = Report(
        reporter=reporter,
        barangay=barangay,
        municipality=municipality,
        province=province,
        severity=severity,
        lat=lat,
        lng=lng,
        photo=photo,
        user_id=user_id,
    )

    db.session.add(r)
    db.session.commit()

    return jsonify({"message": "Report submitted!", "id": r.id})


# -------------------------------------------------
# DASHBOARD API — REPORT FILTERS
# -------------------------------------------------
@app.route("/api/reports")
def get_reports():
    barangay = request.args.get("barangay")
    severity = request.args.get("severity")
    start_date = request.args.get("start_date")
    end_date = request.args.get("end_date")

    q = Report.query

    if barangay and barangay != "All":
        q = q.filter(Report.barangay == barangay)

    if severity and severity != "All":
        q = q.filter(Report.severity == severity)

    if start_date and end_date:
        s = datetime.strptime(start_date, "%Y-%m-%d")
        e = datetime.strptime(end_date, "%Y-%m-%d")
        q = q.filter(Report.date >= s, Report.date <= e)

    reports = q.order_by(Report.date.desc()).all()

    return jsonify([
        {
            "id": r.id,
            "date": r.date.strftime("%Y-%m-%d %H:%M"),
            "reporter": r.reporter,
            "barangay": r.barangay,
            "municipality": r.municipality,
            "province": r.province,
            "severity": r.severity,
            "status": r.status,
            "action_status": r.action_status,
            "photo": r.photo,
            "lat": r.lat,
            "lng": r.lng
        }
        for r in reports
    ])


# -------------------------------------------------
# RUN APP (RENDER)
# -------------------------------------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)