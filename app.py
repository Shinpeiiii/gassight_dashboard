import os
import json
from datetime import datetime, timedelta

from flask import (
    Flask,
    request,
    jsonify,
    session,
    render_template,
    redirect,
)
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from sqlalchemy import text

app = Flask(__name__)
CORS(app)

# --------------------------------------------------------------------
# SECRET KEY
# --------------------------------------------------------------------
app.secret_key = os.environ.get("SECRET_KEY", "dev_secret_key")

# --------------------------------------------------------------------
# DATABASE CONFIG
# --------------------------------------------------------------------
db_url = os.environ.get("DATABASE_URL", "sqlite:///data.db")

# Render Postgres requires postgresql:// format
if db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)

app.config["SQLALCHEMY_DATABASE_URI"] = db_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)


# --------------------------------------------------------------------
# AUTO-FIX USER TABLE (SQLAlchemy 2.x SAFE)
# --------------------------------------------------------------------
def add_missing_columns():
    try:
        result = db.session.execute(
            text(
                "SELECT column_name FROM information_schema.columns "
                "WHERE table_name='users';"
            )
        ).fetchall()

        columns = [r[0] for r in result]

        required_columns = {
            "password": "VARCHAR(120)",
            "full_name": "VARCHAR(120)",
            "email": "VARCHAR(150)",
            "contact": "VARCHAR(100)",
            "address": "VARCHAR(200)",
            "is_admin": "BOOLEAN DEFAULT FALSE",
        }

        for col, dtype in required_columns.items():
            if col not in columns:
                print(f"⚠ Adding missing users column: {col}")
                db.session.execute(
                    text(f'ALTER TABLE "users" ADD COLUMN {col} {dtype};')
                )
                db.session.commit()
                print(f"✔ Added: {col}")

    except Exception as e:
        print("❌ Column auto-fix failed:", e)


# --------------------------------------------------------------------
# MODELS
# --------------------------------------------------------------------
class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(120), unique=True)
    password = db.Column(db.String(120))

    full_name = db.Column(db.String(120))
    email = db.Column(db.String(150))
    contact = db.Column(db.String(100))
    address = db.Column(db.String(200))

    is_admin = db.Column(db.Boolean, default=False)


class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    reporter = db.Column(db.String(120))
    province = db.Column(db.String(120))
    municipality = db.Column(db.String(120))
    barangay = db.Column(db.String(120))
    severity = db.Column(db.String(50))
    infestation_type = db.Column(db.String(120))
    lat = db.Column(db.Float)
    lng = db.Column(db.Float)
    description = db.Column(db.Text)
    photo = db.Column(db.String(250))
    date = db.Column(db.DateTime, default=datetime.utcnow)


# --------------------------------------------------------------------
# LOAD DEMO REPORTS FROM JSON
# --------------------------------------------------------------------
DEMO_REPORTS = []
demo_path = os.path.join(os.path.dirname(__file__), "demo_reports.json")

if os.path.exists(demo_path):
    try:
        with open(demo_path, "r") as f:
            DEMO_REPORTS = json.load(f)
        print(f"✔ Loaded {len(DEMO_REPORTS)} demo reports from demo_reports.json")
    except Exception as e:
        print("❌ Failed to load demo_reports.json:", e)
else:
    print("ℹ demo_reports.json not found; skipping demo load.")


def seed_demo_reports():
    """
    Seed the Report table with DEMO_REPORTS if table is empty.
    Runs only once on a fresh DB.
    """
    if not DEMO_REPORTS:
        print("ℹ No demo reports to seed.")
        return

    existing_count = Report.query.count()
    if existing_count > 0:
        print(f"ℹ Reports table already has {existing_count} rows. Skipping seeding.")
        return

    print("⚠ Seeding demo reports into database...")

    for r in DEMO_REPORTS:
        # Safe timestamp parsing
        ts = None
        gps_meta = r.get("gps_metadata") or {}
        ts_raw = gps_meta.get("timestamp")
        if ts_raw:
            try:
                ts = datetime.strptime(ts_raw, "%Y-%m-%dT%H:%M:%SZ")
            except Exception:
                ts = datetime.utcnow()
        else:
            ts = datetime.utcnow()

        report = Report(
            reporter=r.get("reporter"),
            province=r.get("province"),
            municipality=r.get("municipality"),
            barangay=r.get("barangay"),
            severity=r.get("severity"),
            infestation_type=r.get("infestation_type"),
            lat=r.get("lat"),
            lng=r.get("lng"),
            description=r.get("description"),
            photo=None,
            date=ts,
        )
        db.session.add(report)

    db.session.commit()
    print("✔ Demo reports seeded successfully.")


# --------------------------------------------------------------------
# INITIALIZE DB
# --------------------------------------------------------------------
with app.app_context():
    db.create_all()
    add_missing_columns()
    seed_demo_reports()  # <<< THIS MAKES YOUR DASHBOARD SHOW DEMO DATA


# --------------------------------------------------------------------
# AUTH ROUTES
# --------------------------------------------------------------------
@app.route("/signup", methods=["POST"])
def signup():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Invalid request"}), 400

    username = data.get("username")
    password = data.get("password")
    fullName = data.get("fullName")
    email = data.get("email")
    contact = data.get("contact")
    address = data.get("address")
    adminCode = data.get("adminCode")

    if not username or not password:
        return jsonify({"error": "Missing username/password"}), 400

    if User.query.filter_by(username=username).first():
        return jsonify({"error": "Username already exists"}), 400

    is_admin = adminCode == os.environ.get("ADMIN_CODE", "12345")

    user = User(
        username=username,
        password=password,
        full_name=fullName,
        email=email,
        contact=contact,
        address=address,
        is_admin=is_admin,
    )

    db.session.add(user)
    db.session.commit()

    return jsonify({"message": "Signup successful"})


@app.route("/api/register", methods=["POST"])
def api_register():
    return signup()


# --------------------------------------------------------------------
# LOGIN
# --------------------------------------------------------------------
@app.route("/login", methods=["POST"])
def login_submit():
    # HTML FORM LOGIN
    if request.form:
        username = request.form.get("username")
        password = request.form.get("password")
    else:  # JSON LOGIN
        data = request.get_json(silent=True)
        if not data:
            return jsonify({"error": "Invalid request"}), 400

        username = data.get("username")
        password = data.get("password")

    user = User.query.filter_by(username=username, password=password).first()

    if not user:
        if request.form:
            return redirect("/login?error=1")
        return jsonify({"success": False, "error": "Invalid credentials"}), 401

    session["user"] = username
    session["is_admin"] = user.is_admin

    if request.is_json:
        return jsonify({"success": True})

    return redirect("/")


@app.route("/login")
def login_page():
    if "user" in session:
        return redirect("/")
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")


# --------------------------------------------------------------------
# PAGES
# --------------------------------------------------------------------
@app.route("/")
def dashboard():
    if "user" not in session:
        return redirect("/login")
    return render_template("dashboard.html")


@app.route("/register")
def register_page():
    return render_template("register.html")


@app.route("/no_access")
def no_access():
    return render_template("no_access.html")


@app.route("/offline.html")
def offline_page():
    return render_template("offline.html")


@app.route("/reports/print")
def print_reports():
    if "user" not in session:
        return redirect("/login")
    reports = Report.query.order_by(Report.date.desc()).all()
    return render_template("reports_print.html", reports=reports, now=datetime.utcnow)


# --------------------------------------------------------------------
# REPORTS API
# --------------------------------------------------------------------
@app.route("/api/barangays", methods=["GET"])
def get_barangays():
    brgys = [b[0] for b in db.session.query(Report.barangay).distinct().all()]
    return jsonify(brgys)


@app.route("/api/reports", methods=["GET"])
def get_reports():
    query = Report.query

    barangay = request.args.get("barangay")
    severity = request.args.get("severity")
    infestation_type = request.args.get("infestation_type")
    start_date = request.args.get("start_date")
    end_date = request.args.get("end_date")

    if barangay:
        query = query.filter_by(barangay=barangay)
    if severity:
        query = query.filter_by(severity=severity)
    if infestation_type:
        query = query.filter_by(infestation_type=infestation_type)

    # date filtering
    try:
        if start_date:
            query = query.filter(
                Report.date >= datetime.strptime(start_date, "%Y-%m-%d")
            )
        if end_date:
            query = query.filter(
                Report.date
                <= datetime.strptime(end_date, "%Y-%m-%d") + timedelta(days=1)
            )
    except Exception:
        pass

    reports = query.order_by(Report.date.desc()).all()

    return jsonify(
        [
            {
                "id": r.id,
                "reporter": r.reporter,
                "province": r.province,
                "municipality": r.municipality,
                "barangay": r.barangay,
                "severity": r.severity,
                "infestation_type": r.infestation_type,
                "lat": r.lat,
                "lng": r.lng,
                "description": r.description,
                "photo": r.photo,
                "date": r.date.strftime("%Y-%m-%d %H:%M:%S"),
                "status": "Pending",
            }
            for r in reports
        ]
    )


# --------------------------------------------------------------------
# RENDER ENTRY POINT
# --------------------------------------------------------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
