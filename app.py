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

# Render Postgres: convert postgres:// → postgresql://
if db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)

app.config["SQLALCHEMY_DATABASE_URI"] = db_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

# --------------------------------------------------------------------
# MODELS
# --------------------------------------------------------------------
class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)

    # login fields
    username = db.Column(db.String(120), unique=True)
    password = db.Column(db.String(120))

    # NEW FIELDS
    full_name = db.Column(db.String(120))
    email = db.Column(db.String(120))
    contact = db.Column(db.String(120))
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
# AUTO ADD MISSING COLUMNS (NO SHELL REQUIRED)
# --------------------------------------------------------------------
def add_missing_columns():
    engine = db.engine
    existing = engine.execute(
        "SELECT column_name FROM information_schema.columns WHERE table_name='users';"
    ).fetchall()

    columns = [c[0] for c in existing]

    needed = {
        "full_name": "VARCHAR(120)",
        "email": "VARCHAR(120)",
        "contact": "VARCHAR(120)",
        "address": "VARCHAR(200)",
        "is_admin": "BOOLEAN DEFAULT FALSE"
    }

    for col, dtype in needed.items():
        if col not in columns:
            print(f"⚠ Adding missing column: {col}")
            engine.execute(f'ALTER TABLE "users" ADD COLUMN {col} {dtype};')
            print(f"✔ Added {col}")


with app.app_context():
    db.create_all()
    add_missing_columns()

# --------------------------------------------------------------------
# READ DEMO REPORTS
# --------------------------------------------------------------------
DEMO_REPORTS = []
demo_file = os.path.join(os.path.dirname(__file__), "demo_reports.json")

if os.path.exists(demo_file):
    DEMO_REPORTS = json.load(open(demo_file))


def seed_demo_reports():
    if Report.query.count() > 0:
        return

    for r in DEMO_REPORTS:
        db.session.add(
            Report(
                reporter=r["reporter"],
                province=r["province"],
                municipality=r["municipality"],
                barangay=r["barangay"],
                severity=r["severity"],
                infestation_type=r["infestation_type"],
                lat=r["lat"],
                lng=r["lng"],
                description=r["description"],
                date=datetime.strptime(
                    r["gps_metadata"]["timestamp"], "%Y-%m-%dT%H:%M:%SZ"
                ),
            )
        )
    db.session.commit()


seed_demo_reports()

# --------------------------------------------------------------------
# SIGNUP WITH FULL USER INFO
# --------------------------------------------------------------------
@app.route("/signup", methods=["POST"])
def signup():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Invalid request"}), 400

    username = data.get("username")
    password = data.get("password")
    full_name = data.get("fullName")
    email = data.get("email")
    contact = data.get("contact")
    address = data.get("address")
    admin_code = data.get("adminCode")

    if not username or not password:
        return jsonify({"error": "Missing username or password"}), 400

    if User.query.filter_by(username=username).first():
        return jsonify({"error": "Username already exists"}), 400

    ADMIN_CODE = os.environ.get("ADMIN_CODE", "ADMIN123")
    is_admin = (admin_code == ADMIN_CODE)

    user = User(
        username=username,
        password=password,
        full_name=full_name,
        email=email,
        contact=contact,
        address=address,
        is_admin=is_admin,
    )

    db.session.add(user)
    db.session.commit()

    return jsonify({"message": "Signup successful", "is_admin": is_admin})


@app.route("/api/register", methods=["POST"])
def api_register():
    return signup()

# --------------------------------------------------------------------
# LOGIN
# --------------------------------------------------------------------
@app.route("/login", methods=["POST"])
def login_submit():

    if request.form:  # HTML form
        username = request.form.get("username")
        password = request.form.get("password")
    else:  # JSON (mobile)
        data = request.get_json(silent=True)
        username = data.get("username")
        password = data.get("password")

    user = User.query.filter_by(username=username, password=password).first()

    if not user:
        if request.form:
            return redirect("/login?error=1")
        return jsonify({"success": False, "error": "Invalid credentials"}), 401

    # store session
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
# MAIN PAGES
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
def no_access_page():
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
# REPORT APIS
# --------------------------------------------------------------------
@app.route("/api/barangays", methods=["GET"])
def get_barangays():
    return jsonify([b[0] for b in db.session.query(Report.barangay).distinct().all()])

@app.route("/api/reports", methods=["GET"])
def get_reports():
    query = Report.query

    if request.args.get("barangay"):
        query = query.filter_by(barangay=request.args.get("barangay"))
    if request.args.get("severity"):
        query = query.filter_by(severity=request.args.get("severity"))
    if request.args.get("infestation_type"):
        query = query.filter_by(infestation_type=request.args.get("infestation_type"))

    try:
        if request.args.get("start_date"):
            sd = datetime.strptime(request.args.get("start_date"), "%Y-%m-%d")
            query = query.filter(Report.date >= sd)

        if request.args.get("end_date"):
            ed = datetime.strptime(request.args.get("end_date"), "%Y-%m-%d") + timedelta(days=1)
            query = query.filter(Report.date <= ed)

    except:
        pass

    reports = query.order_by(Report.date.desc()).all()

    return jsonify([
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
            "status": "Pending"
        }
        for r in reports
    ])

# --------------------------------------------------------------------
# RENDER ENTRY POINT
# --------------------------------------------------------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
