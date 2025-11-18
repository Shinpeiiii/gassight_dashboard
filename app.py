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
# AUTO FIX BROKEN USER TABLE
# --------------------------------------------------------------------
def fix_user_table():
    with app.app_context():
        try:
            engine = db.engine

            # Check if "users" table exists
            table_exists = engine.dialect.has_table(engine.connect(), "users")

            if not table_exists:
                print("⚠ Users table missing. Creating new table...")
                db.create_all()
                return

            # Check columns
            result = engine.execute(
                "SELECT column_name FROM information_schema.columns "
                "WHERE table_name='users';"
            ).fetchall()
            columns = [r[0] for r in result]

            if "password" not in columns:
                print("⚠ Missing 'password' column. Recreating users table...")
                engine.execute('DROP TABLE IF EXISTS "users" CASCADE;')
                db.create_all()
                print("✔ Users table recreated.")

        except Exception as e:
            print("❌ Error fixing users table:", e)


# Execute auto-repair
fix_user_table()


# --------------------------------------------------------------------
# MODELS
# --------------------------------------------------------------------
class User(db.Model):
    __tablename__ = "users"  # important fix
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(120), unique=True)
    password = db.Column(db.String(120))


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
# DEMO DATA SEED
# --------------------------------------------------------------------
DEMO_REPORTS = []
demo_file_path = os.path.join(os.path.dirname(__file__), "demo_reports.json")

if os.path.exists(demo_file_path):
    with open(demo_file_path, "r") as f:
        DEMO_REPORTS = json.load(f)


def seed_demo_reports():
    if Report.query.count() > 0:
        return
    if not DEMO_REPORTS:
        return

    print("⚠ Seeding demo reports...")

    for r in DEMO_REPORTS:
        report = Report(
            reporter=r["reporter"],
            province=r["province"],
            municipality=r["municipality"],
            barangay=r["barangay"],
            severity=r["severity"],
            infestation_type=r["infestation_type"],
            lat=r["lat"],
            lng=r["lng"],
            description=r["description"],
            photo=None,
            date=datetime.strptime(
                r["gps_metadata"]["timestamp"], "%Y-%m-%dT%H:%M:%SZ"
            ),
        )
        db.session.add(report)

    db.session.commit()
    print("✔ Demo reports inserted.")


with app.app_context():
    db.create_all()
    seed_demo_reports()


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

    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400

    if User.query.filter_by(username=username).first():
        return jsonify({"error": "Username already exists"}), 400

    user = User(username=username, password=password)
    db.session.add(user)
    db.session.commit()

    return jsonify({"message": "Signup successful"})


@app.route("/api/register", methods=["POST"])
def api_register():
    return signup()


# ------------------------------ LOGIN FIXED ------------------------------
@app.route("/login", methods=["POST"])
def login_submit():

    # HTML form login
    if request.form:
        username = request.form.get("username")
        password = request.form.get("password")

    # JSON login (mobile app)
    else:
        data = request.get_json(silent=True)
        if not data:
            return jsonify({"error": "Invalid request"}), 400
        username = data.get("username")
        password = data.get("password")

    user = User.query.filter_by(username=username, password=password).first()

    if not user:
        # HTML FORM → redirect with error
        if request.form:
            return redirect("/login?error=1")

        # JSON → API response
        return jsonify({"success": False, "error": "Invalid credentials"}), 401

    # SUCCESS — login user
    session["user"] = username

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
# API ROUTES
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
            d = datetime.strptime(start_date, "%Y-%m-%d")
            query = query.filter(Report.date >= d)
        if end_date:
            d = datetime.strptime(end_date, "%Y-%m-%d") + timedelta(days=1)
            query = query.filter(Report.date <= d)
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
            "status": "Pending",
        }
        for r in reports
    ])


# --------------------------------------------------------------------
# RENDER ENTRY POINT
# --------------------------------------------------------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
