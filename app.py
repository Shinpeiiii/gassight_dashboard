import os
from flask import Flask, request, jsonify, session, render_template, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from datetime import datetime, timedelta
import json

app = Flask(__name__)
CORS(app)

app.secret_key = os.environ.get("SECRET_KEY", "dev_secret_key")

# --------------------------------------------------------------------
# DATABASE CONFIG
# --------------------------------------------------------------------
db_url = os.environ.get("DATABASE_URL", "sqlite:///data.db")

if db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)

app.config["SQLALCHEMY_DATABASE_URI"] = db_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)


# --------------------------------------------------------------------
# MODELS
# --------------------------------------------------------------------
class User(db.Model):
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
# INITIAL DATABASE CREATE
# --------------------------------------------------------------------
with app.app_context():
    db.create_all()


# --------------------------------------------------------------------
# DEMO REPORT DATA
# --------------------------------------------------------------------
DEMO_REPORTS = json.loads(open("demo_reports.json").read()) if os.path.exists("demo_reports.json") else []


# --------------------------------------------------------------------
# SEEDER (Runs automatically only if DB empty)
# --------------------------------------------------------------------
def seed_demo_reports():
    if Report.query.count() > 0:
        print("✔ Demo reports already exist. Skipping seeding.")
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
            date=datetime.strptime(r["gps_metadata"]["timestamp"], "%Y-%m-%dT%H:%M:%SZ")
        )
        db.session.add(report)

    db.session.commit()
    print("✔ Demo reports inserted successfully.")


with app.app_context():
    seed_demo_reports()


# --------------------------------------------------------------------
# AUTH ROUTES
# --------------------------------------------------------------------
@app.route("/signup", methods=["POST"])
def signup():
    data = request.json
    if not data:
        return jsonify({"error": "Invalid request"}), 400

    username = data.get("username")
    password = data.get("password")

    if User.query.filter_by(username=username).first():
        return jsonify({"error": "Username already exists"}), 400

    user = User(username=username, password=password)
    db.session.add(user)
    db.session.commit()

    return jsonify({"message": "Signup successful"})


@app.route("/login", methods=["POST"])
def login():
    data = request.json
    if not data:
        return jsonify({"error": "Invalid request"}), 400

    username = data.get("username")
    password = data.get("password")

    user = User.query.filter_by(username=username, password=password).first()
    if not user:
        return jsonify({"success": False, "error": "Invalid credentials"})

    session["user"] = username
    return jsonify({"success": True, "username": username})


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")


# --------------------------------------------------------------------
# API – BARANGAY LIST
# --------------------------------------------------------------------
@app.route("/api/barangays", methods=["GET"])
def get_barangays():
    brgys = db.session.query(Report.barangay).distinct().all()
    brgys = [b[0] for b in brgys]
    return jsonify(brgys)


# --------------------------------------------------------------------
# API – REPORT LIST WITH FILTERS
# --------------------------------------------------------------------
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

    if start_date:
        try:
            d = datetime.strptime(start_date, "%Y-%m-%d")
            query = query.filter(Report.date >= d)
        except:
            pass

    if end_date:
        try:
            d = datetime.strptime(end_date, "%Y-%m-%d") + timedelta(days=1)
            query = query.filter(Report.date <= d)
        except:
            pass

    reports = query.order_by(Report.date.desc()).all()

    output = []
    for r in reports:
        output.append({
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
        })

    return jsonify(output)


# --------------------------------------------------------------------
# ADMIN PAGES
# --------------------------------------------------------------------
@app.route("/")
def dashboard():
    return render_template("dashboard.html")


@app.route("/login")
def login_page():
    return render_template("login.html")


# --------------------------------------------------------------------
# FLASK RUN
# --------------------------------------------------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
