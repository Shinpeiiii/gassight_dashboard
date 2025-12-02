import os
import json
from datetime import datetime, timedelta
from collections import Counter

from flask import (
    Flask,
    request,
    jsonify,
    session,
    render_template,
    redirect,
    send_from_directory,
)
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from sqlalchemy import text, func

import bcrypt

app = Flask(__name__)
CORS(app, supports_credentials=True, origins=["*"])

app.secret_key = os.environ.get("SECRET_KEY", "dev_secret_key_change_this_in_production")

# SESSION CONFIG
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)

# DATABASE CONFIG
db_url = os.environ.get("DATABASE_URL", "sqlite:///data.db")

if db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)

app.config["SQLALCHEMY_DATABASE_URI"] = db_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)


# =====================================================================
# AUTO-FIX USERS TABLE
# =====================================================================
def add_missing_columns():
    try:
        if app.config["SQLALCHEMY_DATABASE_URI"].startswith("sqlite"):
            return

        result = db.session.execute(
            text(
                "SELECT column_name FROM information_schema.columns "
                "WHERE table_name='users';"
            )
        ).fetchall()

        columns = [r[0] for r in result]

        required_columns = {
            "password": "VARCHAR(200)",
            "full_name": "VARCHAR(120)",
            "email": "VARCHAR(150)",
            "contact": "VARCHAR(100)",
            "phone": "VARCHAR(100)",
            "address": "VARCHAR(200)",
            "province": "VARCHAR(120)",
            "municipality": "VARCHAR(120)",
            "barangay": "VARCHAR(120)",
            "is_admin": "BOOLEAN DEFAULT FALSE",
        }

        for col, dtype in required_columns.items():
            if col not in columns:
                print(f"Adding missing users column: {col}")
                db.session.execute(
                    text(f'ALTER TABLE "users" ADD COLUMN {col} {dtype};')
                )
                db.session.commit()

    except Exception as e:
        print("Error adding missing columns:", e)


# =====================================================================
# MODELS
# =====================================================================
class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(120), unique=True)
    password = db.Column(db.String(200))

    full_name = db.Column(db.String(120))
    email = db.Column(db.String(150))
    contact = db.Column(db.String(100))
    phone = db.Column(db.String(100))

    address = db.Column(db.String(200))
    province = db.Column(db.String(120))
    municipality = db.Column(db.String(120))
    barangay = db.Column(db.String(120))

    is_admin = db.Column(db.Boolean, default=False)


class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    reporter = db.Column(db.String(120))
    province = db.Column(db.String(120))
    municipality = db.Column(db.String(120))
    barangay = db.Column(db.String(120))
    severity = db.Column(db.String(50), default="Pending")
    infestation_type = db.Column(db.String(120))
    lat = db.Column(db.Float)
    lng = db.Column(db.Float)
    description = db.Column(db.Text)
    photo = db.Column(db.String(250))
    date = db.Column(db.DateTime, default=datetime.utcnow)


# =====================================================================
# DEMO DATA SEEDING
# =====================================================================
DEMO_PATH = os.path.join(os.path.dirname(__file__), "demo_reports.json")


def seed_demo_reports():
    try:
        if Report.query.count() > 0:
            print("Reports already exist.")
            return

        if not os.path.exists(DEMO_PATH):
            print("demo_reports.json missing.")
            return

        with open(DEMO_PATH, "r") as f:
            data = json.load(f)

        for r in data:
            ts = r.get("gps_metadata", {}).get("timestamp")
            if ts:
                try:
                    date_val = datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ")
                except Exception:
                    date_val = datetime.utcnow()
            else:
                date_val = datetime.utcnow()

            report = Report(
                reporter=r.get("reporter"),
                province=r.get("province"),
                municipality=r.get("municipality"),
                barangay=r.get("barangay"),
                severity="Pending",
                infestation_type=r.get("infestation_type"),
                lat=r.get("lat"),
                lng=r.get("lng"),
                description=r.get("description"),
                photo=None,
                date=date_val,
            )
            db.session.add(report)

        db.session.commit()
        print("Demo seed complete.")

    except Exception as e:
        print("Error seeding:", e)


# =====================================================================
# AUTO-DETERMINE SEVERITY BASED ON REPORT DENSITY
# =====================================================================
def auto_calculate_severity():
    """
    Automatically determine severity based on number of reports in each barangay.
    Logic:
    - 1-2 reports: Low
    - 3-5 reports: Moderate
    - 6-10 reports: High
    - 11+ reports: Critical
    """
    try:
        # Get report counts per barangay
        report_counts = db.session.query(
            Report.barangay,
            Report.municipality,
            Report.province,
            func.count(Report.id).label('count')
        ).filter(
            Report.severity == 'Pending'
        ).group_by(
            Report.barangay,
            Report.municipality,
            Report.province
        ).all()

        for barangay, municipality, province, count in report_counts:
            # Determine severity based on count
            if count >= 11:
                new_severity = "Critical"
            elif count >= 6:
                new_severity = "High"
            elif count >= 3:
                new_severity = "Moderate"
            else:
                new_severity = "Low"

            # Update all pending reports in this barangay
            db.session.execute(
                text("""
                    UPDATE report 
                    SET severity = :severity 
                    WHERE barangay = :barangay 
                    AND municipality = :municipality 
                    AND province = :province 
                    AND severity = 'Pending'
                """),
                {
                    "severity": new_severity,
                    "barangay": barangay,
                    "municipality": municipality,
                    "province": province
                }
            )

        db.session.commit()
        print("Auto-calculated severities updated successfully")

    except Exception as e:
        db.session.rollback()
        print(f"Error auto-calculating severity: {e}")


# =====================================================================
# STARTUP DB INITIALIZATION
# =====================================================================
with app.app_context():
    db.create_all()
    add_missing_columns()
    seed_demo_reports()


# =====================================================================
# PASSWORD HELPERS
# =====================================================================
def hash_password(raw_password: str) -> str:
    return bcrypt.hashpw(raw_password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def check_password(raw_password: str, stored_password: str) -> bool:
    if not stored_password:
        return False

    if stored_password.startswith("$2b$") or stored_password.startswith("$2a$") or stored_password.startswith("$2y$"):
        try:
            return bcrypt.checkpw(
                (raw_password or "").encode("utf-8"),
                stored_password.encode("utf-8"),
            )
        except Exception:
            return False
    else:
        return (raw_password or "") == stored_password


# =====================================================================
# AUTH ROUTES
# =====================================================================
@app.route("/signup", methods=["POST"])
def signup():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Invalid request"}), 400

    username = data.get("username")
    password = data.get("password")

    full_name = data.get("full_name") or data.get("fullName")
    phone = data.get("phone") or data.get("contact")
    contact = phone
    email = data.get("email")

    address = data.get("address")
    province = data.get("province")
    municipality = data.get("municipality")
    barangay = data.get("barangay")

    adminCode = data.get("adminCode")

    if not username or not password:
        return jsonify({"error": "Missing username/password"}), 400

    if User.query.filter_by(username=username).first():
        return jsonify({"error": "Username exists"}), 400

    hashed_pw = hash_password(password)
    is_admin = adminCode == os.environ.get("ADMIN_CODE", "12345")

    user = User(
        username=username,
        password=hashed_pw,
        full_name=full_name,
        email=email,
        contact=contact,
        phone=phone,
        address=address,
        province=province,
        municipality=municipality,
        barangay=barangay,
        is_admin=is_admin,
    )

    db.session.add(user)
    db.session.commit()

    return jsonify({"message": "Signup successful"})


@app.route("/api/register", methods=["POST"])
def api_register():
    return signup()


# =====================================================================
# LOGIN
# =====================================================================
@app.route("/login", methods=["POST"])
def login_submit():
    if request.form:
        username = request.form.get("username")
        password = request.form.get("password")
    else:
        data = request.get_json(silent=True)
        if not data:
            return jsonify({"error": "Invalid request"}), 400
        username = data.get("username")
        password = data.get("password")

    user = User.query.filter_by(username=username).first()

    if not user or not check_password(password, user.password):
        if request.form:
            return redirect("/login?error=1")
        return jsonify({"success": False, "error": "Invalid credentials"}), 401

    session.clear()
    session["user"] = username
    session["is_admin"] = user.is_admin
    session.permanent = True

    if request.is_json:
        return jsonify({"success": True, "is_admin": user.is_admin})

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


# =====================================================================
# USER PROFILE API
# =====================================================================
@app.route("/api/profile", methods=["GET"])
def get_profile():
    """Get current user's profile information"""
    if "user" not in session:
        return jsonify({"error": "Not logged in"}), 401

    username = session["user"]
    user = User.query.filter_by(username=username).first()

    if not user:
        return jsonify({"error": "User not found"}), 404

    return jsonify({
        "username": user.username,
        "full_name": user.full_name,
        "email": user.email,
        "phone": user.phone,
        "contact": user.contact,
        "address": user.address,
        "province": user.province,
        "municipality": user.municipality,
        "barangay": user.barangay,
        "is_admin": user.is_admin
    })


# =====================================================================
# PAGES
# =====================================================================
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


# =====================================================================
# DATABASE EXPORT (FOR SHAHEEN)
# =====================================================================
@app.route("/api/export/database", methods=["GET"])
def export_database():
    """Export all database data as JSON"""
    if "user" not in session:
        return jsonify({"error": "Not logged in"}), 401

    if not session.get("is_admin", False):
        return jsonify({"error": "Admin only"}), 403

    try:
        users = User.query.all()
        reports = Report.query.all()

        return jsonify({
            "users": [{
                "id": u.id,
                "username": u.username,
                "full_name": u.full_name,
                "email": u.email,
                "phone": u.phone,
                "province": u.province,
                "municipality": u.municipality,
                "barangay": u.barangay,
                "is_admin": u.is_admin
            } for u in users],
            "reports": [{
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
                "date": r.date.strftime("%Y-%m-%d %H:%M:%S") if r.date else None
            } for r in reports]
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# =====================================================================
# REPORTS API
# =====================================================================
@app.route("/api/barangays", methods=["GET"])
def get_barangays():
    brgys = [b[0] for b in db.session.query(Report.barangay).distinct().all()]
    return jsonify(brgys)


@app.route("/api/reports", methods=["GET"])
def get_reports():
    query = Report.query

    province = request.args.get("province")
    municipality = request.args.get("municipality")
    barangay = request.args.get("barangay")
    severity = request.args.get("severity")
    infestation_type = request.args.get("infestation_type")
    start_date = request.args.get("start_date")
    end_date = request.args.get("end_date")

    if province:
        query = query.filter_by(province=province)
    if municipality:
        query = query.filter_by(municipality=municipality)
    if barangay:
        query = query.filter_by(barangay=barangay)
    if severity:
        query = query.filter_by(severity=severity)
    if infestation_type:
        query = query.filter_by(infestation_type=infestation_type)

    if start_date:
        try:
            query = query.filter(
                Report.date >= datetime.strptime(start_date, "%Y-%m-%d")
            )
        except Exception:
            pass

    if end_date:
        try:
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
            }
            for r in reports
        ]
    )


# =====================================================================
# REPORTS API
# =====================================================================
@app.route("/api/barangays", methods=["GET"])
def get_barangays():
    # ... existing code ...

@app.route("/api/reports", methods=["GET"])
def get_reports():
    # ... existing code ...

# =====================================================================
# PHILIPPINE LOCATIONS API - ADD THIS NEW SECTION HERE
# =====================================================================

# Complete list of Philippine provinces (81 provinces + NCR)
PHILIPPINE_PROVINCES = [
    "Abra", "Agusan del Norte", "Agusan del Sur", "Aklan", "Albay",
    "Antique", "Apayao", "Aurora", "Basilan", "Bataan", "Batanes",
    "Batangas", "Benguet", "Biliran", "Bohol", "Bukidnon", "Bulacan",
    "Cagayan", "Camarines Norte", "Camarines Sur", "Camiguin", "Capiz",
    "Catanduanes", "Cavite", "Cebu", "Cotabato", "Davao de Oro",
    "Davao del Norte", "Davao del Sur", "Davao Occidental", "Davao Oriental",
    "Dinagat Islands", "Eastern Samar", "Guimaras", "Ifugao", "Ilocos Norte",
    "Ilocos Sur", "Iloilo", "Isabela", "Kalinga", "La Union", "Laguna",
    "Lanao del Norte", "Lanao del Sur", "Leyte", "Maguindanao del Norte",
    "Maguindanao del Sur", "Marinduque", "Masbate", "Metro Manila",
    "Misamis Occidental", "Misamis Oriental", "Mountain Province",
    "Negros Occidental", "Negros Oriental", "Northern Samar", "Nueva Ecija",
    "Nueva Vizcaya", "Occidental Mindoro", "Oriental Mindoro", "Palawan",
    "Pampanga", "Pangasinan", "Quezon", "Quirino", "Rizal", "Romblon",
    "Samar", "Sarangani", "Siquijor", "Sorsogon", "South Cotabato",
    "Southern Leyte", "Sultan Kudarat", "Sulu", "Surigao del Norte",
    "Surigao del Sur", "Tarlac", "Tawi-Tawi", "Zambales",
    "Zamboanga del Norte", "Zamboanga del Sur", "Zamboanga Sibugay"
]

# Sample municipalities for major provinces
PHILIPPINE_LOCATIONS = {
    "Ilocos Norte": [
        "Adams", "Bacarra", "Badoc", "Bangui", "Banna", "Batac City",
        "Burgos", "Carasi", "Currimao", "Dingras", "Dumalneg", "Laoag City",
        "Marcos", "Nueva Era", "Pagudpud", "Paoay", "Pasuquin", "Piddig",
        "Pinili", "San Nicolas", "Sarrat", "Solsona", "Vintar"
    ],
    "Ilocos Sur": [
        "Alilem", "Banayoyo", "Bantay", "Burgos", "Cabugao", "Candon City",
        "Caoayan", "Cervantes", "Galimuyod", "Gregorio del Pilar", "Lidlidda",
        "Magsingal", "Nagbukel", "Narvacan", "Quirino", "Salcedo", "San Emilio",
        "San Esteban", "San Ildefonso", "San Juan", "San Vicente", "Santa",
        "Santa Catalina", "Santa Cruz", "Santa Lucia", "Santa Maria",
        "Santiago", "Santo Domingo", "Sigay", "Sinait", "Sugpon", "Suyo",
        "Tagudin", "Vigan City"
    ],
    "La Union": [
        "Agoo", "Aringay", "Bacnotan", "Bagulin", "Balaoan", "Bangar",
        "Bauang", "Burgos", "Caba", "Luna", "Naguilian", "Pugo",
        "Rosario", "San Fernando City", "San Gabriel", "San Juan",
        "Santo Tomas", "Santol", "Sudipen", "Tubao"
    ],
    "Pangasinan": [
        "Agno", "Aguilar", "Alaminos City", "Alcala", "Anda", "Asingan",
        "Balungao", "Bani", "Basista", "Bautista", "Bayambang", "Binalonan",
        "Binmaley", "Bolinao", "Bugallon", "Burgos", "Calasiao", "Dagupan City",
        "Dasol", "Infanta", "Labrador", "Laoac", "Lingayen", "Mabini",
        "Malasiqui", "Manaoag", "Mangaldan", "Mangatarem", "Mapandan", "Natividad",
        "Pozorrubio", "Rosales", "San Carlos City", "San Fabian", "San Jacinto",
        "San Manuel", "San Nicolas", "San Quintin", "Santa Barbara", "Santa Maria",
        "Santo Tomas", "Sison", "Sual", "Tayug", "Umingan", "Urbiztondo",
        "Urdaneta City", "Villasis"
    ],
    "Metro Manila": [
        "Caloocan City", "Las Piñas City", "Makati City", "Malabon City",
        "Mandaluyong City", "Manila", "Marikina City", "Muntinlupa City",
        "Navotas City", "Parañaque City", "Pasay City", "Pasig City",
        "Pateros", "Quezon City", "San Juan City", "Taguig City", "Valenzuela City"
    ],
    # Add more provinces as needed
}


@app.route("/api/locations/provinces", methods=["GET"])
def get_provinces():
    """Get all provinces in the Philippines (static list)"""
    return jsonify({"provinces": sorted(PHILIPPINE_PROVINCES)})


@app.route("/api/locations/municipalities", methods=["GET"])
def get_municipalities():
    """Get municipalities/cities for a specific province"""
    province = request.args.get("province")
    
    if not province:
        return jsonify({"error": "Province parameter required"}), 400
    
    try:
        # First try static data
        if province in PHILIPPINE_LOCATIONS:
            return jsonify({"municipalities": sorted(PHILIPPINE_LOCATIONS[province])})
        
        # Fallback: Get from database (actual reports)
        municipalities = db.session.query(Report.municipality).distinct().filter(
            Report.province == province,
            Report.municipality.isnot(None)
        ).order_by(Report.municipality).all()
        
        municipality_list = sorted([m[0] for m in municipalities if m[0]])
        
        return jsonify({"municipalities": municipality_list})
        
    except Exception as e:
        print(f"Error fetching municipalities: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/locations/barangays", methods=["GET"])
def get_barangays():
    """Get barangays for a specific municipality/city"""
    province = request.args.get("province")
    municipality = request.args.get("municipality")
    
    if not municipality:
        return jsonify({"error": "Municipality parameter required"}), 400
    
    try:
        # Get barangays from database (actual reports)
        query = db.session.query(Report.barangay).distinct().filter(
            Report.municipality == municipality,
            Report.barangay.isnot(None)
        )
        
        if province:
            query = query.filter(Report.province == province)
        
        barangays = query.order_by(Report.barangay).all()
        barangay_list = sorted([b[0] for b in barangays if b[0]])
        
        return jsonify({"barangays": barangay_list})
        
    except Exception as e:
        print(f"Error fetching barangays: {e}")
        return jsonify({"error": str(e)}), 500


# =====================================================================
# SUBMIT REPORT (Mobile App)
# =====================================================================
@app.route("/api/report", methods=["POST"])
def submit_report():
    # ... existing code continues ...

# =====================================================================
# SUBMIT REPORT (Mobile App)
# =====================================================================
@app.route("/api/report", methods=["POST"])
def submit_report():
    try:
        if request.is_json:
            data = request.get_json()
            photo_file = None
        else:
            data = request.form.to_dict()
            photo_file = request.files.get("photo")
        
        reporter = data.get("reporter")
        province = data.get("province")
        municipality = data.get("municipality")
        barangay = data.get("barangay")
        infestation_type = data.get("infestation_type")
        description = data.get("description")
        lat = data.get("lat")
        lng = data.get("lng")
        
        if not all([reporter, province, municipality, barangay, infestation_type]):
            return jsonify({"error": "Missing required fields"}), 400
        
        photo_path = None
        if photo_file:
            upload_dir = os.path.join(os.path.dirname(__file__), "uploads")
            os.makedirs(upload_dir, exist_ok=True)
            
            filename = f"{datetime.utcnow().timestamp()}_{photo_file.filename}"
            photo_path = os.path.join(upload_dir, filename)
            photo_file.save(photo_path)
            photo_path = f"/uploads/{filename}"
        
        report = Report(
            reporter=reporter,
            province=province,
            municipality=municipality,
            barangay=barangay,
            severity="Pending",
            infestation_type=infestation_type,
            lat=float(lat) if lat else None,
            lng=float(lng) if lng else None,
            description=description,
            photo=photo_path,
            date=datetime.utcnow()
        )
        
        db.session.add(report)
        db.session.commit()

        # Auto-calculate severity after new report
        auto_calculate_severity()
        
        return jsonify({
            "status": "success",
            "message": "Report submitted successfully",
            "id": report.id
        }), 201
        
    except Exception as e:
        db.session.rollback()
        print(f"Error submitting report: {e}")
        return jsonify({"error": str(e)}), 500


# =====================================================================
# DELETE REPORT (ADMIN ONLY)
# =====================================================================
@app.route("/api/report/<int:report_id>", methods=["DELETE"])
def delete_report(report_id):
    """Delete a report (admin only)"""
    try:
        report = Report.query.get(report_id)
        if not report:
            return jsonify({"error": "Report not found"}), 404

        # Delete associated photo if exists
        if report.photo and report.photo.startswith("/uploads/"):
            try:
                photo_path = os.path.join(os.path.dirname(__file__), report.photo.lstrip("/"))
                if os.path.exists(photo_path):
                    os.remove(photo_path)
            except Exception as e:
                print(f"Failed to delete photo: {e}")

        db.session.delete(report)
        db.session.commit()

        return jsonify({
            "status": "success",
            "message": "Report deleted successfully"
        }), 200

    except Exception as e:
        db.session.rollback()
        print(f"Error deleting report: {e}")
        return jsonify({"error": str(e)}), 500


# =====================================================================
# SERVE UPLOADED PHOTOS
# =====================================================================
@app.route("/uploads/<filename>")
def serve_upload(filename):
    upload_dir = os.path.join(os.path.dirname(__file__), "uploads")
    return send_from_directory(upload_dir, filename)


# =====================================================================
# UPDATE SEVERITY
# =====================================================================
@app.route("/api/update_severity", methods=["POST"])
def update_severity():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Invalid request"}), 400

    report_id = data.get("id")
    new_severity = data.get("severity")

    if not report_id or not new_severity:
        return jsonify({"error": "Missing id or severity"}), 400

    try:
        report = Report.query.get(report_id)
        if not report:
            return jsonify({"error": "Report not found"}), 404

        report.severity = new_severity
        db.session.commit()
        
        return jsonify({
            "status": "success",
            "message": f"Severity updated to {new_severity}"
        }), 200

    except Exception as e:
        db.session.rollback()
        print(f"ERROR: Database error: {e}")
        return jsonify({"error": f"Database error: {str(e)}"}), 500


# =====================================================================
# RUN
# =====================================================================
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)