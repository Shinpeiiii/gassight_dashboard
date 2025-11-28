import os
import json
from datetime import datetime, timedelta
from functools import wraps

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
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

import bcrypt
import jwt
import secrets

app = Flask(__name__)

# =====================================================================
# SECURITY CONFIGURATION
# =====================================================================
# CORS - Restrict origins in production
CORS(app, 
     supports_credentials=True, 
     origins=["*"],  # Change to your domain in production
     allow_headers=["Content-Type", "Authorization"],
     methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"])

# Rate Limiting
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

# SECRET KEYS
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))
JWT_SECRET = os.environ.get("JWT_SECRET", secrets.token_hex(32))
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_HOURS = 24

# SESSION CONFIG
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)

# Additional Security Headers
@app.after_request
def set_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response

# =====================================================================
# DATABASE CONFIG
# =====================================================================
db_url = os.environ.get("DATABASE_URL", "sqlite:///data.db")

if db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)

app.config["SQLALCHEMY_DATABASE_URI"] = db_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)


# =====================================================================
# MODELS
# =====================================================================
class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

    full_name = db.Column(db.String(120))
    email = db.Column(db.String(150))
    contact = db.Column(db.String(100))
    phone = db.Column(db.String(100))

    address = db.Column(db.String(200))
    province = db.Column(db.String(120))
    municipality = db.Column(db.String(120))
    barangay = db.Column(db.String(120))

    is_admin = db.Column(db.Boolean, default=False)
    is_active = db.Column(db.Boolean, default=True)
    failed_login_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime, nullable=True)


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
    ip_address = db.Column(db.String(50))


class AuditLog(db.Model):
    __tablename__ = "audit_logs"
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(120))
    action = db.Column(db.String(100))
    ip_address = db.Column(db.String(50))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    details = db.Column(db.Text)


# =====================================================================
# JWT TOKEN FUNCTIONS
# =====================================================================
def generate_jwt_token(username, is_admin=False):
    """Generate JWT token for user"""
    payload = {
        'username': username,
        'is_admin': is_admin,
        'exp': datetime.utcnow() + timedelta(hours=JWT_EXPIRATION_HOURS),
        'iat': datetime.utcnow()
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def decode_jwt_token(token):
    """Decode and verify JWT token"""
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


def token_required(f):
    """Decorator to require valid JWT token"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        # Get token from header
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            try:
                token = auth_header.split(" ")[1]  # Bearer TOKEN
            except IndexError:
                return jsonify({'error': 'Invalid token format'}), 401
        
        if not token:
            return jsonify({'error': 'Token is missing'}), 401
        
        # Verify token
        payload = decode_jwt_token(token)
        if not payload:
            return jsonify({'error': 'Token is invalid or expired'}), 401
        
        # Add user info to request
        request.current_user = payload['username']
        request.is_admin = payload.get('is_admin', False)
        
        return f(*args, **kwargs)
    
    return decorated


def admin_required(f):
    """Decorator to require admin privileges"""
    @wraps(f)
    @token_required
    def decorated(*args, **kwargs):
        if not request.is_admin:
            log_audit(request.current_user, "UNAUTHORIZED_ADMIN_ACCESS", request.remote_addr)
            return jsonify({'error': 'Admin privileges required'}), 403
        return f(*args, **kwargs)
    return decorated


# =====================================================================
# AUDIT LOGGING
# =====================================================================
def log_audit(username, action, ip_address, details=None):
    """Log security-relevant actions"""
    try:
        log = AuditLog(
            username=username,
            action=action,
            ip_address=ip_address,
            details=details
        )
        db.session.add(log)
        db.session.commit()
    except Exception as e:
        print(f"Audit log error: {e}")


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


def validate_password_strength(password):
    """Validate password meets security requirements"""
    if len(password) < 8:
        return False, "Password must be at least 8 characters"
    if not any(c.isupper() for c in password):
        return False, "Password must contain at least one uppercase letter"
    if not any(c.islower() for c in password):
        return False, "Password must contain at least one lowercase letter"
    if not any(c.isdigit() for c in password):
        return False, "Password must contain at least one number"
    return True, "Password is strong"


# =====================================================================
# INPUT VALIDATION
# =====================================================================
def sanitize_input(text):
    """Basic input sanitization"""
    if not text:
        return text
    # Remove potential XSS attempts
    dangerous_chars = ['<', '>', '"', "'", '&', ';']
    for char in dangerous_chars:
        text = text.replace(char, '')
    return text.strip()


# =====================================================================
# STARTUP DB INITIALIZATION
# =====================================================================
with app.app_context():
    db.create_all()


# =====================================================================
# AUTH ROUTES
# =====================================================================
@app.route("/signup", methods=["POST"])
@limiter.limit("5 per hour")  # Prevent signup spam
def signup():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Invalid request"}), 400

    username = sanitize_input(data.get("username"))
    password = data.get("password")
    full_name = sanitize_input(data.get("full_name") or data.get("fullName"))

    if not username or not password:
        return jsonify({"error": "Missing username/password"}), 400

    # Validate password strength
    is_strong, msg = validate_password_strength(password)
    if not is_strong:
        return jsonify({"error": msg}), 400

    # Check if username exists
    if User.query.filter_by(username=username).first():
        return jsonify({"error": "Username already exists"}), 400

    # Create user
    hashed_pw = hash_password(password)
    
    user = User(
        username=username,
        password=hashed_pw,
        full_name=full_name,
        email=sanitize_input(data.get("email")),
        phone=sanitize_input(data.get("phone") or data.get("contact")),
        province=sanitize_input(data.get("province")),
        municipality=sanitize_input(data.get("municipality")),
        barangay=sanitize_input(data.get("barangay")),
        is_admin=False  # Never allow admin signup via API
    )

    db.session.add(user)
    db.session.commit()

    log_audit(username, "USER_REGISTERED", request.remote_addr)

    return jsonify({"message": "Signup successful"})


@app.route("/login", methods=["POST"])
@limiter.limit("10 per minute")  # Prevent brute force
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

    username = sanitize_input(username)
    user = User.query.filter_by(username=username).first()

    # Check if account is locked
    if user and user.locked_until:
        if datetime.utcnow() < user.locked_until:
            remaining = (user.locked_until - datetime.utcnow()).seconds // 60
            return jsonify({
                "error": f"Account locked. Try again in {remaining} minutes"
            }), 403
        else:
            # Unlock account
            user.locked_until = None
            user.failed_login_attempts = 0
            db.session.commit()

    # Check credentials
    if not user or not check_password(password, user.password):
        # Increment failed attempts
        if user:
            user.failed_login_attempts += 1
            if user.failed_login_attempts >= 5:
                user.locked_until = datetime.utcnow() + timedelta(minutes=30)
                db.session.commit()
                log_audit(username, "ACCOUNT_LOCKED", request.remote_addr, "Too many failed attempts")
                return jsonify({"error": "Account locked due to multiple failed attempts"}), 403
            db.session.commit()
        
        log_audit(username or "unknown", "LOGIN_FAILED", request.remote_addr)
        return jsonify({"error": "Invalid credentials"}), 401

    # Check if account is active
    if not user.is_active:
        log_audit(username, "LOGIN_INACTIVE_ACCOUNT", request.remote_addr)
        return jsonify({"error": "Account is deactivated"}), 403

    # Successful login
    user.failed_login_attempts = 0
    user.last_login = datetime.utcnow()
    db.session.commit()

    # Generate JWT token
    token = generate_jwt_token(username, user.is_admin)

    # For web login
    if request.form:
        session["user"] = username
        session["is_admin"] = user.is_admin
        session.permanent = True
        log_audit(username, "LOGIN_SUCCESS_WEB", request.remote_addr)
        return redirect("/")

    # For API login (mobile)
    log_audit(username, "LOGIN_SUCCESS_API", request.remote_addr)
    return jsonify({
        "success": True,
        "token": token,
        "username": username,
        "is_admin": user.is_admin
    })


@app.route("/logout")
def logout():
    username = session.get("user", "unknown")
    log_audit(username, "LOGOUT", request.remote_addr)
    session.clear()
    return redirect("/login")


# =====================================================================
# PROTECTED ROUTES
# =====================================================================
@app.route("/api/profile", methods=["GET"])
@token_required
def get_profile():
    """Get current user's profile (JWT protected)"""
    user = User.query.filter_by(username=request.current_user).first()

    if not user:
        return jsonify({"error": "User not found"}), 404

    return jsonify({
        "username": user.username,
        "full_name": user.full_name,
        "email": user.email,
        "phone": user.phone,
        "province": user.province,
        "municipality": user.municipality,
        "barangay": user.barangay,
        "is_admin": user.is_admin
    })


@app.route("/api/report", methods=["POST"])
@token_required
@limiter.limit("20 per hour")  # Prevent spam reports
def submit_report():
    """Submit a new report (JWT protected)"""
    try:
        if request.is_json:
            data = request.get_json()
            photo_file = None
        else:
            data = request.form.to_dict()
            photo_file = request.files.get("photo")
        
        # Sanitize inputs
        reporter = sanitize_input(data.get("reporter"))
        province = sanitize_input(data.get("province"))
        municipality = sanitize_input(data.get("municipality"))
        barangay = sanitize_input(data.get("barangay"))
        infestation_type = sanitize_input(data.get("infestation_type"))
        description = sanitize_input(data.get("description"))
        
        if not all([reporter, province, municipality, barangay, infestation_type]):
            return jsonify({"error": "Missing required fields"}), 400
        
        # Handle photo upload
        photo_path = None
        if photo_file:
            # Validate file type
            allowed_extensions = {'png', 'jpg', 'jpeg', 'gif'}
            filename = photo_file.filename
            if '.' not in filename or filename.rsplit('.', 1)[1].lower() not in allowed_extensions:
                return jsonify({"error": "Invalid file type"}), 400
            
            upload_dir = os.path.join(os.path.dirname(__file__), "uploads")
            os.makedirs(upload_dir, exist_ok=True)
            
            safe_filename = f"{datetime.utcnow().timestamp()}_{secrets.token_hex(8)}.{filename.rsplit('.', 1)[1]}"
            photo_path = os.path.join(upload_dir, safe_filename)
            photo_file.save(photo_path)
            photo_path = f"/uploads/{safe_filename}"
        
        # Create report
        report = Report(
            reporter=reporter,
            province=province,
            municipality=municipality,
            barangay=barangay,
            severity="Pending",
            infestation_type=infestation_type,
            lat=float(data.get("lat")) if data.get("lat") else None,
            lng=float(data.get("lng")) if data.get("lng") else None,
            description=description,
            photo=photo_path,
            ip_address=request.remote_addr,
            date=datetime.utcnow()
        )
        
        db.session.add(report)
        db.session.commit()

        log_audit(request.current_user, "REPORT_CREATED", request.remote_addr, f"Report ID: {report.id}")
        
        return jsonify({
            "status": "success",
            "message": "Report submitted successfully",
            "id": report.id
        }), 201
        
    except Exception as e:
        db.session.rollback()
        log_audit(request.current_user, "REPORT_ERROR", request.remote_addr, str(e))
        return jsonify({"error": str(e)}), 500


@app.route("/api/report/<int:report_id>", methods=["DELETE"])
@admin_required
def delete_report(report_id):
    """Delete a report (admin only)"""
    try:
        report = Report.query.get(report_id)
        if not report:
            return jsonify({"error": "Report not found"}), 404

        # Delete photo if exists
        if report.photo and report.photo.startswith("/uploads/"):
            try:
                photo_path = os.path.join(os.path.dirname(__file__), report.photo.lstrip("/"))
                if os.path.exists(photo_path):
                    os.remove(photo_path)
            except Exception as e:
                print(f"Failed to delete photo: {e}")

        db.session.delete(report)
        db.session.commit()

        log_audit(request.current_user, "REPORT_DELETED", request.remote_addr, f"Report ID: {report_id}")

        return jsonify({"status": "success", "message": "Report deleted"}), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500


@app.route("/api/reports", methods=["GET"])
def get_reports():
    """Get reports (public endpoint with rate limit)"""
    # Rate limit public access
    limiter.limit("30 per minute")(lambda: None)()
    
    query = Report.query

    # Apply filters (sanitized)
    province = sanitize_input(request.args.get("province"))
    municipality = sanitize_input(request.args.get("municipality"))
    barangay = sanitize_input(request.args.get("barangay"))
    severity = sanitize_input(request.args.get("severity"))

    if province:
        query = query.filter_by(province=province)
    if municipality:
        query = query.filter_by(municipality=municipality)
    if barangay:
        query = query.filter_by(barangay=barangay)
    if severity:
        query = query.filter_by(severity=severity)

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
        }
        for r in reports
    ])


@app.route("/uploads/<filename>")
def serve_upload(filename):
    """Serve uploaded files"""
    upload_dir = os.path.join(os.path.dirname(__file__), "uploads")
    return send_from_directory(upload_dir, filename)


# =====================================================================
# ADMIN ROUTES
# =====================================================================
@app.route("/")
def dashboard():
    if "user" not in session:
        return redirect("/login")
    return render_template("dashboard.html")


@app.route("/login")
def login_page():
    if "user" in session:
        return redirect("/")
    return render_template("login.html")


# =====================================================================
# RUN
# =====================================================================
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)  # debug=False in production