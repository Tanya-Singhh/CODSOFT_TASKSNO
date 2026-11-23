import os
import sqlite3
import secrets
import hashlib
from datetime import datetime, timedelta, timezone
from functools import wraps

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    send_file,
    abort
)

from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    login_required,
    logout_user,
    current_user
)

from flask_wtf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from dotenv import load_dotenv


# ---------------------------------------------------------
# CONFIGURATION
# ---------------------------------------------------------

load_dotenv()

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

DATABASE = os.path.join(BASE_DIR, "file_sharing.db")
STORAGE_DIR = os.path.join(BASE_DIR, "storage", "encrypted")

os.makedirs(STORAGE_DIR, exist_ok=True)

app = Flask(__name__)

app.config["SECRET_KEY"] = os.getenv(
    "FLASK_SECRET_KEY",
    secrets.token_hex(32)
)

app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024  # 10 MB

csrf = CSRFProtect(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"


# ---------------------------------------------------------
# ENCRYPTION KEY
# ---------------------------------------------------------

# For a real deployment, store this in a secure secret manager.
# Do NOT commit it to GitHub.

ENCRYPTION_KEY = os.getenv("FILE_ENCRYPTION_KEY")

if not ENCRYPTION_KEY:
    generated_key = AESGCM.generate_key(bit_length=256)
    ENCRYPTION_KEY = generated_key.hex()

    print("\n[WARNING]")
    print("No FILE_ENCRYPTION_KEY found in .env.")
    print("A temporary encryption key has been generated.")
    print("Files will become unreadable if the application restarts.")
    print("Create a .env file with a permanent key for real use.\n")

KEY = bytes.fromhex(ENCRYPTION_KEY)


# ---------------------------------------------------------
# DATABASE
# ---------------------------------------------------------

def get_db():
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    return connection


def init_database():

    db = get_db()

    db.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            created_at TEXT NOT NULL
        )
    """)

    db.execute("""
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            original_name TEXT NOT NULL,
            stored_name TEXT NOT NULL,
            owner_id INTEGER NOT NULL,
            file_size INTEGER NOT NULL,
            uploaded_at TEXT NOT NULL,
            FOREIGN KEY(owner_id) REFERENCES users(id)
        )
    """)

    db.execute("""
        CREATE TABLE IF NOT EXISTS download_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            token_hash TEXT UNIQUE NOT NULL,
            file_id INTEGER NOT NULL,
            expires_at TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(file_id) REFERENCES files(id)
        )
    """)

    db.commit()

    # Create default administrator
    admin = db.execute(
        "SELECT id FROM users WHERE username = ?",
        ("admin",)
    ).fetchone()

    if not admin:

        password_hash = generate_password_hash("Admin@12345")

        db.execute("""
            INSERT INTO users
            (username, password_hash, role, created_at)
            VALUES (?, ?, ?, ?)
        """, (
            "admin",
            password_hash,
            "admin",
            datetime.now(timezone.utc).isoformat()
        ))

        db.commit()

        print("\nDefault admin created:")
        print("Username: admin")
        print("Password: Admin@12345")
        print("CHANGE THIS PASSWORD FOR REAL DEPLOYMENT.\n")

    db.close()


# ---------------------------------------------------------
# USER MODEL
# ---------------------------------------------------------

class User(UserMixin):

    def __init__(self, user_id, username, role):

        self.id = user_id
        self.username = username
        self.role = role


@login_manager.user_loader
def load_user(user_id):

    db = get_db()

    user = db.execute(
        "SELECT * FROM users WHERE id = ?",
        (user_id,)
    ).fetchone()

    db.close()

    if user:

        return User(
            user["id"],
            user["username"],
            user["role"]
        )

    return None


# ---------------------------------------------------------
# ROLE-BASED ACCESS CONTROL
# ---------------------------------------------------------

def role_required(required_role):

    def decorator(function):

        @wraps(function)
        @login_required
        def wrapper(*args, **kwargs):

            if current_user.role != required_role:

                flash(
                    "You do not have permission to access this resource.",
                    "danger"
                )

                abort(403)

            return function(*args, **kwargs)

        return wrapper

    return decorator


# ---------------------------------------------------------
# FILE ENCRYPTION
# ---------------------------------------------------------

def encrypt_file(input_path, output_path):

    with open(input_path, "rb") as file:

        plaintext = file.read()

    nonce = secrets.token_bytes(12)

    aesgcm = AESGCM(KEY)

    ciphertext = aesgcm.encrypt(
        nonce,
        plaintext,
        None
    )

    with open(output_path, "wb") as file:

        # Store nonce before encrypted data.
        file.write(nonce)
        file.write(ciphertext)


def decrypt_file(encrypted_path):

    with open(encrypted_path, "rb") as file:

        data = file.read()

    nonce = data[:12]
    ciphertext = data[12:]

    aesgcm = AESGCM(KEY)

    plaintext = aesgcm.decrypt(
        nonce,
        ciphertext,
        None
    )

    return plaintext


# ---------------------------------------------------------
# AUTHENTICATION
# ---------------------------------------------------------

@app.route("/")
def index():

    if current_user.is_authenticated:

        return redirect(url_for("dashboard"))

    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if len(username) < 3:

            flash(
                "Username must contain at least 3 characters.",
                "danger"
            )

            return redirect(url_for("register"))

        if len(password) < 8:

            flash(
                "Password must contain at least 8 characters.",
                "danger"
            )

            return redirect(url_for("register"))

        db = get_db()

        existing_user = db.execute(
            "SELECT id FROM users WHERE username = ?",
            (username,)
        ).fetchone()

        if existing_user:

            db.close()

            flash(
                "Username already exists.",
                "danger"
            )

            return redirect(url_for("register"))

        password_hash = generate_password_hash(password)

        db.execute("""
            INSERT INTO users
            (username, password_hash, role, created_at)
            VALUES (?, ?, ?, ?)
        """, (
            username,
            password_hash,
            "user",
            datetime.now(timezone.utc).isoformat()
        ))

        db.commit()
        db.close()

        flash(
            "Registration successful. Please log in.",
            "success"
        )

        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        db = get_db()

        user = db.execute(
            "SELECT * FROM users WHERE username = ?",
            (username,)
        ).fetchone()

        db.close()

        if user and check_password_hash(
            user["password_hash"],
            password
        ):

            user_object = User(
                user["id"],
                user["username"],
                user["role"]
            )

            login_user(user_object)

            return redirect(url_for("dashboard"))

        flash(
            "Invalid username or password.",
            "danger"
        )

    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():

    logout_user()

    flash(
        "You have been logged out.",
        "success"
    )

    return redirect(url_for("login"))


# ---------------------------------------------------------
# DASHBOARD
# ---------------------------------------------------------

@app.route("/dashboard")
@login_required
def dashboard():

    db = get_db()

    if current_user.role == "admin":

        files = db.execute("""
            SELECT files.*, users.username
            FROM files
            JOIN users ON files.owner_id = users.id
            ORDER BY files.uploaded_at DESC
        """).fetchall()

    else:

        files = db.execute("""
            SELECT files.*, users.username
            FROM files
            JOIN users ON files.owner_id = users.id
            WHERE files.owner_id = ?
            ORDER BY files.uploaded_at DESC
        """, (current_user.id,)).fetchall()

    db.close()

    return render_template(
        "dashboard.html",
        files=files
    )


# ---------------------------------------------------------
# FILE UPLOAD
# ---------------------------------------------------------

ALLOWED_EXTENSIONS = {
    "txt",
    "pdf",
    "doc",
    "docx",
    "xls",
    "xlsx",
    "png",
    "jpg",
    "jpeg",
    "zip"
}


def allowed_file(filename):

    return (
        "." in filename and
        filename.rsplit(".", 1)[1].lower()
        in ALLOWED_EXTENSIONS
    )


@app.route("/upload", methods=["POST"])
@login_required
def upload():

    if "file" not in request.files:

        flash(
            "No file selected.",
            "danger"
        )

        return redirect(url_for("dashboard"))

    uploaded_file = request.files["file"]

    if uploaded_file.filename == "":

        flash(
            "Please select a file.",
            "danger"
        )

        return redirect(url_for("dashboard"))

    if not allowed_file(uploaded_file.filename):

        flash(
            "File type is not allowed.",
            "danger"
        )

        return redirect(url_for("dashboard"))

    original_name = secure_filename(
        uploaded_file.filename
    )

    random_name = secrets.token_hex(32) + ".enc"

    temporary_path = os.path.join(
        STORAGE_DIR,
        "temp_" + secrets.token_hex(16)
    )

    encrypted_path = os.path.join(
        STORAGE_DIR,
        random_name
    )

    try:

        uploaded_file.save(temporary_path)

        file_size = os.path.getsize(temporary_path)

        encrypt_file(
            temporary_path,
            encrypted_path
        )

        os.remove(temporary_path)

        db = get_db()

        db.execute("""
            INSERT INTO files
            (original_name, stored_name, owner_id,
             file_size, uploaded_at)
            VALUES (?, ?, ?, ?, ?)
        """, (
            original_name,
            random_name,
            current_user.id,
            file_size,
            datetime.now(timezone.utc).isoformat()
        ))

        db.commit()
        db.close()

        flash(
            "File uploaded and encrypted successfully.",
            "success"
        )

    except Exception as error:

        if os.path.exists(temporary_path):
            os.remove(temporary_path)

        if os.path.exists(encrypted_path):
            os.remove(encrypted_path)

        print("Upload error:", error)

        flash(
            "File upload failed.",
            "danger"
        )

    return redirect(url_for("dashboard"))


# ---------------------------------------------------------
# NORMAL SECURE DOWNLOAD
# ---------------------------------------------------------

@app.route("/download/<int:file_id>")
@login_required
def download(file_id):

    db = get_db()

    file_record = db.execute(
        "SELECT * FROM files WHERE id = ?",
        (file_id,)
    ).fetchone()

    db.close()

    if not file_record:

        abort(404)

    # RBAC:
    # Admin can access all files.
    # Normal users can access only their own files.

    if (
        current_user.role != "admin"
        and file_record["owner_id"] != current_user.id
    ):

        abort(403)

    encrypted_path = os.path.join(
        STORAGE_DIR,
        file_record["stored_name"]
    )

    if not os.path.exists(encrypted_path):

        abort(404)

    try:

        plaintext = decrypt_file(
            encrypted_path
        )

        from io import BytesIO

        return send_file(
            BytesIO(plaintext),
            as_attachment=True,
            download_name=file_record["original_name"]
        )

    except Exception as error:

        print("Download error:", error)

        abort(500)


# ---------------------------------------------------------
# TEMPORARY DOWNLOAD LINK
# ---------------------------------------------------------

@app.route(
    "/generate-link/<int:file_id>",
    methods=["POST"]
)
@login_required
def generate_link(file_id):

    db = get_db()

    file_record = db.execute(
        "SELECT * FROM files WHERE id = ?",
        (file_id,)
    ).fetchone()

    if not file_record:

        db.close()
        abort(404)

    if (
        current_user.role != "admin"
        and file_record["owner_id"] != current_user.id
    ):

        db.close()
        abort(403)

    token = secrets.token_urlsafe(32)

    token_hash = hashlib.sha256(
        token.encode()
    ).hexdigest()

    expires_at = (
        datetime.now(timezone.utc)
        + timedelta(minutes=10)
    ).isoformat()

    db.execute("""
        INSERT INTO download_tokens
        (token_hash, file_id, expires_at, created_at)
        VALUES (?, ?, ?, ?)
    """, (
        token_hash,
        file_id,
        expires_at,
        datetime.now(timezone.utc).isoformat()
    ))

    db.commit()
    db.close()

    download_url = url_for(
        "temporary_download",
        token=token,
        _external=True
    )

    flash(
        f"Temporary link (valid for 10 minutes): {download_url}",
        "success"
    )

    return redirect(url_for("dashboard"))


@app.route("/temporary-download/<token>")
def temporary_download(token):

    token_hash = hashlib.sha256(
        token.encode()
    ).hexdigest()

    db = get_db()

    record = db.execute("""
        SELECT download_tokens.*, files.*
        FROM download_tokens
        JOIN files
        ON download_tokens.file_id = files.id
        WHERE download_tokens.token_hash = ?
    """, (token_hash,)).fetchone()

    if not record:

        db.close()
        abort(404)

    expires_at = datetime.fromisoformat(
        record["expires_at"]
    )

    if datetime.now(timezone.utc) > expires_at:

        db.execute(
            "DELETE FROM download_tokens WHERE id = ?",
            (record["id"],)
        )

        db.commit()
        db.close()

        return "This download link has expired.", 410

    encrypted_path = os.path.join(
        STORAGE_DIR,
        record["stored_name"]
    )

    if not os.path.exists(encrypted_path):

        db.close()
        abort(404)

    try:

        plaintext = decrypt_file(
            encrypted_path
        )

        # One-time token
        db.execute(
            "DELETE FROM download_tokens WHERE id = ?",
            (record["id"],)
        )

        db.commit()
        db.close()

        from io import BytesIO

        return send_file(
            BytesIO(plaintext),
            as_attachment=True,
            download_name=record["original_name"]
        )

    except Exception as error:

        db.close()

        print(
            "Temporary download error:",
            error
        )

        abort(500)


# ---------------------------------------------------------
# ADMIN USER MANAGEMENT
# ---------------------------------------------------------

@app.route("/admin/users")
@role_required("admin")
def admin_users():

    db = get_db()

    users = db.execute("""
        SELECT id, username, role, created_at
        FROM users
        ORDER BY created_at DESC
    """).fetchall()

    db.close()

    return render_template(
        "dashboard.html",
        files=[],
        users=users,
        admin_page=True
    )


# ---------------------------------------------------------
# ERROR HANDLERS
# ---------------------------------------------------------

@app.errorhandler(403)
def forbidden(error):

    return """
    <h1>403 - Access Denied</h1>
    <p>You do not have permission to access this resource.</p>
    <a href="/dashboard">Back to Dashboard</a>
    """, 403


@app.errorhandler(404)
def not_found(error):

    return """
    <h1>404 - Not Found</h1>
    <p>The requested resource was not found.</p>
    <a href="/dashboard">Back to Dashboard</a>
    """, 404


@app.errorhandler(413)
def file_too_large(error):

    flash(
        "File is too large. Maximum size is 10 MB.",
        "danger"
    )

    return redirect(url_for("dashboard"))


# ---------------------------------------------------------
# APPLICATION START
# ---------------------------------------------------------

if __name__ == "__main__":

    init_database()

    print("\n====================================")
    print(" Secure File Sharing Application")
    print("====================================")
    print("Open: http://127.0.0.1:5000")
    print("====================================\n")

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False
    )