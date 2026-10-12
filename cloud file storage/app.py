import base64
import os
import sqlite3
from functools import wraps
from pathlib import Path

from flask import (
    Flask, flash, redirect, render_template,
    request, send_file, session, url_for
)
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename


# =========================
# PROJECT PATHS
# =========================

BASE_DIR = Path(__file__).resolve().parent

DB_PATH = BASE_DIR / "database.db"
STORAGE_DIR = BASE_DIR / "storage"
KEYS_DIR = BASE_DIR / "keys"

PRIVATE_KEY_PATH = KEYS_DIR / "private_key.pem"
PUBLIC_KEY_PATH = KEYS_DIR / "public_key.pem"


# =========================
# FLASK CONFIGURATION
# =========================

app = Flask(__name__)

app.secret_key = os.environ.get(
    "SECRET_KEY",
    "change-this-development-secret-key"
)

STORAGE_DIR.mkdir(exist_ok=True)
KEYS_DIR.mkdir(exist_ok=True)


# =========================
# DATABASE
# =========================

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():

    conn = get_db()

    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            original_name TEXT NOT NULL,
            stored_name TEXT NOT NULL,
            encrypted_key TEXT NOT NULL,
            iv TEXT NOT NULL,
            uploaded_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    """)

    conn.commit()
    conn.close()


# =========================
# RSA KEY GENERATION
# =========================

def generate_rsa_keys():

    if PRIVATE_KEY_PATH.exists() and PUBLIC_KEY_PATH.exists():
        return

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    PRIVATE_KEY_PATH.write_bytes(private_pem)
    PUBLIC_KEY_PATH.write_bytes(public_pem)


def load_public_key():

    return serialization.load_pem_public_key(
        PUBLIC_KEY_PATH.read_bytes()
    )


def load_private_key():

    return serialization.load_pem_private_key(
        PRIVATE_KEY_PATH.read_bytes(),
        password=None
    )


# =========================
# AES ENCRYPTION
# =========================

def aes_encrypt(data):

    # Generate random AES-256 key
    aes_key = os.urandom(32)

    # Generate random IV
    iv = os.urandom(16)

    cipher = Cipher(
        algorithms.AES(aes_key),
        modes.CFB(iv)
    )

    encryptor = cipher.encryptor()

    encrypted_data = (
        encryptor.update(data)
        + encryptor.finalize()
    )

    return encrypted_data, aes_key, iv


# =========================
# AES DECRYPTION
# =========================

def aes_decrypt(encrypted_data, aes_key, iv):

    cipher = Cipher(
        algorithms.AES(aes_key),
        modes.CFB(iv)
    )

    decryptor = cipher.decryptor()

    return (
        decryptor.update(encrypted_data)
        + decryptor.finalize()
    )


# =========================
# RSA ENCRYPT AES KEY
# =========================

def rsa_encrypt_key(aes_key):

    public_key = load_public_key()

    encrypted_key = public_key.encrypt(
        aes_key,

        padding.OAEP(
            mgf=padding.MGF1(
                algorithm=hashes.SHA256()
            ),

            algorithm=hashes.SHA256(),

            label=None
        )
    )

    return encrypted_key


# =========================
# RSA DECRYPT AES KEY
# =========================

def rsa_decrypt_key(encrypted_key):

    private_key = load_private_key()

    aes_key = private_key.decrypt(
        encrypted_key,

        padding.OAEP(
            mgf=padding.MGF1(
                algorithm=hashes.SHA256()
            ),

            algorithm=hashes.SHA256(),

            label=None
        )
    )

    return aes_key


# =========================
# LOGIN REQUIRED
# =========================

def login_required(view):

    @wraps(view)
    def wrapped_view(*args, **kwargs):

        if "user_id" not in session:

            flash("Please log in first.")

            return redirect(
                url_for("login")
            )

        return view(*args, **kwargs)

    return wrapped_view


# =========================
# HOME PAGE
# =========================

@app.route("/")
def index():

    if "user_id" in session:
        return redirect(
            url_for("dashboard")
        )

    return render_template("index.html")


# =========================
# REGISTER
# =========================

@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        username = request.form.get(
            "username", ""
        ).strip()

        password = request.form.get(
            "password", ""
        )

        if not username or not password:

            flash(
                "Username and password are required."
            )

            return redirect(
                url_for("register")
            )

        if len(password) < 6:

            flash(
                "Password must contain at least 6 characters."
            )

            return redirect(
                url_for("register")
            )

        conn = get_db()

        try:

            conn.execute(
                """
                INSERT INTO users
                (username, password_hash)
                VALUES (?, ?)
                """,

                (
                    username,
                    generate_password_hash(password)
                )
            )

            conn.commit()

        except sqlite3.IntegrityError:

            conn.close()

            flash(
                "Username already exists."
            )

            return redirect(
                url_for("register")
            )

        conn.close()

        flash(
            "Registration successful. Please log in."
        )

        return redirect(
            url_for("login")
        )

    return render_template(
        "register.html"
    )


# =========================
# LOGIN
# =========================

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form.get(
            "username", ""
        ).strip()

        password = request.form.get(
            "password", ""
        )

        conn = get_db()

        user = conn.execute(
            """
            SELECT * FROM users
            WHERE username = ?
            """,

            (username,)
        ).fetchone()

        conn.close()

        if (
            user
            and check_password_hash(
                user["password_hash"],
                password
            )
        ):

            session.clear()

            session["user_id"] = user["id"]
            session["username"] = user["username"]

            return redirect(
                url_for("dashboard")
            )

        flash(
            "Invalid username or password."
        )

    return render_template(
        "login.html"
    )


# =========================
# LOGOUT
# =========================

@app.route("/logout")
def logout():

    session.clear()

    return redirect(
        url_for("index")
    )


# =========================
# DASHBOARD
# =========================

@app.route("/dashboard")
@login_required
def dashboard():

    conn = get_db()

    files = conn.execute(
        """
        SELECT * FROM files
        WHERE user_id = ?
        ORDER BY uploaded_at DESC
        """,

        (session["user_id"],)
    ).fetchall()

    conn.close()

    return render_template(
        "dashboard.html",
        files=files
    )


# =========================
# FILE UPLOAD
# =========================

@app.route("/upload", methods=["POST"])
@login_required
def upload():

    uploaded = request.files.get(
        "file"
    )

    if not uploaded or not uploaded.filename:

        flash(
            "Please select a file."
        )

        return redirect(
            url_for("dashboard")
        )

    original_name = secure_filename(
        uploaded.filename
    )

    if not original_name:

        flash(
            "Invalid filename."
        )

        return redirect(
            url_for("dashboard")
        )

    data = uploaded.read()

    if not data:

        flash(
            "The selected file is empty."
        )

        return redirect(
            url_for("dashboard")
        )

    # AES encrypt the file
    encrypted_data, aes_key, iv = aes_encrypt(
        data
    )

    # RSA encrypt AES key
    encrypted_key = rsa_encrypt_key(
        aes_key
    )

    # Generate random storage filename
    stored_name = (
        os.urandom(16).hex()
        + ".enc"
    )

    encrypted_path = (
        STORAGE_DIR / stored_name
    )

    encrypted_path.write_bytes(
        encrypted_data
    )

    # Save information in database
    conn = get_db()

    conn.execute(
        """
        INSERT INTO files
        (
            user_id,
            original_name,
            stored_name,
            encrypted_key,
            iv
        )
        VALUES (?, ?, ?, ?, ?)
        """,

        (
            session["user_id"],
            original_name,
            stored_name,
            base64.b64encode(
                encrypted_key
            ).decode(),

            base64.b64encode(
                iv
            ).decode()
        )
    )

    conn.commit()
    conn.close()

    flash(
        "File encrypted and uploaded successfully."
    )

    return redirect(
        url_for("dashboard")
    )


# =========================
# FILE DOWNLOAD
# =========================

@app.route("/download/<int:file_id>")
@login_required
def download(file_id):

    conn = get_db()

    file_record = conn.execute(
        """
        SELECT * FROM files
        WHERE id = ?
        AND user_id = ?
        """,

        (
            file_id,
            session["user_id"]
        )
    ).fetchone()

    conn.close()

    if not file_record:

        flash(
            "File not found."
        )

        return redirect(
            url_for("dashboard")
        )

    encrypted_path = (
        STORAGE_DIR
        / file_record["stored_name"]
    )

    if not encrypted_path.exists():

        flash(
            "Encrypted file is missing."
        )

        return redirect(
            url_for("dashboard")
        )

    encrypted_data = (
        encrypted_path.read_bytes()
    )

    encrypted_key = base64.b64decode(
        file_record["encrypted_key"]
    )

    iv = base64.b64decode(
        file_record["iv"]
    )

    try:

        # RSA decrypt AES key
        aes_key = rsa_decrypt_key(
            encrypted_key
        )

        # AES decrypt file
        original_data = aes_decrypt(
            encrypted_data,
            aes_key,
            iv
        )

    except Exception:

        flash(
            "Decryption failed."
        )

        return redirect(
            url_for("dashboard")
        )

    # Temporary decrypted file
    temp_path = (
        STORAGE_DIR
        / (
            "download_"
            + os.urandom(8).hex()
        )
    )

    temp_path.write_bytes(
        original_data
    )

    response = send_file(
        temp_path,
        as_attachment=True,
        download_name=file_record[
            "original_name"
        ]
    )

    @response.call_on_close
    def cleanup():

        try:

            temp_path.unlink(
                missing_ok=True
            )

        except Exception:

            pass

    return response


# =========================
# DELETE FILE
# =========================

@app.route(
    "/delete/<int:file_id>",
    methods=["POST"]
)
@login_required
def delete_file(file_id):

    conn = get_db()

    file_record = conn.execute(
        """
        SELECT * FROM files
        WHERE id = ?
        AND user_id = ?
        """,

        (
            file_id,
            session["user_id"]
        )
    ).fetchone()

    if not file_record:

        conn.close()

        flash(
            "File not found."
        )

        return redirect(
            url_for("dashboard")
        )

    encrypted_path = (
        STORAGE_DIR
        / file_record["stored_name"]
    )

    encrypted_path.unlink(
        missing_ok=True
    )

    conn.execute(
        """
        DELETE FROM files
        WHERE id = ?
        AND user_id = ?
        """,

        (
            file_id,
            session["user_id"]
        )
    )

    conn.commit()
    conn.close()

    flash(
        "File deleted."
    )

    return redirect(
        url_for("dashboard")
    )


# =========================
# INITIALIZATION
# =========================

with app.app_context():

    init_db()
    generate_rsa_keys()


# =========================
# START SERVER
# =========================

if __name__ == "__main__":

    app.run(
        debug=True
    )