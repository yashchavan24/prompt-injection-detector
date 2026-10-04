"""
auth.py -- per-user accounts + signed session cookies.

Storage: the users table lives in the same database as the event log
(attack_log.py): Neon/Postgres when DATABASE_URL is set, SQLite locally.
Passwords are hashed with PBKDF2-HMAC-SHA256 (200k iterations, per-user
salt). Sessions are HMAC-signed cookies ("who until when") -- no
server-side session table, so cold starts cannot log anyone out as long
as AUTH_SECRET is stable.

Env vars:
  AUTH_SECRET   -- HMAC key for session cookies (generated + persisted
                   locally if absent; SET THIS on Vercel so sessions
                   survive cold starts).
"""
import base64
import hashlib
import hmac
import os
import secrets
import time
import uuid

import attack_log

PBKDF2_ITERATIONS = 200_000
SESSION_DAYS = 30

# ------------------------------------------------------------------- schema
def _init_users():
    attack_log.db_execute("""
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            email TEXT UNIQUE NOT NULL,
            name TEXT,
            pw_hash TEXT NOT NULL,
            created_at REAL NOT NULL
        )
    """)
    attack_log.db_execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email ON users(email)")


_init_users()


# ---------------------------------------------------------------- passwords
def _hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)
    return "pbkdf2$%d$%s$%s" % (
        PBKDF2_ITERATIONS,
        base64.b64encode(salt).decode(),
        base64.b64encode(digest).decode())


def _check_password(password: str, stored: str) -> bool:
    try:
        _algo, iters, salt_b64, digest_b64 = stored.split("$")
        digest = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"),
            base64.b64decode(salt_b64), int(iters))
        return hmac.compare_digest(digest, base64.b64decode(digest_b64))
    except Exception:  # noqa: BLE001 -- malformed stored hash
        return False


# ----------------------------------------------------------------- sessions
def _secret() -> bytes:
    env = os.getenv("AUTH_SECRET", "").strip()
    if env:
        return env.encode("utf-8")
    # local dev: generate once and persist next to the SQLite store
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "data", ".auth_secret")
    try:
        with open(path) as f:
            return f.read().strip().encode("utf-8")
    except FileNotFoundError:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        key = secrets.token_hex(32)
        with open(path, "w") as f:
            f.write(key)
        return key.encode("utf-8")


def make_session_cookie(user_id: str) -> str:
    exp = int(time.time()) + SESSION_DAYS * 86400
    payload = f"{user_id}.{exp}"
    sig = hmac.new(_secret(), payload.encode("utf-8"), hashlib.sha256)\
        .hexdigest()
    return f"v1.{payload}.{sig}"


def read_session_cookie(value: str):
    """Return the user id for a valid, unexpired cookie, else None."""
    if not value:
        return None
    try:
        version, user_id, exp, sig = value.split(".", 3)
        if version != "v1" or int(exp) < time.time():
            return None
        expected = hmac.new(_secret(), f"{user_id}.{exp}".encode("utf-8"),
                            hashlib.sha256).hexdigest()
        if hmac.compare_digest(sig, expected):
            return user_id
    except Exception:  # noqa: BLE001 -- malformed cookie
        return None
    return None


# ------------------------------------------------------------------- users
def _public(row):
    if not row:
        return None
    return {"id": row["id"], "email": row["email"],
            "name": row.get("name") or row["email"].split("@")[0],
            "created_at": row["created_at"]}


def get_user(user_id: str):
    if not user_id:
        return None
    return _public(attack_log.db_query(
        "SELECT id, email, name, pw_hash, created_at FROM users WHERE id = ?",
        (user_id,), one=True))


def get_user_by_email(email: str):
    email = (email or "").strip().lower()
    if not email:
        return None
    return attack_log.db_query(
        "SELECT id, email, name, pw_hash, created_at FROM users"
        " WHERE email = ?", (email,), one=True)


def create_user(email: str, password: str, name: str = ""):
    email = (email or "").strip().lower()
    if "@" not in email or len(email) > 254:
        return None, "Please enter a valid email address."
    if len(password) < 8:
        return None, "Password must be at least 8 characters."
    if get_user_by_email(email):
        return None, "An account with this email already exists."
    user_id = uuid.uuid4().hex
    try:
        attack_log.db_execute(
            "INSERT INTO users (id, email, name, pw_hash, created_at)"
            " VALUES (?,?,?,?,?)",
            (user_id, email, (name or "").strip()[:80] or None,
             _hash_password(password), time.time()))
    except Exception:  # noqa: BLE001 -- race on the unique email index
        return None, "An account with this email already exists."
    return get_user(user_id), None


def verify_user(email: str, password: str):
    row = get_user_by_email(email)
    if row and _check_password(password or "", row["pw_hash"]):
        return _public(row)
    return None
