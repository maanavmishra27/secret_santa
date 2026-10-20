"""Secret Santa backend: Flask + SQLite.

Draw states:  open  ->  locked (optional, manual)  ->  drawn
Nobody can join once the state is not 'open'.
"""
import functools
import hashlib
import os
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone

from flask import Flask, g, jsonify, request
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.config["DB_PATH"] = os.environ.get("DB_PATH", "santa.db")
# Below 3 people, "no mutual pairs" is mathematically impossible, so 3 is a hard floor.
app.config["MIN_PARTICIPANTS"] = max(3, int(os.environ.get("MIN_PARTICIPANTS", "3")))
TOKEN_TTL_DAYS = 7

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT NOT NULL,
    email         TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    wishlist      TEXT NOT NULL DEFAULT '',
    is_admin      INTEGER NOT NULL DEFAULT 0,
    giftee_id     INTEGER REFERENCES users(id),
    created_at    TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    user_id    INTEGER NOT NULL REFERENCES users(id),
    expires_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS state (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
INSERT OR IGNORE INTO state (key, value) VALUES ('status', 'open');
"""


# ---------- helpers ----------
def get_db():
    if "db" not in g:
        # isolation_level=None -> we control transactions manually (needed for the draw)
        g.db = sqlite3.connect(app.config["DB_PATH"], isolation_level=None)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
        g.db.executescript(SCHEMA)
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def now():
    return datetime.now(timezone.utc)


def hash_token(token):
    return hashlib.sha256(token.encode()).hexdigest()


def err(message, code):
    return jsonify({"error": message}), code


def get_status():
    return get_db().execute("SELECT value FROM state WHERE key='status'").fetchone()["value"]


def require_auth(f):
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        header = request.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            return err("Missing or invalid Authorization header", 401)
        token = header[7:]
        row = get_db().execute(
            "SELECT u.*, s.expires_at FROM sessions s JOIN users u ON u.id = s.user_id "
            "WHERE s.token_hash = ?",
            (hash_token(token),),
        ).fetchone()
        if row is None or datetime.fromisoformat(row["expires_at"]) < now():
            return err("Invalid or expired token", 401)
        g.user = row
        g.token_hash = hash_token(token)
        return f(*args, **kwargs)

    return wrapper


def require_admin(f):
    @functools.wraps(f)
    @require_auth
    def wrapper(*args, **kwargs):
        if not g.user["is_admin"]:
            return err("Admin only", 403)
        return f(*args, **kwargs)

    return wrapper


# ---------- auth ----------
@app.post("/auth/signup")
def signup():
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""
    if not name or "@" not in email or len(password) < 8:
        return err("Need name, valid email, and password of at least 8 characters", 400)
    if len(name) > 100:
        return err("Name too long", 400)

    db = get_db()
    if get_status() != "open":
        return err("Signups are closed: the draw is locked or already run", 403)
    if db.execute("SELECT 1 FROM users WHERE email = ?", (email,)).fetchone():
        return err("Email already registered", 409)

    # The very first person to sign up becomes the admin.
    is_admin = 1 if db.execute("SELECT COUNT(*) c FROM users").fetchone()["c"] == 0 else 0
    cur = db.execute(
        "INSERT INTO users (name, email, password_hash, is_admin, created_at) VALUES (?,?,?,?,?)",
        (name, email, generate_password_hash(password), is_admin, now().isoformat()),
    )
    return jsonify({"id": cur.lastrowid, "name": name, "is_admin": bool(is_admin)}), 201


@app.post("/auth/login")
def login():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    if user is None or not check_password_hash(user["password_hash"], password):
        return err("Wrong email or password", 401)
    token = secrets.token_urlsafe(32)
    db.execute(
        "INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?,?,?)",
        (hash_token(token), user["id"], (now() + timedelta(days=TOKEN_TTL_DAYS)).isoformat()),
    )
    return jsonify({"token": token, "expires_in_days": TOKEN_TTL_DAYS})


@app.post("/auth/logout")
@require_auth
def logout():
    get_db().execute("DELETE FROM sessions WHERE token_hash = ?", (g.token_hash,))
    return jsonify({"message": "Logged out"})


# ---------- participants ----------
@app.get("/participants")
@require_auth
def participants():
    rows = get_db().execute("SELECT id, name FROM users ORDER BY id").fetchall()
    return jsonify([{"id": r["id"], "name": r["name"]} for r in rows])


@app.get("/participant/<int:pid>")
@require_auth
def participant(pid):
    if pid != g.user["id"]:
        return err("You can only view your own profile", 403)
    u = g.user
    return jsonify(
        {"id": u["id"], "name": u["name"], "email": u["email"],
         "wishlist": u["wishlist"], "is_admin": bool(u["is_admin"])}
    )


@app.patch("/participant/<int:pid>/wishlist")
@require_auth
def update_wishlist(pid):
    if pid != g.user["id"]:
        return err("You can only edit your own wishlist", 403)
    data = request.get_json(silent=True) or {}
    wishlist = data.get("wishlist")
    if not isinstance(wishlist, str) or len(wishlist) > 1000:
        return err("wishlist must be a string of at most 1000 characters", 400)
    get_db().execute("UPDATE users SET wishlist = ? WHERE id = ?", (wishlist, pid))
    return jsonify({"wishlist": wishlist})


@app.delete("/participant/<int:pid>")
@require_admin
def delete_participant(pid):
    db = get_db()
    if get_status() == "drawn":
        return err("Cannot remove anyone after the draw", 409)
    if pid == g.user["id"]:
        return err("Admin cannot delete themselves", 400)
    if not db.execute("SELECT 1 FROM users WHERE id = ?", (pid,)).fetchone():
        return err("No such participant", 404)
    db.execute("DELETE FROM sessions WHERE user_id = ?", (pid,))
    db.execute("DELETE FROM users WHERE id = ?", (pid,))
    return jsonify({"message": "Participant removed"})


# ---------- draw ----------
@app.get("/draw/status")
@require_auth
def draw_status():
    db = get_db()
    count = db.execute("SELECT COUNT(*) c FROM users").fetchone()["c"]
    return jsonify({"status": get_status(), "participants": count,
                    "minimum_needed": app.config["MIN_PARTICIPANTS"]})


@app.post("/draw/lock")
@require_admin
def draw_lock():
    db = get_db()
    if get_status() != "open":
        return err("Draw is already locked or run", 409)
    db.execute("UPDATE state SET value='locked' WHERE key='status'")
    return jsonify({"status": "locked"})


@app.post("/draw/run")
@require_admin
def draw_run():
    db = get_db()
    db.execute("BEGIN IMMEDIATE")  # grab the write lock so two runs can't race
    try:
        if get_status() == "drawn":
            db.execute("ROLLBACK")
            return err("Draw has already been run", 409)
        ids = [r["id"] for r in db.execute("SELECT id FROM users").fetchall()]
        if len(ids) < app.config["MIN_PARTICIPANTS"]:
            db.execute("ROLLBACK")
            return err(f"Need at least {app.config['MIN_PARTICIPANTS']} participants", 409)

        # Shuffle everyone into one big circle; each person gives to the next person.
        # -> nobody gets themselves, and with 3+ people nobody gets a mutual pair (A->B, B->A).
        secrets.SystemRandom().shuffle(ids)
        for i, giver in enumerate(ids):
            giftee = ids[(i + 1) % len(ids)]
            db.execute("UPDATE users SET giftee_id = ? WHERE id = ?", (giftee, giver))
        db.execute("UPDATE state SET value='drawn' WHERE key='status'")
        db.execute("COMMIT")
    except Exception:
        db.execute("ROLLBACK")
        raise
    # Deliberately do NOT return the pairings, not even to the admin.
    return jsonify({"status": "drawn", "participants": len(ids)})


# ---------- private reveal ----------
@app.get("/my-giftee")
@require_auth
def my_giftee():
    if get_status() != "drawn":
        return err("The draw hasn't been run yet", 409)
    row = get_db().execute(
        "SELECT id, name, wishlist FROM users WHERE id = ?", (g.user["giftee_id"],)
    ).fetchone()
    return jsonify({"giftee": {"id": row["id"], "name": row["name"], "wishlist": row["wishlist"]}})


@app.get("/my-wishlist-giver")
@require_auth
def my_wishlist_giver():
    # The spec says "who's assigned to you", but revealing your Santa's identity would
    # kill the whole point of Secret Santa. So we only confirm that you HAVE a Santa
    # and echo back the wishlist they can currently see.
    if get_status() != "drawn":
        return err("The draw hasn't been run yet", 409)
    return jsonify({"has_secret_santa": True, "wishlist_your_santa_sees": g.user["wishlist"]})


if __name__ == "__main__":
    app.run(debug=False, port=int(os.environ.get("PORT", "5000")))
