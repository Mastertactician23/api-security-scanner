#!/usr/bin/env python3
"""
Deliberately Vulnerable API — Target for API Security Scanner
Author: Kofi Asibey-Kitiabi
Description: An intentionally insecure Flask API with one flaw per OWASP
             API Top 10 category plus additional vulnerabilities for scanner testing.
             DO NOT deploy this in production or expose to the internet.
GitHub: https://github.com/Mastertactician23/api-security-scanner
"""

from flask import Flask, request, jsonify
import jwt
import sqlite3
import os
import hashlib

app = Flask(__name__)

# Weak secret — intentional flaw for JWT brute force testing
JWT_SECRET = "secret123"
JWT_ALGORITHM = "HS256"

# ──────────────────────────────────────────────
# IN-MEMORY DATABASE SETUP
# ──────────────────────────────────────────────

def init_db():
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    conn.execute("""
        CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            username TEXT,
            email TEXT,
            password_hash TEXT,
            role TEXT,
            ssn TEXT,
            credit_card TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE orders (
            id INTEGER PRIMARY KEY,
            user_id INTEGER,
            item TEXT,
            amount REAL
        )
    """)
    users = [
        (1, "admin", "admin@corp.com", hashlib.md5(b"admin123").hexdigest(), "admin", "123-45-6789", "4111111111111111"),
        (2, "alice", "alice@corp.com", hashlib.md5(b"alice456").hexdigest(), "user", "987-65-4321", "4222222222222222"),
        (3, "bob",   "bob@corp.com",   hashlib.md5(b"bob789").hexdigest(),   "user", "456-78-9012", "4333333333333333"),
    ]
    conn.executemany("INSERT INTO users VALUES (?,?,?,?,?,?,?)", users)
    orders = [
        (1, 1, "Laptop", 999.99),
        (2, 2, "Phone",  599.99),
        (3, 3, "Tablet", 399.99),
    ]
    conn.executemany("INSERT INTO orders VALUES (?,?,?,?)", orders)
    conn.commit()
    return conn

DB = init_db()


# ──────────────────────────────────────────────
# HELPERS
# ──────────────────────────────────────────────

def get_user(user_id):
    cur = DB.execute("SELECT * FROM users WHERE id=?", (user_id,))
    row = cur.fetchone()
    if not row:
        return None
    return {
        "id": row[0], "username": row[1], "email": row[2],
        "password_hash": row[3], "role": row[4],
        "ssn": row[5], "credit_card": row[6]
    }

def get_token_user(req):
    """Extract user from JWT — intentionally weak validation."""
    auth = req.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    token = auth[7:]
    try:
        # FLAW: accepts 'none' algorithm
        payload = jwt.decode(token, JWT_SECRET,
                             algorithms=["HS256", "none"],
                             options={"verify_signature": False})
        return payload
    except Exception:
        return None


# ──────────────────────────────────────────────
# AUTH ENDPOINTS
# ──────────────────────────────────────────────

@app.route("/api/login", methods=["POST"])
def login():
    """API2 flaw: no rate limiting, returns JWT with sensitive claims."""
    data = request.get_json() or {}
    username = data.get("username", "")
    password = data.get("password", "")
    password_hash = hashlib.md5(password.encode()).hexdigest()

    cur = DB.execute(
        "SELECT * FROM users WHERE username=? AND password_hash=?",
        (username, password_hash)
    )
    row = cur.fetchone()
    if not row:
        # FLAW: verbose error leaks whether username exists
        cur2 = DB.execute("SELECT id FROM users WHERE username=?", (username,))
        if cur2.fetchone():
            return jsonify({"error": "Wrong password for user: " + username}), 401
        return jsonify({"error": "User not found: " + username}), 401

    token = jwt.encode(
        {"user_id": row[0], "username": row[1], "role": row[4]},
        JWT_SECRET, algorithm=JWT_ALGORITHM
    )
    return jsonify({
        "token": token,
        "user_id": row[0],
        "role": row[4],
        # FLAW: returns password hash in login response
        "password_hash": row[3]
    })


# ──────────────────────────────────────────────
# USER ENDPOINTS
# ──────────────────────────────────────────────

@app.route("/api/users/<int:user_id>", methods=["GET"])
def get_user_endpoint(user_id):
    """
    API1 flaw: BOLA — any authenticated user can access any user's data.
    API3 flaw: returns SSN, credit card, password hash (excessive data exposure).
    """
    # FLAW: no ownership check — user 2 can read user 1's data
    user = get_user(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404
    # Returns ALL fields including sensitive ones
    return jsonify(user)


@app.route("/api/profile", methods=["GET"])
def profile():
    """API2 flaw: returns profile data with no authentication required."""
    # FLAW: no auth check at all
    return jsonify({
        "message": "Profile endpoint",
        "server": "Flask/3.0",
        "database": "SQLite",
        "debug_mode": True,
        "users_count": 3
    })


@app.route("/api/users", methods=["GET"])
def list_users():
    """API6 flaw: mass enumeration — returns all users with sensitive data."""
    cur = DB.execute("SELECT * FROM users")
    rows = cur.fetchall()
    users = [{"id": r[0], "username": r[1], "email": r[2],
              "password_hash": r[3], "role": r[4], "ssn": r[5]} for r in rows]
    return jsonify({"users": users, "total": len(users)})


# ──────────────────────────────────────────────
# ORDER ENDPOINTS (BOLA via different resource)
# ──────────────────────────────────────────────

@app.route("/api/orders/<int:order_id>", methods=["GET"])
def get_order(order_id):
    """API1 flaw: BOLA — user can access any order by ID."""
    cur = DB.execute("SELECT * FROM orders WHERE id=?", (order_id,))
    row = cur.fetchone()
    if not row:
        return jsonify({"error": "Order not found"}), 404
    return jsonify({"id": row[0], "user_id": row[1], "item": row[2], "amount": row[3]})


# ──────────────────────────────────────────────
# ADMIN ENDPOINTS
# ──────────────────────────────────────────────

@app.route("/api/admin/users", methods=["GET"])
def admin_users():
    """API5 flaw: admin endpoint accessible without privilege check."""
    # FLAW: no role check — any user (or no user) can hit this
    cur = DB.execute("SELECT * FROM users")
    rows = cur.fetchall()
    return jsonify({
        "admin_panel": True,
        "users": [{"id": r[0], "username": r[1], "email": r[2],
                   "role": r[4], "ssn": r[5], "credit_card": r[6]} for r in rows]
    })


@app.route("/api/admin/config", methods=["GET"])
def admin_config():
    """API5 flaw: exposes server configuration to unauthenticated users."""
    return jsonify({
        "database_url": "sqlite:///prod.db",
        "jwt_secret": JWT_SECRET,
        "debug": True,
        "version": "1.0.0",
        "internal_ip": "172.18.0.3"
    })


# ──────────────────────────────────────────────
# SQL INJECTION VULNERABLE ENDPOINT
# ──────────────────────────────────────────────

@app.route("/api/search", methods=["GET"])
def search():
    """SQL injection flaw: user input directly concatenated into query."""
    query = request.args.get("q", "")
    try:
        # FLAW: raw string concatenation — SQLi vulnerable
        sql = f"SELECT id, username, email FROM users WHERE username LIKE '%{query}%'"
        cur = DB.execute(sql)
        rows = cur.fetchall()
        return jsonify({
            "query": query,
            "sql": sql,  # FLAW: exposes raw SQL in response
            "results": [{"id": r[0], "username": r[1], "email": r[2]} for r in rows]
        })
    except Exception as e:
        # FLAW: returns full exception including SQL error
        return jsonify({"error": str(e), "sql": sql}), 500


# ──────────────────────────────────────────────
# SSRF VULNERABLE ENDPOINT
# ──────────────────────────────────────────────

@app.route("/api/fetch", methods=["POST"])
def fetch_url():
    """API7 flaw: SSRF — fetches any URL the user provides."""
    import urllib.request
    data = request.get_json() or {}
    url = data.get("url", "")
    if not url:
        return jsonify({"error": "url parameter required"}), 400
    try:
        # FLAW: fetches internal URLs without restriction
        with urllib.request.urlopen(url, timeout=3) as resp:
            content = resp.read(500).decode("utf-8", errors="replace")
        return jsonify({"url": url, "content": content, "status": "fetched"})
    except Exception as e:
        return jsonify({"url": url, "error": str(e), "status": "failed"})


# ──────────────────────────────────────────────
# XSS VULNERABLE ENDPOINT
# ──────────────────────────────────────────────

@app.route("/api/comment", methods=["POST"])
def comment():
    """XSS flaw: reflects user input without sanitisation."""
    data = request.get_json() or {}
    text = data.get("text", "")
    # FLAW: reflects raw input — XSS if rendered in browser
    return jsonify({"comment": text, "rendered": f"<p>{text}</p>"})


# ──────────────────────────────────────────────
# HIDDEN / LEGACY ENDPOINTS (API9)
# ──────────────────────────────────────────────

@app.route("/debug", methods=["GET"])
def debug():
    """API9 flaw: undocumented debug endpoint leaks server internals."""
    return jsonify({
        "python_version": "3.11",
        "flask_version": "3.0",
        "jwt_secret": JWT_SECRET,
        "db_path": ":memory:",
        "routes": [str(r) for r in app.url_map.iter_rules()]
    })

@app.route("/swagger", methods=["GET"])
def swagger():
    """API9 flaw: swagger/OpenAPI docs exposed in production."""
    return jsonify({
        "openapi": "3.0.0",
        "info": {"title": "Corp API", "version": "1.0"},
        "paths": {
            "/api/admin/config": {"get": {"description": "Admin config"}},
            "/api/users": {"get": {"description": "All users"}},
        }
    })

@app.route("/v1/users/<int:user_id>", methods=["GET"])
def legacy_user(user_id):
    """API9 flaw: legacy API version still active and unpatched."""
    user = get_user(user_id)
    return jsonify(user) if user else (jsonify({"error": "Not found"}), 404)

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "version": "1.0.0"})


# ──────────────────────────────────────────────
# CORS MISCONFIGURATION (API8)
# ──────────────────────────────────────────────

@app.after_request
def add_headers(response):
    """
    API8 flaw: CORS wildcard allows any origin to read responses.
    Also missing all recommended security headers.
    """
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, PATCH, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "*"
    # FLAWS: missing X-Content-Type-Options, X-Frame-Options, CSP, HSTS
    return response


@app.errorhandler(500)
def server_error(e):
    """API8 flaw: verbose 500 errors expose stack traces."""
    import traceback
    return jsonify({
        "error": "Internal server error",
        "exception": str(e),
        "traceback": traceback.format_exc()
    }), 500


# ──────────────────────────────────────────────
# ENTRY POINT
# ──────────────────────────────────────────────

if __name__ == "__main__":
    print("")
    print("  DELIBERATELY VULNERABLE API")
    print("  by Kofi Asibey-Kitiabi")
    print("  WARNING: Intentionally insecure — lab use only")
    print("  Running on: http://0.0.0.0:8080")
    print("")
    app.run(host="0.0.0.0", port=8080, debug=True)
