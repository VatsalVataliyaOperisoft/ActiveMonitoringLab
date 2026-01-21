import sqlite3
import secrets
import string
from datetime import datetime
import hashlib
import os

DB_FILE = os.path.join(os.path.dirname(__file__), "users.db")

def get_db():
    return sqlite3.connect(DB_FILE, check_same_thread=False)

def init_user_db():
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            vm_password TEXT,
            vm_password_hash TEXT,
            web_password TEXT,
            created_at TEXT,
            vm_created INTEGER DEFAULT 0
        )
    """)
    conn.commit()
    conn.close()

def generate_password():
    return str(secrets.randbelow(10000)).zfill(4)

def hash_password(pwd):
    return hashlib.sha256(pwd.encode()).hexdigest()

def create_user(username, web_password):
    vm_password = generate_password()
    vm_hash = vm_password

    conn = get_db()
    conn.execute("""
        INSERT INTO users (username, vm_password, vm_password_hash, web_password, created_at)
        VALUES (?, ?, ?, ?, ?)
    """, (
        username,
        vm_password,
        vm_hash,
        web_password,
        datetime.utcnow().isoformat()
    ))
    conn.commit()
    conn.close()

    return {
        "username": username,
        "vm_password": vm_password
    }

def get_user_for_vm(hostname):
    conn = get_db()
    rows = conn.execute("""
        SELECT id, username, vm_password_hash AS vm_password
        FROM users
        WHERE vm_created = 0
    """).fetchall()
    conn.close()

    return [
        {
            "id": r[0],
            "username": r[1],
            "vm_password": r[2]
        }
        for r in rows
    ]



def mark_vm_created(user_id):
    conn = get_db()
    conn.execute("UPDATE users SET vm_created = 1 WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()

def get_all_users():
    conn = get_db()
    rows = conn.execute("""
        SELECT username, web_password, created_at FROM users
    """).fetchall()
    conn.close()

    return [
        {"username": r[0], "web_password": r[1], "created_at": r[2]}
        for r in rows
    ]
