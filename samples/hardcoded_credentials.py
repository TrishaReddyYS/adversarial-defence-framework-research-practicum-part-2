"""Sample generated code — hard-coded credentials (CWE-798). Test input."""
import sqlite3

DB_USER = "admin"
DB_PASSWORD = "S3cr3t_admin_pw!"   # hard-coded secret


def connect():
    return sqlite3.connect(f"db?user={DB_USER}&password={DB_PASSWORD}")
