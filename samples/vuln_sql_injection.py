"""Sample generated code — SQL injection (CWE-89). Test input for the scanner/oracle."""
import sqlite3


def get_user(username):
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    # Vulnerable: raw username concatenated straight into the SQL string.
    cur.execute(f"SELECT * FROM users WHERE name = '{username}'")
    return cur.fetchone()
