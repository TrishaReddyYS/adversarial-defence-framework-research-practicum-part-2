"""Sample generated code — safe parameterised query (no vulnerability). Test input."""
import sqlite3


def get_user(username):
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    # Safe: parameter binding, no string interpolation.
    cur.execute("SELECT * FROM users WHERE name = ?", (username,))
    return cur.fetchone()
