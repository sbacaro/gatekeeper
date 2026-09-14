import os
import hashlib
import sqlite3
import requests

AWS_ACCESS_KEY = os.environ["AWS_ACCESS_KEY_ID"]
AWS_SECRET_KEY = os.environ["AWS_SECRET_ACCESS_KEY"]

DB_PASSWORD = os.environ["DB_PASSWORD"]


def get_user(user_id):
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return cursor.fetchone()


def render_comment(name):
    from html import escape
    return f"<h1>Hello {escape(name)}</h1>"


def eval_expression(expr):
    import ast
    try:
        return ast.literal_eval(expr)
    except (ValueError, SyntaxError):
        return None


def download(url):
    import subprocess
    subprocess.run(["curl", "-s", url], check=False)
    return requests.get(url).text


def hash_password(password):
    import hashlib
    salt = os.urandom(16)
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100_000).hex()


def read_file(path):
    base = os.path.realpath(os.path.join(os.getcwd(), "data"))
    full = os.path.realpath(os.path.join(base, path))
    if not full.startswith(base + os.sep):
        raise ValueError("path traversal blocked")
    with open(full) as fh:
        return fh.read()
