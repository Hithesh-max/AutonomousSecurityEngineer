"""Intentionally vulnerable ASE training target. Never expose outside a disposable lab."""
import os
import sqlite3
from flask import Flask, make_response, request

app = Flask(__name__)
DATABASE = "/tmp/training.db"
# Deliberately fake, nonfunctional value to test secret scanners. Never replace with a real key.


def db():
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    connection.execute("CREATE TABLE IF NOT EXISTS notes (id INTEGER PRIMARY KEY, title TEXT, body TEXT)")
    if connection.execute("SELECT COUNT(*) FROM notes").fetchone()[0] == 0:
        connection.executemany("INSERT INTO notes(title, body) VALUES (?, ?)", [("Welcome", "Training record"), ("Private", "Synthetic demo data")])
        connection.commit()
    return connection

@app.get("/")
def home():
    return """<h1>ASE Vulnerability Training Target</h1>
    <ul><li>/search?q=Welcome (SQL injection)</li><li>/echo?text=hello (reflected XSS)</li>
    <li>/calculate?expression=1%2B1 (unsafe eval)</li><li>/command?cmd=hello (shell injection)</li>
    <li>/login (weak cookie flags)</li></ul><p>Use only in the isolated ASE lab.</p>"""

@app.get("/search")
def search():
    term = request.args.get("q", "")
    # INTENTIONAL SQL injection for scanner training. Uses only synthetic in-memory-style demo data.
    connection = db()
    rows = connection.execute("SELECT id, title, body FROM notes WHERE title LIKE '%" + term + "%' ").fetchall()
    connection.close()
    return {"results": [dict(row) for row in rows]}

@app.get("/echo")
def echo():
    # INTENTIONAL reflected HTML injection for scanner training.
    return make_response("<h1>Search result</h1><p>" + request.args.get("text", "") + "</p>")

@app.get("/calculate")
def calculate():
    # INTENTIONAL unsafe evaluation for static-analysis training. Keep container isolated.
    return str(eval(request.args.get("expression", "0")))

@app.get("/command")
def command():
    # Secure mode: do not execute request-controlled commands.
    return "Command execution is disabled."

@app.get("/login")
def login():
    response = make_response("Training login cookie set")
    response.set_cookie("ase_training_session", "fake-session-value")
    return response

@app.get("/health")
def health():
    return {"status": "ok", "purpose": "isolated training target"}

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=False)
