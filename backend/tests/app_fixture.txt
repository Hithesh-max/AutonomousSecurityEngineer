"""Intentionally unsafe STATIC TEST FIXTURE. Do not deploy or execute this file."""
from flask import Flask, request
import sqlite3
import subprocess
app = Flask(__name__)

@app.get("/search")
def search():
    value = request.args.get("q")
    database = sqlite3.connect(":memory:")
    return database.execute("SELECT * FROM invoices WHERE owner = '" + value + "'").fetchall()

@app.get("/calculate")
def calculate():
    return str(eval(request.args.get("expression")))

@app.get("/command")
def command():
    return subprocess.run(request.args.get("cmd"), shell=True)
