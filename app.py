import flask

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request
import json

# Configure application
app = Flask(__name__)

# Configure CS50 Library to use SQLite database
db = SQL("./database.db")

@app.route("/home")
def home():
    users = db.execute("SELECT * FROM users")
    for row in users:
        row.pop("id")

    return json.dumps(users)