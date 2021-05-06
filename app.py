import flask

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request
import json

# Configure application
app = Flask(__name__)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///database.db")

@app.route("/")
def home():
    users = db.execute("SELECT * FROM users")
    for row in users:
        row.pop("id")

    return jsonify(dumps(users))

# NOTE: we should make a package.json file
# current dependencies: python, flask, cs50