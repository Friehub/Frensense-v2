from flask import Flask, request, redirect, url_for, render_template, render_template_string
app = Flask(__name__)
import sqlite3
@app.route("/u")
def u():
    uid = request.args.get("id")
    if not uid.isdigit():
        return "bad", 400
    return str(sqlite3.connect("x").execute("SELECT * FROM t WHERE id = " + uid).fetchall())
