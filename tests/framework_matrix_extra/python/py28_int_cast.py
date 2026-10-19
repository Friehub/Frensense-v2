from flask import Flask, request, redirect, url_for, render_template, render_template_string
app = Flask(__name__)
import sqlite3
@app.route("/u")
def u():
    uid = int(request.args.get("id"))
    return str(sqlite3.connect("x").execute("SELECT * FROM t WHERE id = " + str(uid)).fetchall())
