from flask import Flask, request, redirect, url_for, render_template, render_template_string
app = Flask(__name__)
import sqlite3
@app.route("/u")
def u():
    conn = sqlite3.connect("x.db")
    return str(conn.execute("SELECT * FROM t WHERE id = ?", (request.args.get("id"),)).fetchall())
