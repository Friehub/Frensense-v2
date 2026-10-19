from flask import Flask, request, redirect, url_for, render_template, render_template_string
app = Flask(__name__)
from sqlalchemy import text
from myapp import db
@app.route("/u")
def u():
    uid = request.args.get("id")
    return str(db.session.execute(text("SELECT * FROM users WHERE id = :id"), {"id": uid}).fetchall())
