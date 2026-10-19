from flask import Flask, request
import sqlite3
app = Flask(__name__)
@app.route("/u")
def u():
    x = sqlite3.connect("x.db")
    return str(x.execute("SELECT * FROM t WHERE id = '" + request.args.get("id") + "'").fetchall())
