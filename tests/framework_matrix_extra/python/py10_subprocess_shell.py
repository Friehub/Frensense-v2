from flask import Flask, request, redirect, url_for, render_template, render_template_string
app = Flask(__name__)
import subprocess
@app.route("/u")
def u():
    d = request.args.get("d")
    return subprocess.run(f"ls {d}", shell=True, capture_output=True).stdout
