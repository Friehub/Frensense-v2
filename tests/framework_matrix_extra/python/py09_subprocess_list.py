from flask import Flask, request, redirect, url_for, render_template, render_template_string
app = Flask(__name__)
import subprocess
@app.route("/u")
def u():
    return subprocess.run(["ls", request.args.get("d")], capture_output=True).stdout
