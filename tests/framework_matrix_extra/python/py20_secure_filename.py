from flask import Flask, request, redirect, url_for, render_template, render_template_string
app = Flask(__name__)
import os
from werkzeug.utils import secure_filename
@app.route("/u")
def u():
    return open(os.path.join("/data", secure_filename(request.args.get("f")))).read()
