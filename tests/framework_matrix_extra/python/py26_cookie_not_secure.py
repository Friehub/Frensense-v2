from flask import Flask, request, redirect, url_for, render_template, render_template_string
app = Flask(__name__)
from flask import make_response
@app.route("/u")
def u():
    r = make_response("ok")
    r.set_cookie("sid", "abc", secure=False)
    return r
