from flask import Flask, request, redirect, url_for, render_template, render_template_string
app = Flask(__name__)
import requests
@app.route("/u")
def u():
    return requests.get(request.args.get("u")).text
