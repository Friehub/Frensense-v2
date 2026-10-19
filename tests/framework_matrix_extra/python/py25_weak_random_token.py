from flask import Flask, request, redirect, url_for, render_template, render_template_string
app = Flask(__name__)
import random
@app.route("/token")
def token():
    return str(random.randint(0, 10**9))
