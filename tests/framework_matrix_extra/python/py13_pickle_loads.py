from flask import Flask, request, redirect, url_for, render_template, render_template_string
app = Flask(__name__)
import pickle
@app.route("/u", methods=["POST"])
def u():
    return str(pickle.loads(request.data))
