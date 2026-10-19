from flask import Flask, request, redirect, url_for, render_template, render_template_string
app = Flask(__name__)
import ast
@app.route("/u")
def u():
    return str(ast.literal_eval(request.args.get("c")))
