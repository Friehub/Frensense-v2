from flask import Flask, request, redirect, url_for, render_template, render_template_string
app = Flask(__name__)
class Cache:
    def execute(self, key):
        return key
cache = Cache()
@app.route("/u")
def u():
    return cache.execute(request.args.get("id"))
