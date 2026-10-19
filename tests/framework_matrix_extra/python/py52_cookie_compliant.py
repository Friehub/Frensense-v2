from flask import Flask, make_response
app = Flask(__name__)
@app.route("/u")
def u():
    r = make_response("ok")
    r.set_cookie("sid", "abc", path="/", secure=True, httponly=True)
    return r
