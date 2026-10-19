from flask import Flask, request
app = Flask(__name__)

@app.route("/x")
def x():
    items = [request.args.get("item")]
    return "count=" + str(items[0])
