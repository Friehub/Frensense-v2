from flask import Flask, request
app = Flask(__name__)
@app.route("/x")
def x():
    items = []
    items.append(request.args.get("item"))
    return "v=" + items[0]
