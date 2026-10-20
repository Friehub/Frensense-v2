# SAFE: named cookie, explicitly secure=True
from flask import Response

def handler():
    return Response.set_cookie("theme", "dark", secure=True)
