# SAFE: explicit `secure=False`, non-sensitive name
from flask import Response

def handler():
    return Response.set_cookie("theme", "dark", secure=False)
