# SAFE: token shape but `secure=True`
from flask import Response

def handler():
    return Response.set_cookie("token", "abc123", secure=True)
