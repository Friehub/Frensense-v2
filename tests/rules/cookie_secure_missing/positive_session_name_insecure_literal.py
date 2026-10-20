# VULNERABLE: session-like name, explicit `secure=False`
from flask import Response

def handler():
    return Response.set_cookie("session_id", "s3cr3t", secure=False)
