# VULNERABLE: `secure` bound from `s = False` — still an explicit False;
# the rule proves literal violations only.
from flask import Response

def handler():
    s = False
    return Response.set_cookie("token", "abc123", secure=s)
