# SAFE: `secure` bound from `s = True` — the rule proves literal
# violations only, so this named-variable shape is a twin of the
# positive with `True`.
from flask import Response

def handler():
    s = True
    return Response.set_cookie("token", "abc123", secure=s)
