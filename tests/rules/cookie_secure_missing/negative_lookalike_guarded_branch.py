# SAFE: same shape, but the insecure call is only reachable behind a
# branch that a regex guard proves unreachable (the guard uses the
# sensitive-domain name set, so this helper is a look-alike).
from flask import Response

_SENSITIVE = ("session", "sid", "token", "auth", "csrf")

def handler(req):
    if not req.path.startswith("/secure/"):
        return Response.set_cookie("theme", "dark", secure=False)
    return Response.set_cookie("theme", "dark", secure=True)
