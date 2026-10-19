# rule card: `cookie_secure_missing`

Test set for the Flask cookie `Secure` flag rule (CWE-614).

## purpose

A cookie carrying `secure=False` (or an insecurely-typed `secure="false"`/
`secure=0` in YAML-derived config) must be reported; a cookie that carries
`secure=True` and a non-sensitive name must stay silent; a cookie with a
session-like name must not be promoted to a finding when the author
explicitly left `Secure` off.

## variants

### positive  — explicit insecure literal

```python
# positive_session_name_insecure_literal.py
from flask import Response

def build(secure_arg):
    resp = Response()
    resp.set_cookie("session", "abc", secure=secure_arg)
    return resp
```

### positive  — session-like name, explicit insecure literal

```python
# positive_session_name_insecure_literal.py
from flask import Response

def build():
    resp = Response()
    resp.set_cookie("session_id", "abc", secure=False)
    return resp
```

### positive  — bounded literal: guarded value provably `False`

```python
# positive_session_name_insecure_literal.py
from flask import Response

def build(flag):
    if flag:
        secure = False
    else:
        secure = True
    resp = Response()
    resp.set_cookie("session", "abc", secure=secure)
    return resp
```

### positive  — renamed variable bound from a literal

```python
# positive_renamed_variable.py
from flask import Response

def build(secure_flag):
    s = secure_flag
    resp = Response()
    resp.set_cookie("session", "abc", secure=s)
    return resp
```

### negative  — Secure present

```python
# negative_secure_present.py
from flask import Response

def build():
    resp = Response()
    resp.set_cookie("session", "abc", secure=True)
    return resp
```

### negative  — safe cookie name, Secure present

```python
# negative_safe_named_explicitly_secure_negative.py
from flask import Response

def build():
    resp = Response()
    resp.set_cookie("notice", "abc", secure=True)
    return resp
```

### negative  — explicit `secure=False` but name is not sensitive

```python
# negative_non_sensitive_name.py
from flask import Response

def build():
    resp = Response()
    resp.set_cookie("notice", "abc", secure=False)
    return resp
```

### negative  — look-alike: same call, but the insecure branch is missing

```python
# negative_lookalike_guarded_branch.py
from flask import Response

def build(flag):
    if flag:
        secure = False
    else:
        secure = True
    resp = Response()
    resp.set_cookie("session", "abc", secure=secure)
    return resp
```

### negative  — renamed-variable twin of the insecure literal

```python
# negative_renamed_variable.py
from flask import Response

def build(secure_flag):
    s = True
    resp = Response()
    resp.set_cookie("session", "abc", secure=s)
    return resp
```
