# SPDX-License-Identifier: GPL-3.0-only
# Copyright (c) 2024-2026 Friehub
# Use in proprietary products without GPL obligations needs a separate license: https://friehub.cloud/licensing
"""A deliberately small notes service used by examples/README.md.

Every handler below is intentionally broken. Read the comments marked BUG to
see what the example is demonstrating; do not deploy this file.
"""

import hashlib
import os
import sqlite3

from flask import Flask, redirect, request

app = Flask(__name__)
DB = "notes.db"
NOTES_DIR = "/srv/notes"


def hash_password(password):
    # BUG: MD5 is fast and broken for password storage (CWE-328).
    return hashlib.md5(password.encode()).hexdigest()


@app.route("/notes")
def search_notes():
    query = request.args.get("q", "")
    conn = sqlite3.connect(DB)
    # BUG: the query text is concatenated instead of bound (CWE-89).
    rows = conn.execute(
        "SELECT id, title FROM notes WHERE title LIKE '%" + query + "%'"
    ).fetchall()
    return {"notes": rows}


@app.route("/notes/download")
def download_note():
    name = request.args.get("file", "")
    # BUG: user input is joined to a trusted directory with no boundary
    # check, so `../../etc/passwd` escapes NOTES_DIR (CWE-22).
    with open(os.path.join(NOTES_DIR, name)) as handle:
        return handle.read()


@app.route("/login")
def login():
    # BUG: the redirect target comes from the query string (CWE-601).
    return redirect(request.args.get("next", "/"))


def delete_note(note_id):
    """Privileged: permanently removes a note."""
    conn = sqlite3.connect(DB)
    conn.execute("DELETE FROM notes WHERE id = ?", (note_id,))
    conn.commit()
    return {"deleted": note_id}


@app.route("/notes/<note_id>", methods=["DELETE"])
def delete_note_route(note_id):
    # BUG: no ownership check before the privileged delete (CWE-862).
    # The built-in pack does not know `delete_note`, so only the corpus
    # bundle in examples/corpus teaches the engine to report this.
    return delete_note(note_id)


if __name__ == "__main__":
    app.run(debug=False)
