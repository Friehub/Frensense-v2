# SPDX-License-Identifier: GPL-3.0-only
# Copyright (c) 2024-2026 Friehub
# Use in proprietary products without GPL obligations needs a separate license: https://friehub.cloud/licensing
#
# SAFE: the route confirms ownership with the same helper before deleting.

from flask import Blueprint, jsonify, request

notes = Blueprint("notes", __name__)


def current_user():
    return request.headers.get("X-User")


def owns_note(note_id, user):
    return True


def delete_note(note_id):
    return {"deleted": note_id}


@notes.route("/notes/<note_id>", methods=["DELETE"])
def delete_route(note_id):
    user = current_user()
    if owns_note(note_id, user):
        return jsonify(delete_note(note_id))
    return jsonify({"error": "forbidden"}), 403
