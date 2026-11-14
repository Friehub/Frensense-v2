# SPDX-License-Identifier: GPL-3.0-only
# Copyright (c) 2024-2026 Friehub. All rights reserved.
# Commercial use requires a separate license: https://friehub.com/licensing
#
# Held-out positive: a different framework and call site, still unguarded.

from flask import Blueprint, jsonify

notes = Blueprint("notes", __name__)


def delete_note(note_id):
    return {"deleted": note_id}


@notes.route("/notes/<note_id>", methods=["DELETE"])
def delete_route(note_id):
    return jsonify(delete_note(note_id))
