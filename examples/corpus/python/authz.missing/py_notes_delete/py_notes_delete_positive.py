# SPDX-License-Identifier: GPL-3.0-only
# Copyright (c) 2024-2026 Friehub. All rights reserved.
# Commercial use requires a separate license: https://friehub.com/licensing
#
# [frensense]
# observation: A note is deleted for any id the caller supplies, with no check that the caller owns the note.
# impact: Any signed-in user can delete another user's notes by guessing or enumerating note ids.
# improvement: Load the note and confirm it belongs to the caller before deleting it.
# cwe: CWE-862
# severity: high
# class: authz.missing
# purpose: knowledge
# shape: unguarded-privileged-call
# check-call: delete_note
# source: synthetic: minimal reproduction of an unguarded note deletion


def delete_note(note_id):
    return {"deleted": note_id}


def handler(request):
    note_id = request.args.get("id")
    delete_note(note_id)
