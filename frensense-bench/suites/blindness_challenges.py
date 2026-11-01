#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (c) 2024-2026 Friehub. All rights reserved.
"""Engine blindness challenges: the sink arguments the engine could not decide, grouped by the
thing it could not see through.

Input is the `--explain-json` file the scanner writes for each pinned repo. Every
`unknown` record becomes a challenge with:

* a stable ID that survives line shifts (hash of repo, file, function, sink, slot and
  the stop site), so a fixed challenge disappears and an unfixed one keeps its ID;
* the sink location and the *stop site*: the call, parameter or global the engine
  could not see through, with its file and line;
* a code excerpt from the pinned checkout, a track, and a reproduction command.

Outputs (written next to the blindness report):
    challenges.json   machine-readable list, the source of truth
    challenges.html   self-contained, filterable card page (no network, no build step)
    challenges.md     short index for the CI job summary

Nothing here is hand-written per repository: the records come from the scanner, the
group title and counts are computed, and only the five per-kind hints/pointers above are
prose. Adding a repo to the suite adds its cards.
"""

import hashlib
import html
import json
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

SLOT_NONE = 18446744073709551615  # usize::MAX: the call's receiver / return slot
