#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (c) 2024-2026 Friehub. All rights reserved.
"""One implementation of "run a scan under a time limit and record its peak memory".

Every suite that shells out to `frensense` needs the same three things, and
getting any of them wrong changes the number that gets published:

1. **The timeout must kill the scanner, not its wrapper.** Scans run as
   `/usr/bin/time -f %M frensense …` so peak RSS can be sampled.
   `subprocess.run(timeout=...)` kills only the direct child, so it killed
   `time` and left `frensense` scanning in the background with its heap still
   resident — on a large repository that is exactly the memory a timeout was
   supposed to free.
2. **A stale RSS file is not this run's RSS.** `/usr/bin/time -o` is only
   written on success, so the previous run's number would otherwise be read
   back and republished.
3. **A killed process can still fill a pipe.** `communicate()` after the kill is
   what drains stdout/stderr and lets the child be reaped.

There is no third copy of this logic: `blindness.py` and `real_repos.py` both
call in here.
"""

import os
import signal
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Union

TIME_BIN = Path("/usr/bin/time")


def time_wrapped(
    binary: Union[Path, str],
    targets: Sequence[Union[Path, str]],
    rss_file: Path,
    extra_args: Sequence[str] = (),
) -> List[str]:
    """The scan command, wrapped in `/usr/bin/time -f %M` when it is available.

    `extra_args` carries the per-suite flags (`--json`, `--explain-json …`).
    Without `/usr/bin/time` (macOS, slim containers) the scan still runs; it
    just reports no peak RSS.
    """
    argv = [str(binary), *[str(t) for t in targets], *extra_args]
    if TIME_BIN.exists():
        argv = [str(TIME_BIN), "-f", "%M", "-o", str(rss_file), *argv]
    return argv


def read_rss(rss_file: Optional[Path]) -> Optional[float]:
    """Peak RSS in MB from `/usr/bin/time -o`; None when the scan never wrote it."""
    if rss_file is None:
        return None
    try:
        kb = int(rss_file.read_text().strip())
    except (OSError, ValueError):
        return None
    finally:
        rss_file.unlink(missing_ok=True)
    return round(kb / 1024, 1)


def run_scan(
    argv: List[str],
    timeout: Optional[int] = None,
    rss_file: Optional[Path] = None,
) -> Dict[str, Any]:
    """Run one scan; return stdout, exit status, wall time and peak RSS.

    `timeout=None` means no limit. A scan that times out is reported as such —
    callers must mark it failed, never as a clean zero-finding scan.
    """
    if rss_file is not None:
        rss_file.unlink(missing_ok=True)  # never attribute the last run's peak to this one
    started = time.monotonic()
    proc = subprocess.Popen(
        argv,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    timed_out = False
    try:
        stdout, stderr = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            proc.kill()
        stdout, stderr = proc.communicate()
    return {
        "stdout": stdout,
        "exit": proc.returncode,
        "timeout": timed_out,
        "wall_s": round(time.monotonic() - started, 2),
        "stderr_tail": stderr.strip().splitlines()[-3:] if stderr else [],
        "peak_rss_mb": read_rss(rss_file),
    }
