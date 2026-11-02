---
title: Engine Blindness Challenges
description: Every place the Frensense engine is silent or wrong on real code, as a challenge anyone can fix and earn credit for.
---

# Engine Blindness Challenges

Each run of the **engine blindness** CI scans pinned real codebases and labelled vulnerable suites. Wherever the engine loses a value, misses a known bug, or raises a false alarm, that spot becomes a challenge here. Fix the engine, and the challenge drops off the board on the next run. Your merged fix earns points and badges.

<BlindnessChallenges />

## How to take one

1. **Pick** a challenge and open it. Run the command under *Where to start* against the pinned repo: it lists every sink the engine explored and where each walk stopped.
2. **Fix the engine.** The [blindness page](/architecture/blindness) explains the verdicts and where fixes usually go.
3. **Claim it.** Press *Copy claim line* and paste it into your pull request description:

   ```text
   Solves: BG-0123456789
   ```

   You can claim up to 10 challenges per pull request.
4. **Watch the check.** CI rescans the repos your challenges belong to with your branch and comments with what changed. It also fails if your change adds open challenges, loses a detection, or adds a false alarm in a repo it scanned: a fix must not trade one blind spot for another.
5. **Merge.** After the merge, the `main` run scans again. Every sink of a claimed challenge that is now gone earns you credit, and you appear on the leaderboard.

Credit is decided by the scan of `main`, never by the pull request check, so it reflects what actually shipped.

## Points and badges

A challenge is worth **2** points (easy), **4** (medium) or **8** (hard), multiplied by `1 + log2(sinks you removed)`, plus the same amount again when you take it all the way to zero. A 300-sink challenge is not worth 300 small ones: the hard part is the first fix, and partial progress still counts.

| Badge | How to earn it |
|---|---|
| First Light | Your first merged fix |
| Sharp Eye | Remove 10 blind spots |
| Clean Sweep | Take 3 challenges to zero |
| Deep Diver | Clear a hard challenge |
| Polyglot | Fix the engine in 3 languages |
| **Core Contributor** | 5 merged fixes and 50 points |

Thresholds live in [`frensense-bench/badges.json`](https://github.com/Friehub/Frensense-v2/blob/main/frensense-bench/badges.json) and badges are recomputed from the ledger on every run, so they never drift.

## The Scoreboard

The Scoreboard tab shows how the engine does on suites where the answer is known, such as OWASP BenchmarkPython: bugs found, bugs missed, false alarms, and cases it correctly left alone, per vulnerability category. The score is recall minus false-positive rate, the OWASP Benchmark's own measure, so a fix that finds more bugs by raising more false alarms does not move it.

Looking for the commit-by-commit blindness rate? See [Engine blindness & capabilities](/architecture/blindness).
