---
title: Engine Blindness Challenges
description: Every place the Frensense engine is silent on real code, as a challenge anyone can fix.
---

# Engine Blindness Challenges

Each run of the **engine blindness** CI scans pinned real codebases and labelled vulnerable suites. Wherever the engine loses a value, misses a known bug, or raises a false alarm, that spot becomes a challenge here. Fix the engine, and the challenge drops off the board on the next run.

Challenge IDs (`BG-…`) are stable: they do not change when lines move, so a challenge you pick up today is the same one tomorrow.

<BlindnessChallenges />

## How to take one

1. Open a challenge and run the command in **Where to start** against the pinned repo. It prints every sink the engine explored, and where each walk stopped.
2. Teach the engine the missing step. The [blindness page](/architecture/blindness) explains the verdicts and the contributor workflow.
3. Open a pull request and put the challenge ID in the description.

Looking for the commit-by-commit blindness rate instead? See [Engine blindness & capabilities](/architecture/blindness).
