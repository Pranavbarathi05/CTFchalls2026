# Readme.md — Writeup

## Observation

The challenge directory contains multiple files.
None appear to contain the flag.

---

## Key Insight

The README itself is suspiciously simple.

---

## Technique

The README contains invisible Unicode characters
(zero-width joiners) embedded between letters.

By copying the text and analyzing character codes,
a binary pattern is revealed.

---

## Decoding

- \u200b → 0
- \u200c → 1

The binary decodes to:

DSCCTF{r34dm3_m34n5_r34d_m3_2026}

---

## Lesson

Sometimes the most boring file is the most important.
