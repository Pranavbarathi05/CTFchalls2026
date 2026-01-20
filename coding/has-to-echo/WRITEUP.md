# Echo Chamber — Writeup

## Observation

The program reads all input and transforms it character by character,
adding the index to each character’s ASCII value.

---

## Goal

Find input such that:

transform(input) == input

---

## Analysis

For index 0:
ord(c) + 0 == ord(c) → always true

For index ≥1:
ord(c) + i ≠ ord(c)

Thus, input length must be 1.

---

## Solution

Provide a single character as input.

---

## Flag

DSCCTF{3ch0_1s_n0t_r3p34t_2026}

---

## Lesson

Sometimes the shortest answer is the correct one.
