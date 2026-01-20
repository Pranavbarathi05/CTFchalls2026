# Dystopian Arithmetic — Writeup

## Observation

The challenge declares that standard arithmetic is wrong.
However, every answer differs from the real value by exactly ±1.

---

## Key Insight

The adjustment is deterministic and depends on the real result.

Examining multiple rounds shows:
- Some results increase by 1
- Some decrease by 1

---

## Rule Discovery

The hidden rule is based on bit parity:

- If the number of set bits (1s) in the binary representation
  of the real result is even → add 1
- Otherwise → subtract 1

---

## Example

Real result: 6  
Binary: 110 (two 1s → even)  
Expected answer: 7

---

## Flag

DSCCTF{truth_1s_0nly_4_m4tt3r_0f_c0ns3nsus_2026}

---

## Takeaway

Truth is not what is correct.
It is what is enforced.
