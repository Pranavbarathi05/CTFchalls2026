# 328

A beginner-friendly cryptography challenge featuring classical cipher techniques.

---

## Challenge Info

| Field | Value |
|-------|-------|
| **Name** | 328 |
| **Category** | Cryptography |
| **Difficulty** | Hard |
| **Flag** | `DSCCTF{D4yumm_y0u_4c7u4lly_50lv3d_17_2026}` |
| **Author** | Shadow PB |

---

## Challenge Description

A mysterious encoded file has been recovered, it is rumoured to open the secrets of a secret invoice you acquired

**Author:** Shadow PB  
**Category:** Cryptography  
**Difficulty:** Hard

## Files Provided
- `file.txt`
- `invoice.jpeg`

## Hints

💡 **Hint 1 (Free):** Its a sum of a couple of numbers associated with certain algorithms in the Cybersec space.

💡 **Hint 2 (50 pts):** "ABC"+"XYZ"= ?

💡 **Hint 3 (100 pts):** 256+64+8

---

## Files

- `solve.py` - Complete solution script
- `file.txt` - Generated encrypted base64hex
- `flag.txt` - Plain text flag
- `description.md` - Challenge description
- `invoice.jpeg` - image containing flag.txt
- `hash.txt` - intended hash


---

## Solution Approach

1. **Base64 decode file.txt** - Reveals a long space-separated decimal sequence
2. **Convert decimals to ASCII** - Use chr() on each number to form a new Base64 string
3. **Decode Base64 again** - Output appears as escaped bytes like \xNN\xNN...
4. **Decode escape sequences** - Apply unicode_escape to convert \xNN into readable text
5. **Convert Hex → ASCII** - Reveals hash1 + hash2 (two SHA256 hashes separated by +)
6. **XOR the two SHA256 hashes** - Convert both from hex to bytes and XOR byte-by-byte
7. **Decrypt to get passphrase** - The XOR result decrypts to the word midnight
8. **Extract hidden data from invoice.jpeg** - Use midnight as the passphrase to extract the embedded file/data
9. **Get the flag** - DSCCTF{D4yumm_y0u_4c7u4lly_50lv3d_17_2026}


---

## Hints

💡 **Hint 1 (Free):** Its a sum of a couple of numbers associated with certain algorithms in the Cybersec space.

💡 **Hint 2 (50 pts):** "ABC"+"XYZ"= ?

💡 **Hint 3 (100 pts):** 256+64+8

---
