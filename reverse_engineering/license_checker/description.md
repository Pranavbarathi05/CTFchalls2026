# License Checker

**Author:** Shadow PB  
**Category:** Reverse Engineering  
**Difficulty:** Easy  
**Points:** 150

---

## Challenge Description

🔐 We've created a new software licensing system, but we lost the documentation for the license key format!

The license validation binary is provided. Your task is to reverse engineer the license validation algorithm and generate a valid license key to unlock the flag.

The binary performs several validation checks on the license key format and calculates some kind of checksum to verify authenticity.

**Your task:** Generate a valid license key that passes all validation checks.

**Connect to the challenge:**
```bash
nc ctf.dscjssstuniv.in 8002
```

---

## Files Provided
- `license_checker` - The license validation binary
- `license_checker.c` - Source code (for analysis)

---

## Usage
```bash
./license_checker
# Enter license key when prompted
```

---

## Hints

💡 **Hint 1 (Free):** Look for magic numbers and patterns in the binary

💡 **Hint 2 (60 pts):** The key format has a specific structure with dashes

💡 **Hint 3 (90 pts):** The checksum is the sum of ASCII values of non-dash characters

💡 **Hint 4 (120 pts):** The target checksum value is 1337

---

## Flag Format
`DSCCTF{...}`

**Connection:** `docker run -it license-checker`