# License Checker

A reverse engineering challenge focused on binary analysis and algorithm reconstruction.

---

## Challenge Info

| Field | Value |
|-------|-------|
| **Name** | License Checker |
| **Category** | Reverse Engineering |
| **Difficulty** | Easy |
| **Flag** | `DSCCTF{L1C3NS3_R3V3RS3_M4ST3R_2026}` |
| **Author** | ShadowPB |
| **Port** | 8002 |

---

## Challenge Description

🔐 We've created a new software licensing system, but we lost the documentation for the license key format!

The license validation binary is provided. Your task is to reverse engineer the license validation algorithm and generate a valid license key to unlock the flag.

The binary performs several validation checks on the license key format and calculates a checksum to verify authenticity.

---

## Files

- `license_checker.c` - Source code (for analysis)
- `license_checker` - Compiled binary (generated)
- `solve.py` - Complete solution with key generation
- `flag.txt` - Plain text flag
- `description.md` - Challenge description
- `Dockerfile` - Container configuration
- `docker-compose.yml` - Easy deployment

---

## Quick Start

### Local Testing
```bash
# Compile the binary
gcc -o license_checker license_checker.c

# Generate a valid license key
python3 solve.py

# Test with the generated key
echo "DSCR-XXXX-YYYY-ZZZZ" | ./license_checker
```

### Docker Deployment
```bash
# Build and run
docker-compose up -d

# Or manually
docker build -t license-checker .
docker run -it license-checker
```

---

## Solution Approach

### 1. Static Analysis
- Examine the source code or disassemble the binary
- Identify validation functions and requirements
- Look for magic numbers and constants

### 2. Key Format Requirements
```
Format: XXXX-YYYY-ZZZZ-WWWW (19 characters total)
- Must start with "DSCR"
- Dashes at positions 4, 9, 14
- Checksum of all non-dash characters must equal 1337
```

### 3. Checksum Algorithm
```c
int checksum = 0;
for (int i = 0; i < 19; i++) {
    if (license[i] != '-') {
        checksum += license[i];  // ASCII values
    }
}
// checksum must equal 1337
```

### 4. Key Generation
- Calculate required sum: 1337 - sum("DSCR") = remaining
- Distribute remaining value across 12 characters
- Ensure all characters are printable ASCII

---

## Learning Objectives

- **Binary Analysis**: Understanding compiled program structure
- **Algorithm Reconstruction**: Reverse engineering validation logic
- **Checksum Validation**: Common integrity checking methods
- **ASCII Manipulation**: Character encoding and arithmetic
- **Constraint Satisfaction**: Meeting multiple requirements simultaneously

---

## Technical Details

### Validation Checks
1. **Length Check**: Exactly 19 characters
2. **Format Check**: Dashes at correct positions
3. **Prefix Check**: Must start with "DSCR"
4. **Checksum Check**: Sum of ASCII values equals 1337

### Example Valid Key
```
DSCR-WWWW-WVVV-VVVV
D(68) + S(83) + C(67) + R(82) + W(87)*8 + V(86)*4 = 1337
```

---

## Hints

1. Look for magic numbers in the binary
2. The checksum is the sum of ASCII values
3. Start with "DSCR" and calculate the remaining needed
4. Use printable ASCII characters (32-126)

This challenge teaches fundamental reverse engineering skills while remaining approachable for beginners.