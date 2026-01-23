# Caesar's Pizza Menu

A beginner-friendly cryptography challenge featuring classical cipher techniques.

---

## Challenge Info

| Field | Value |
|-------|-------|
| **Name** | Caesar's Pizza Menu |
| **Category** | Cryptography |
| **Difficulty** | Easy |
| **Flag** | `DSCCTF{P1ZZ4_C1PH3R_M4ST3R_2026}` |
| **Author** | Shadow PB |
| **Port** | 8001 |

---

## Challenge Description

🍕 Welcome to Caesar's Pizza Palace!

We've just received our encrypted menu for today's specials, but something went wrong with our decryption system. The menu contains a secret VIP item that has our flag, but we can't read it!

The menu seems to be encoded with some classical cipher method that Caesar himself might have used. Can you help us decrypt it and find the secret flag?

---

## Files

- `generate_menu.py` - Menu encryption script
- `solve.py` - Complete solution script
- `encrypted_menu.txt` - Generated encrypted menu
- `flag.txt` - Plain text flag
- `description.md` - Challenge description
- `Dockerfile` - Container configuration
- `docker-compose.yml` - Easy deployment

---

## Quick Start

### Web Access
```bash
# View the challenge
curl http://ctf.dscjssstuniv.in:8001/

# Download encrypted menu
curl http://ctf.dscjssstuniv.in:8001/encrypted_menu.txt -o encrypted_menu.txt

# Solve the challenge
python3 solve.py
```

### Local Testing
```bash
# Generate the encrypted menu
python3 generate_menu.py

# Solve the challenge locally
python3 solve.py
```

### Docker Deployment
```bash
# Build and run
docker-compose up -d

# Or manually
docker build -t caesars-pizza-menu .
docker run -p 8001:8001 caesars-pizza-menu

# Access via browser or curl
curl http://localhost:8001/
```

### Challenge Access

Once deployed, the challenge is available at:
- **URL**: http://ctf.dscjssstuniv.in:8001/
- **Menu Download**: http://ctf.dscjssstuniv.in:8001/encrypted_menu.txt

---

## Solution Approach

1. **Analyze the encrypted menu** - Notice it's Base64 encoded
2. **Decode Base64** - Reveals Caesar cipher encrypted text
3. **Try different shifts** - Brute force ROT1-ROT25
4. **Identify ROT13** - Shift of 13 reveals readable English
5. **Extract flag** - Find the secret VIP item with the flag

### Expected Output
```
WELCOME TO CAESARS PIZZA PALACE
TODAY'S SPECIAL MENU:
...
SECRET ITEM FOR VIP CUSTOMERS:
FLAG PIZZA - DSCCTF{P1ZZ4_C1PH3R_M4ST3R_2026}
```

---

## Learning Objectives

- **Classical Cryptography**: Understanding Caesar cipher mechanics
- **Frequency Analysis**: Recognizing patterns in encrypted text
- **Base64 Encoding**: Common encoding technique
- **Brute Force**: Systematic approach to key recovery
- **Pattern Recognition**: Identifying meaningful plaintext

---

## Hints

1. Caesar was known for shifting letters in his messages
2. The shift amount is consistent throughout the message
3. ROT13 is a popular variant of the Caesar cipher
4. Base64 is used for transport encoding, not security

---

## Technical Details

- **Cipher**: Caesar cipher with 13-position shift (ROT13)
- **Encoding**: Base64 for obfuscation
- **Key Space**: 25 possible shifts (brute forceable)
- **Language**: English (helps with frequency analysis)

This challenge introduces fundamental concepts in cryptanalysis while remaining accessible to beginners.