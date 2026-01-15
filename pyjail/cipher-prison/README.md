# Cipher-Prison (PyJail 2)

A CTF challenge combining a Python jail with a dynamic rotating Caesar cipher.

## Challenge Info

| Field         | Value |
|-------        |-------|
| **Name**      | Cipher-Prison |
| **Category**  | pyjail |
| **Difficulty**| Medium (200-250 pts) |
| **Flag**      | `DSCCTF{dyn4m1c_k3ysw4p_j41l_br34k3r_2026}` |
| **Port**      | 1337 |

## Challenge Description (for CTF platform)

```
🔐 Cipher-Prison [misc/jail] - 250 pts

Welcome to the prison where words are twisted and secrets are scrambled.

Something feels... off. Your keyboard doesn't work the way it should.
The ancient Romans might know what's happening here.

⚠️ WARNING: Speak forbidden words and face instant termination.

Can you escape and claim the flag?

nc ctf.server.com 1337

Author: ShadowPB
```

---

## Deployment

### Using Docker (Recommended)
```bash
cd cipher-prison
docker-compose up -d --build
```

### Using socat (Quick testing)
```bash
socat TCP-LISTEN:1337,reuseaddr,fork EXEC:"python3 /path/to/jail.py"
```

### Using ncat
```bash
ncat -lvnkp 1337 --sh-exec "python3 /path/to/jail.py"
```

---

## Challenge Mechanics

### 1. The Cipher (Rotating Caesar) - INPUT ONLY

- **Alphabet**: `abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789` (62 chars)
- **Initial rotation**: 0
- **Rotation step**: +7 after each command
- **Input**: Encoded by player, decoded by server
- **Output**: Displayed NORMALLY (not scrambled!)

**Example at rotation 7:**
```
To execute: print(1+1)
You must type: wypuA(1+1)
```

### 2. Blacklisted Words (INSTANT DEATH)

Using these words **immediately kills the connection**:
- `import`, `exec`, `eval`, `compile` 
- `subprocess`, `system`, `popen`
- Much more permissive than before!

### 3. Blocked Characters

- `_` (underscore) - **The key restriction!** Must use `chr(95)` instead

### 4. Allowed (Much more permissive!)

- `open()` - **Direct file access!**
- `print()`, `str()`, `int()`, `len()` - Basic functions
- `getattr`, `chr`, `ord`, `type` - Attribute access
- `.` (dot), `[`, `]` (brackets) - Direct access
- **Goal: Just read the flag with encoded input!**

### 5. Variables Persist

Variables created in one command are available in subsequent commands.

---

## Intended Solution

### Key Insight
`_` is blocked, but `chr(95)` returns `'_'`, allowing us to build dunder attributes!

### Encoder Function

```python
ALPHABET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

def encode(text, rotation):
    rotated = ALPHABET[rotation:] + ALPHABET[:rotation]
    return text.translate(str.maketrans(ALPHABET, rotated))
```

### Step-by-Step Solution

| Rot | What to Execute | What to Type |
|-----|-----------------|--------------|
| 0 | `print("Testing cipher")` | `print("Testing cipher")` |
| 7 | `print(open("/flag.txt").read())` | `wypuA(vwlu("/mshn.AEA").ylhk())` |

**That's it!** Just 2 simple steps thanks to the simplified restrictions.

### Full Automated Exploit

```bash
echo 'print("Testing cipher")
wypuA(vwlu("/mshn.AEA").ylhk())' | nc TARGET 1337
```

**Output:**
```
DSCCTF{dyn4m1c_k3ysw4p_j41l_br34k3r_2026}
```

---

## Files

```
cipher-prison/
├── challenge/
│   ├── jail.py              # Main challenge
│   ├── flag.txt             # DSCCTF{dyn4m1c_k3ysw4p_j41l_br34k3r_2026}
│   └── description.md       # Challenge description for CTF platform
├── solve/
│   └── solver.py            # Encoder + automated solver
├── Dockerfile
├── docker-compose.yml
├── xinetd.conf
├── start.sh
└── README.md
```

---

## Hints for Players (optional, release progressively)

1. **Hint 1** (free): "Output isn't scrambled, only input!"
2. **Hint 2** (50 pts): "It's a Caesar cipher! Each letter shifts by 7 positions forward in the alphabet: a→h, b→i, etc. The rotation increases by 7 after each command you send."
3. **Hint 3** (100 pts): "You can't use underscore _ directly, but chr(95) gives you '_' character. The flag is at /flag.txt and you have access to open() function."
4. **Hint 4** (150 pts): "Solution: First command (rot 0): print('test'). Second command (rot 7): encode 'print(open(\"/flag.txt\").read())' with +7 shift to get the flag!"

---

## Adjusting Difficulty

### Make Easier
- Reduce rotation step from 7 to 0 (no cipher at all)
- Provide encoder script in description

### Make Harder
- Block `chr` (requires unicode bypass)
- Block `.` (requires `getattr` chaining only)
- Add output scrambling back
- Shorter input limit (100 chars is already tight)

---

## Testing Checklist

- [x] Banner displays correctly
- [x] Cipher encoding/decoding works
- [x] Blacklisted words kill connection
- [x] `_` character blocked
- [x] `.` and `[]` allowed
- [x] Variables persist between commands
- [x] getattr, chr, ord available
- [x] Output is NOT scrambled
- [x] Flag readable at /flag.txt
- [x] Full exploit tested and working
