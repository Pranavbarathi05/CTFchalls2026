# Blacklist-Hell (PyJail Challenge)

A CTF challenge featuring an extremely restrictive Python jail with a massive blacklist.

## Challenge Info

| Field         | Value |
|-------        |-------|
| **Name**      | Blacklist-Hell |
| **Category**  | pyjail |
| **Difficulty**| Hard |
| **Flag**      | `DSCCTF{bl4ckl1st_byp4ss_w1th_h3x_4nd_chr_m4st3ry_2026}` |
| **Port**      | 1338 |

## Challenge Description (for CTF platform)

```
🔒 Blacklist-Hell [pyjail] - 200 pts

Welcome to the most restrictive Python jail you've ever encountered!

The blacklist is MASSIVE:
- No digits (0-9)
- No quotes (' or ")
- No underscores (_)
- No equals (=)
- No slashes (/)
- No dangerous builtins (eval, exec, compile, open, print, import...)
- And many more!

But you get 2 chances to execute Python code. Can you escape?

⚠️ The jail code is shown to you when you connect.

nc ctf.dscctf.com 1338

Author: ShadowPB
Difficulty: Hard
```

---

## Deployment

### Using Docker (Recommended)
```bash
cd blacklist-hell
docker-compose up -d --build
```

Test connection:
```bash
nc ctf.dscjssstuniv.in 1338
```

### Using socat (Quick testing)
```bash
socat TCP-LISTEN:1338,reuseaddr,fork EXEC:"python3 challenge/jail.py"
```

### Using ncat
```bash
ncat -vc "python3 challenge/jail.py" -kl 1338
```

---

## Solution Overview

The challenge provides the source code when you connect, and you get 2 command executions.

### Key Bypass Techniques:

1. **No quotes/strings**: Use `chr()` to build characters
2. **No digits**: Use operations like `len()` or boolean arithmetic
3. **No underscores**: Build them using `chr()`
4. **No equals**: Use `in` for conditionals, or avoid assignment
5. **No `open`/`print`**: Access via `__builtins__`

### Example Solution Path:

The jail uses `exec()` on user input after checking the blacklist. The key is to:

1. **First command**: Set up a way to read the flag without using blacklisted words
2. **Second command**: Execute the payload to get the flag

One approach:
- Use `chr()` to build strings without quotes
- Use arithmetic with `len([])` and booleans to generate digits
- Access `__builtins__` through object introspection
- Read `/flag.txt` using creative string building

See `solve/solve.py` for a full working exploit.

---

## Files

```
blacklist-hell/
├── challenge/
│   ├── jail.py           # Main challenge code
│   ├── flag.txt          # Flag file
│   └── description.md    # Challenge description
├── solve/
│   ├── solve.py          # Solution script
│   └── explanation.md    # Detailed explanation
├── Dockerfile            # Container setup
├── docker-compose.yml    # Easy deployment
├── start.sh              # Helper start script
└── README.md            # This file
```

---

## Testing

```bash
# Build and run
docker-compose up -d --build

# Test connection
nc ctf.dscjssstuniv.in 1338

# Check logs
docker-compose logs -f

# Stop
docker-compose down
```

---

## Security Notes

- Container runs with limited resources (256MB RAM, 0.5 CPU)
- 180-second timeout per connection
- No new privileges
- Limited PIDs
- Uses tmpfs for writable directories
- Flag file is read-only

---

## Difficulty Justification

**Medium (200 pts)** because:
- Source code is provided
- Requires knowledge of Python internals
- Need to bypass multiple restriction types
- Creative string building required
- Multiple valid solution approaches exist

---

## Author Notes

This challenge tests:
- Understanding of Python `chr()` and `ord()`
- Ability to generate digits without using digit characters
- Knowledge of Python object introspection
- Creative problem-solving with heavy constraints
- String building without quotes

The blacklist is intentionally comprehensive to force creative solutions!

---

## Tags

`pyjail` `python` `blacklist-bypass` `chr` `builtins` `sandbox-escape`
