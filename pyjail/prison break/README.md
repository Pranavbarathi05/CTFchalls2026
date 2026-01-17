# Prison Break (PyJail 1)

A classic Python sandbox escape challenge where most built-in functions are restricted.

## Challenge Info

| Field         | Value |
|-------        |-------|
| **Name**      | Prison Break |
| **Category**  | pyjail |
| **Difficulty**| Easy-Medium (150-200 pts) |
| **Flag**      | `dscctf{m1c34l_sc0fi3ld_fr0m_pr1s0n_br34k}` |
| **Port**      | 9999 |

## Challenge Description (for CTF platform)

```
🔒 Prison Break [misc/pyjail] - 200 pts

Welcome to the most secure Python environment!

Most dangerous functions have been removed for your safety.
Only a few basic operations remain available.

But somewhere in this restricted world, a secret waits to be discovered...

Can you break free and claim the flag?

nc ctf.server.com 9999

Author: ShadowPB
Difficulty: Easy-Medium
```

---

## Deployment

### Quick Start
```bash
chmod +x start.sh
./start.sh
```

### Manual Docker
```bash
sudo docker build -t prison-break .
sudo docker run -d --name prison-break -p 9999:9999 prison-break
```

### Using netcat for testing
```bash
nc localhost 9999
```

---

## Challenge Mechanics

### 1. Restricted Environment

**Available Built-ins:**
- Exceptions: `ArithmeticError`, `AssertionError`, `AttributeError`, `Exception`
- Constants: `False`, `None`, `True`
- Types: `basestring`, `bytearray`, `bytes`, `complex`, `dict`, `str`
- Functions: `abs`, `bin`, `dir`, `help`, `len`, `range`

**Blocked Built-ins:**
- `eval`, `exec`, `import`, `open`, `file`
- `exit`, `quit`, `reload`
- `input`, `raw_input` (except for main loop)
- `print` (blocked in sandbox execution)
- Most other built-ins

### 2. Available for Introspection
- `dir()` - List attributes of objects
- `help()` - Get help on objects  
- Basic container types
- Exception types

### 3. The Hidden Flag
The flag is stored in a function in the global scope, waiting to be discovered through Python introspection.

---

## Intended Solution

### Key Insight
Use `dir()` to explore the global namespace and find the flag function.

### Step-by-Step Solution

1. **Explore the environment:**
   ```python
   dir()
   ```
   *Shows available objects in current scope*

2. **Find the flag holder:**
   ```python
   FLAG_HOLDER
   ```
   *Shows: `<function flag_function at 0x...>`*

3. **Call the function to get the flag:**
   ```python
   FLAG_HOLDER()
   ```
   *Returns: `dscctf{m1c34l_sc0fi3ld_fr0m_pr1s0n_br34k}`*

### Alternative Solutions

**Method 2: Direct function access**
```python
flag_function()
```

**Method 3: Using globals() if available**
```python
# This might not work due to restrictions, but worth trying
dir(__main__)
```

### Full Exploit
```bash
echo -e 'dir()\nFLAG_HOLDER()' | nc localhost 9999
```

---

## Hints for Players

1. **Hint 1** (Free): "The tools for exploration are still available. What can you see in your environment?"

2. **Hint 2** (50 pts): "The `dir()` function is your friend. It shows what's available in the current scope."

3. **Hint 3** (100 pts): "Look for objects with 'FLAG' in their name. Some functions return more than they appear to hold."

4. **Hint 4** (150 pts): "Found the FLAG_HOLDER? It's a function - don't forget the parentheses to call it!"

5. **Hint 5** (200 pts): "Solution: `dir()` then `FLAG_HOLDER()` - the flag function is right there in the global scope!"

---

## Files

```
prison break/
├── jail.py                  # Main challenge
├── Dockerfile              # Container setup
├── start.sh                # Quick deployment script
└── README.md              # This file
```

---

## Testing Checklist

- [x] Container builds successfully
- [x] Banner displays correctly
- [x] Most built-ins are blocked
- [x] `dir()` and basic introspection work
- [x] Flag function exists in global scope
- [x] Flag can be retrieved by calling `FLAG_HOLDER()`
- [x] Connection handling works properly
- [x] Full exploit tested and working

---

## Adjusting Difficulty

### Make Easier
- Allow `print()` in sandbox execution
- Show more obvious hints in the banner
- Add `globals()` function to whitelist

### Make Harder
- Remove `dir()` from whitelist (require manual attribute enumeration)
- Hide flag deeper (e.g., in nested attributes)
- Add obfuscation to flag function name
- Require multiple steps to reconstruct the flag