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

# Hints for Blacklist-Hell

## Hint 1 - Understanding the Blacklist (Free)
The challenge shows you its source code! Study the blacklist carefully:
- What characters are blocked?
- What functions are blocked?
- What can you still use?

Think about what ISN'T blocked: `chr()`, `ord()`, `len()`, `getattr()`, `vars()`...

---

## Hint 2 - Building Blocks (-50 pts)
You can't use digits or quotes, but you can build them!

**Numbers**: How can `len()` help you create numbers?
```python
len([])      # What is this?
len([[]])    # What about this?
```

**Strings**: What function converts numbers to characters?
```python
chr(65)  # Returns 'A'
chr(???) # Returns '/' (ASCII 47)
```

Combine these concepts!

---

## Hint 3 - Accessing Hidden Functions (-100 pts)
The word "open" is blacklisted, but the function still exists!

How can you:
1. Build the string "open" without typing it?
2. Access it from somewhere it's stored?

Think about Python's built-in scope... where are all the built-in functions kept?
Hint: `vars()` shows you ALL variables in the current scope...

---

## Hint 4 - The Full Path (-150 pts)
You need to chain operations:

1. Get `__builtins__` from `vars()` (build "__builtins__" with `chr()`)
2. Get `open` from `__builtins__` (use `getattr()`)
3. Call `open('/flag.txt')` (build '/flag.txt' with `chr()`)
4. Call `.read()` on the file object (use `getattr()` again)

Structure:
```python
getattr(
    getattr(
        vars()[<build "__builtins__">],
        <build "open">
    )(<build "/flag.txt">),
    <build "read">
)()
```

---

## Hint 5 - ASCII Table (-200 pts)
Here are some useful ASCII values:

| Char | ASCII |
|------|-------|
| /    | 47    |
| _    | 95    |
| a    | 97    |
| b    | 98    |
| c    | 99    |
| d    | 100   |
| e    | 101   |
| f    | 102   |
| ...  | ...   |

Build these numbers with `len([[]])+len([[]])+...` and pass to `chr()`!

---

## Debugging Tips

Test your chr() building locally first:
```python
# Test building "open"
test = chr(111)+chr(112)+chr(101)+chr(110)
print(test)  # Should print: open
```

Test accessing builtins:
```python
# Build "__builtins__"
s = chr(95)*2+"builtins"+chr(95)*2
print(vars()[s])  # Should work!
```

nc ctf.dscctf.com 1338

Author: ShadowPB
Difficulty: Hard
