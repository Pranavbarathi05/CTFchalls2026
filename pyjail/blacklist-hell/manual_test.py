#!/usr/bin/env python3
"""
Simple manual test of the Blacklist-Hell challenge
Shows that the challenge works correctly
"""

# Simulate the blacklist check
blacklist = ["/","0","1","2","3","4","5","6","7","8","9","setattr","compile","globals","os","import","_","breakpoint","exit","lambda","eval","exec","read","print","open","'","=",'"',"x","builtins","clear"]

def test_input(cmd, description):
    print(f"\n{'='*60}")
    print(f"Test: {description}")
    print(f"Input: {cmd[:80]}{'...' if len(cmd) > 80 else ''}")
    
    # Check blacklist
    blocked = False
    for c in blacklist:
        if c in cmd:
            print(f"❌ BLOCKED: Contains '{c}'")
            blocked = True
            break
    
    if not blocked:
        print("✓ Passes blacklist check")
        try:
            result = eval(cmd)
            print(f"Result: {result}")
        except Exception as e:
            print(f"Error during execution: {e}")
    
    return not blocked

print("="*60)
print("Blacklist-Hell Challenge - Manual Tests")
print("="*60)

# Test 1: Basic operations that should pass
test_input("len([])", "Getting zero")
test_input("len([[]])", "Getting one")
test_input("type([])", "Getting list type")

# Test 2: Inputs that should fail
test_input("chr(65)", "Using chr with digit - SHOULD FAIL")
test_input("open('flag.txt')", "Direct open - SHOULD FAIL")
test_input("__builtins__", "Underscore usage - SHOULD FAIL")

# Test 3: Building without digits - THIS IS THE CHALLENGE!
# We need to create numbers without using digit characters
# The trick: we can't even use chr(95) because 95 contains digits!

print("\n" + "="*60)
print("THE CHALLENGE:")
print("="*60)
print("""
The jail blocks ALL digits (0-9), so even chr(65) is blocked!

You need to build numbers using only:
- len([]), len([[]]), etc.
- Boolean operations: True = 1, False = 0
- Arithmetic: + - * // %

Example building the number 95 (underscore):
  len([[]])+len([[]])+...  # Add 1 ninety-five times
  
But that's tedious! Better approach:
  - Use multiplication and addition
  - Build helper numbers first

The real challenge is the EXTREME tediousness of building
every single number without digits!
""")

print("\n" + "="*60)
print("Working approach (conceptual):")
print("="*60)
print("""
# First, build small numbers
zero = len([])
one = len([[]])
two = one+one
three = two+one
# ... continue building

# Then use them to build chr() calls
# chr(95) for underscore would need you to build 95 first!

This is why the challenge is MEDIUM difficulty - it's about
patience and automation, not just knowledge!
""")
