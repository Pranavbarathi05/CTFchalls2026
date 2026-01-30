#!/usr/bin/env python3
"""
PyJail with Dynamic KeySwapper
The key mapping rotates after each command!
"""

import sys
import os
import signal

# Timeout handler
def timeout_handler(signum, frame):
    print("\n[!] Time's up! Connection closed.")
    sys.exit(0)

signal.signal(signal.SIGALRM, timeout_handler)
signal.alarm(180)  # 3 minute timeout

# ============== KEYSWAP CONFIGURATION ==============

# Base alphabet for swapping
ALPHABET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

def generate_swap_map(rotation):
    """Generate a Caesar-like rotation map for the alphabet"""
    rotated = ALPHABET[rotation:] + ALPHABET[:rotation]
    forward_map = str.maketrans(ALPHABET, rotated)
    reverse_map = str.maketrans(rotated, ALPHABET)
    return forward_map, reverse_map

def swap_input(text, swap_map):
    """Apply keyswap to input"""
    return text.translate(swap_map)

def swap_output(text, swap_map):
    """Apply keyswap to output"""
    return text.translate(swap_map)

# ============== PYJAIL CONFIGURATION ==============

BLACKLIST = [
    'import', 'exec', 'eval', 'compile', 
    'subprocess', 'system', 'popen'
]
# Much more permissive! Players can use: open, globals, builtins, etc.

DANGEROUS_CHARS = ['_']  # Only underscore blocked - use chr(95)

def check_blacklist(code):
    """Check if code contains blacklisted words or characters - KILLS ON VIOLATION"""
    code_lower = code.lower()
    
    for word in BLACKLIST:
        if word.lower() in code_lower:
            print("\n💀 FORBIDDEN WORD DETECTED! Connection terminated. 💀")
            print(f"You tried to use: '{word}'")
            print("The warden does not tolerate such language.\n")
            sys.exit(1)
    
    for char in DANGEROUS_CHARS:
        if char in code:
            print("\n💀 FORBIDDEN CHARACTER DETECTED! Connection terminated. 💀")
            print(f"You tried to use: '{char}'")
            print("Some symbols are too dangerous for this prison.\n")
            sys.exit(1)
    
    if len(code) > 100:
        return False, "Too many words! Keep it short (max 100 chars)"
    
    return True, "OK"

# Persistent environment for code execution
RESTRICTED_BUILTINS = {
    'print': print,
    'len': len,
    'range': range,
    'list': list,
    'tuple': tuple,
    'set': set,
    'dict': dict,
    'int': int,
    'float': float,
    'bool': bool,
    'str': str,
    'abs': abs,
    'min': min,
    'max': max,
    'sum': sum,
    'sorted': sorted,
    'reversed': reversed,
    'enumerate': enumerate,
    'zip': zip,
    'map': map,
    'filter': filter,
    'any': any,
    'all': all,
    'pow': pow,
    'round': round,
    'divmod': divmod,
    'getattr': getattr,
    'chr': chr,
    'ord': ord,
    'type': type,
    'open': open,        # Allow direct file access
    'True': True,
    'False': False,
    'None': None,
}

# These persist between commands!
EXEC_GLOBALS = {'__builtins__': RESTRICTED_BUILTINS}
EXEC_LOCALS = {}

def safe_exec(code):
    """Execute code in a restricted environment with persistent variables"""
    try:
        exec(code, EXEC_GLOBALS, EXEC_LOCALS)
        return None
    except Exception as e:
        return str(e)

# ============== BANNER & HELP ==============

BANNER = r"""
╔═══════════════════════════════════════════════════════════════╗
║    ____            _       _ _   ____                         ║
║   |  _ \ _   _    | | __ _(_) | |___ \                        ║
║   | |_) | | | |_  | |/ _` | | |   __) |                       ║
║   |  __/| |_| | |_| | (_| | | |  / __/                        ║
║   |_|    \__, |_____|\__,_|_|_| |_____|                       ║
║          |___/                                                ║
║                                                               ║
║   🔐 Welcome to the Cipher-Prison! 🔐                         ║
║                                                               ║
║   Rules:                                                      ║
║   1. Your INPUT is scrambled by a rotating cipher             ║
║   2. Output is displayed normally (so you can read errors!)   ║
║   3. ⚠️  FORBIDDEN WORDS = INSTANT DEATH ⚠️                    ║
║   4. The flag awaits those who break free                     ║
║                                                               ║
║   💀 BLACKLIST (instant death): import, exec, eval, compile,  ║
║      subprocess, system, popen                                ║
║   🚫 FORBIDDEN CHARS: _                                       ║!                
║                                                               ║
║   Goal: Read /flag.txt                                        ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
"""

HELP_TEXT = """
Commands:
  help     - Show this help 
  quit     - Exit the jail

The cipher:
  - Caesar cipher on alphanumeric chars (a-zA-Z0-9 = 62 chars)
  - Only YOUR INPUT is encoded, output is normal!
  
"""

# ============== MAIN LOOP ==============

def main():
    print(BANNER)
    sys.stdout.flush()
    
    rotation = 0
    rotation_step = 7
    command_count = 0
    
    while True:
        try:
            # Generate current swap maps
            forward_map, reverse_map = generate_swap_map(rotation)
            
            # Show prompt with current rotation
            prompt = f"\n[Input] >>> "
            print(prompt, end='')
            sys.stdout.flush()
            
            # Read input
            try:
                raw_input = input()
            except EOFError:
                print("\n[!] Goodbye!")
                break
            
            if not raw_input.strip():
                continue
            
            # Apply reverse keyswap to decode user input
            decoded_input = swap_input(raw_input, reverse_map)
            
            # Handle special commands (after decoding)
            if decoded_input.strip().lower() == 'help':
                print(HELP_TEXT)
                rotation = (rotation + rotation_step) % len(ALPHABET)
                command_count += 1
                continue
            
            if decoded_input.strip().lower() == 'rotation':
                print(f"Current rotation: {rotation}, Next: {(rotation + rotation_step) % len(ALPHABET)}")
                rotation = (rotation + rotation_step) % len(ALPHABET)
                command_count += 1
                continue
            
            if decoded_input.strip().lower() == 'test':
                decoded_input = 'print("hello")'
            
            if decoded_input.strip().lower() in ['quit', 'exit', 'q']:
                print("🚪 The prisoner leaves... for now.")
                break
            
            # Check blacklist - THIS MAY KILL THE CONNECTION
            allowed, msg = check_blacklist(decoded_input)
            if not allowed:
                swapped_msg = swap_output(f"⚠️ {msg}", forward_map)
                print(swapped_msg)
                rotation = (rotation + rotation_step) % len(ALPHABET)
                command_count += 1
                continue
            
            # Execute the decoded code
            import io
            from contextlib import redirect_stdout, redirect_stderr
            
            stdout_capture = io.StringIO()
            stderr_capture = io.StringIO()
            
            try:
                with redirect_stdout(stdout_capture), redirect_stderr(stderr_capture):
                    error = safe_exec(decoded_input)
                
                output = stdout_capture.getvalue()
                stderr_output = stderr_capture.getvalue()
                
                # Output is NOT scrambled - displayed normally!
                if output:
                    print(output, end='')
                
                if stderr_output:
                    print(stderr_output, end='')
                
                if error:
                    print(f"[ERROR] {error}")
                    
            except Exception as e:
                print(f"[EXCEPTION] {str(e)}")
            
            # Rotate for next command
            rotation = (rotation + rotation_step) % len(ALPHABET)
            command_count += 1
            
            sys.stdout.flush()
            
        except KeyboardInterrupt:
            print("\n[!] Interrupted. Goodbye!")
            break
        except Exception as e:
            print(f"\n[!] Fatal error: {e}")
            break

if __name__ == "__main__":
    main()
