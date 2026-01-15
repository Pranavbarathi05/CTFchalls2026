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
    'import', 'exec', 'eval', 'compile', 'open', 'input',
    'breakpoint', 'help', 'license', 'credits', 'copyright',
    '__import__', '__loader__', '__spec__', '__builtins__',
    '__file__', '__cached__', '__doc__', '__name__',
    'subprocess', 'os', 'sys', 'socket', 'pty', 'posix',
    'platform', 'popen', 'spawn', 'fork', 'system',
    'read', 'write', 'environ', 'getattr', 'setattr',
    'delattr', 'globals', 'locals', 'vars', 'dir',
    'type', 'class', 'base', 'mro', 'subclasses',
    'init', 'new', 'call', 'dict', 'repr', 'str',
    'bytes', 'chr', 'ord', 'hex', 'oct', 'bin',
    'memoryview', 'bytearray', 'codecs', 'pickle',
    'ctypes', 'cffi', 'multiprocessing', 'threading',
    'asyncio', 'signal', 'fcntl', 'resource',
    'shutil', 'tempfile', 'pathlib', 'glob',
    'request', 'urllib', 'http', 'ftp',
    'flag', 'secret', 'key', 'password',
]

DANGEROUS_CHARS = ['_', '.', '[', ']', '\\', '{{', '}}']

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

def safe_exec(code):
    """Execute code in a restricted environment"""
    restricted_globals = {
        '__builtins__': {
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
            'True': True,
            'False': False,
            'None': None,
        }
    }
    restricted_locals = {}
    
    try:
        exec(code, restricted_globals, restricted_locals)
        return None
    except Exception as e:
        return str(e)

# ============== BANNER & HELP ==============

BANNER = r"""
╔═══════════════════════════════════════════════════════════════╗
║    ____        _       _ _   ____                             ║
║   |  _ \ _   _| | __ _(_) | |___ \                            ║
║   | |_) | | | | |/ _` | | |   __) |                           ║
║   |  __/| |_| | | (_| | | |  / __/                            ║
║   |_|    \__, |_|\__,_|_|_| |_____|                           ║
║          |___/                                                ║
║                                                               ║
║   🔐 Welcome to the Cipher-Prison! 🔐                         ║
║                                                               ║
║   Rules:                                                      ║
║   1. Your keystrokes are... scrambled? Twisted? Shifted?      ║
║   2. The output looks weird too... figure out the pattern!    ║
║   3. Something changes after each command... what is it?      ║
║   4. ⚠️  FORBIDDEN WORDS = INSTANT DEATH ⚠️                   ║
║   5. The flag awaits those who break free                     ║
║                                                               ║
║   Hints:                                                      ║
║   • Caesar once said: "Veni, Vidi, Vici"                      ║
║   • The alphabet has 62 friends (a-z, A-Z, 0-9)               ║
║   • Watch the prompt carefully... numbers don't lie           ║
║   • +7 is a lucky number, or is it?                           ║
║                                                               ║
║   Goal: Read /flag.txt ... if you can figure out how to ask   ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
"""

HELP_TEXT = """
Commands:
  olsw     - (decode me to find help)
  yvahapvu - (what could this be?)
  alza     - (try me at rotation 0)
  xbpa     - (escape... or leave?)

You're in a prison where words are twisted.
The ancient Romans knew this trick well.
The number in your prompt is your guide.
But beware - speak forbidden words and DIE.

Some characters are simply... not allowed.
Think about what symbols programmers love.
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
            prompt = f"\n[Rotation: {rotation:02d}] >>> "
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
                output = HELP_TEXT
                swapped_output = swap_output(output, forward_map)
                print(swapped_output)
                rotation = (rotation + rotation_step) % len(ALPHABET)
                command_count += 1
                continue
            
            if decoded_input.strip().lower() == 'rotation':
                output = f"🔢 The number speaks: {rotation}... next comes {(rotation + rotation_step) % len(ALPHABET)}"
                swapped_output = swap_output(output, forward_map)
                print(swapped_output)
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
                
                if output:
                    swapped_output = swap_output(output, forward_map)
                    print(swapped_output, end='')
                
                if stderr_output:
                    swapped_stderr = swap_output(stderr_output, forward_map)
                    print(swapped_stderr, end='')
                
                if error:
                    swapped_error = swap_output(f"[ERROR] {error}", forward_map)
                    print(swapped_error)
                    
            except Exception as e:
                swapped_error = swap_output(f"[EXCEPTION] {str(e)}", forward_map)
                print(swapped_error)
            
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
