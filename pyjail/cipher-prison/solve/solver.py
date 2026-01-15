#!/usr/bin/env python3
"""
Solver script for the Dynamic KeySwapper PyJail challenge
This demonstrates one possible solution path.

The challenge has several vulnerabilities that can be exploited:
1. The blacklist checks decoded input, but doesn't cover all bypass techniques
2. Unicode/encoding tricks might work
3. Lambda functions and list comprehensions can be abused
4. Built-in functions left available can be chained

This solver helps you encode commands for the rotating cipher.
"""

from pwn import *

# Configuration
HOST = "localhost"
PORT = 1337

ALPHABET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

def generate_swap_map(rotation):
    """Generate the same swap maps as the challenge"""
    rotated = ALPHABET[rotation:] + ALPHABET[:rotation]
    forward_map = str.maketrans(ALPHABET, rotated)
    reverse_map = str.maketrans(rotated, ALPHABET)
    return forward_map, reverse_map

def encode_for_rotation(text, rotation):
    """Encode text so it decodes correctly at given rotation"""
    forward_map, reverse_map = generate_swap_map(rotation)
    # We need to send text that when reverse_map is applied, gives us our desired text
    # So we apply forward_map to our text
    return text.translate(forward_map)

def decode_output(text, rotation):
    """Decode output that was encoded with forward_map"""
    forward_map, reverse_map = generate_swap_map(rotation)
    return text.translate(reverse_map)

def interactive_helper():
    """Interactive mode to help encode/decode"""
    rotation = 0
    rotation_step = 7
    
    print("[*] Dynamic KeySwapper Encoder/Decoder")
    print("[*] Rotation starts at 0, increases by 7 each command")
    print()
    
    while True:
        print(f"[Current Rotation: {rotation}]")
        cmd = input("Enter command to encode (or 'q' to quit): ").strip()
        
        if cmd.lower() == 'q':
            break
        
        encoded = encode_for_rotation(cmd, rotation)
        print(f"  Encoded: {encoded}")
        print(f"  (Send this to get '{cmd}' executed)")
        print()
        
        rotation = (rotation + rotation_step) % len(ALPHABET)

def auto_solve():
    """Automated solver attempt"""
    # Connect to the challenge
    r = remote(HOST, PORT)
    
    rotation = 0
    rotation_step = 7
    
    # Receive banner
    banner = r.recvuntil(b">>> ")
    print(banner.decode())
    
    # Strategy: Try to find a way to read the flag
    # Since common methods are blocked, we need creative approaches
    
    # Example payloads to try (encode each for current rotation):
    payloads = [
        # Test basic execution
        'print(1+1)',
        
        # Try to access builtins through allowed functions
        'print(sum((1,2,3)))',
        
        # The challenge blocks many things, need to find gaps
        # This is intentionally left incomplete for CTF players to solve
    ]
    
    for payload in payloads:
        encoded = encode_for_rotation(payload, rotation)
        print(f"[Rotation {rotation}] Sending: {encoded} (decodes to: {payload})")
        
        r.sendline(encoded.encode())
        
        try:
            response = r.recvuntil(b">>> ", timeout=2)
            decoded_response = decode_output(response.decode(), rotation)
            print(f"Response (decoded): {decoded_response}")
        except:
            print("No response or timeout")
        
        rotation = (rotation + rotation_step) % len(ALPHABET)
    
    r.interactive()

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == "auto":
        auto_solve()
    else:
        interactive_helper()
