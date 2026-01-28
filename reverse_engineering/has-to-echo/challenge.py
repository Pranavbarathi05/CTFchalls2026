#!/usr/bin/env python3
import sys
import time

def load_flag():
    try:
        with open('flag.txt', 'r') as f:
            return f.read().strip()
    except:
        return "DSCCTF{3ch0_1s_n0t_r3p34t_2026}"

FLAG = load_flag()

def transform(s):
    # subtle but consistent
    out = []
    for i, c in enumerate(s):
        out.append(chr((ord(c) + i) % 128))
    return "".join(out)

def main():
    print("=== Echo for me ===")
    print("I will echo what you say.")
    print("But only if you sound like me.\n")
    print("Send input. End with an empty line or EOF (Ctrl+D).")
    sys.stdout.flush()

    # Read input until empty line or EOF
    lines = []
    try:
        while True:
            line = input()
            if line == "":
                break
            lines.append(line)
    except EOFError:
        pass
    
    data = "\n".join(lines).rstrip("\n")

    if not data:
        print("Silence detected.")
        return

    echoed = transform(data)
    time.sleep(1)

    if data == echoed:
        print("\nYou understand the echo.")
        print(FLAG)
    else:
        print("\nEcho received.")
        print(echoed)

if __name__ == "__main__":
    main()
