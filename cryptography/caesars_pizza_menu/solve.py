#!/usr/bin/env python3

import base64

def caesar_decrypt(text, shift):
    result = ""
    for char in text:
        if char.isalpha():
            ascii_offset = 65 if char.isupper() else 97
            shifted = (ord(char) - ascii_offset - shift) % 26
            result += chr(shifted + ascii_offset)
        else:
            result += char
    return result

def solve_menu():
    # Read encrypted menu
    with open("encrypted_menu.txt", "r") as f:
        encoded_menu = f.read().strip()
    
    # Base64 decode
    encrypted_menu = base64.b64decode(encoded_menu).decode()
    
    print("Encrypted Menu:")
    print(encrypted_menu)
    print("\n" + "="*50 + "\n")
    
    # Try different shifts (brute force)
    for shift in range(26):
        print(f"Trying shift {shift}:")
        decrypted = caesar_decrypt(encrypted_menu, shift)
        print(decrypted[:100] + "...")
        
        if "DSCCTF{" in decrypted:
            print(f"\n*** SOLUTION FOUND WITH SHIFT {shift} ***")
            print("\nDecrypted Menu:")
            print(decrypted)
            break
        print("-" * 30)

if __name__ == "__main__":
    solve_menu()