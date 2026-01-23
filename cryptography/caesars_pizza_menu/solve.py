#!/usr/bin/env python3

import base64
import requests
import os

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

def solve_menu(target_url="http://ctf.dscjssstuniv.in:8001"):
    print(f"[*] Fetching encrypted menu from {target_url}...")
    
    # Try to fetch from URL first, fall back to local file
    try:
        response = requests.get(f"{target_url}/encrypted_menu.txt", timeout=10)
        if response.status_code == 200:
            encoded_menu = response.text.strip()
            print("[+] Successfully fetched menu from server")
        else:
            raise Exception("Failed to fetch from server")
    except Exception as e:
        print(f"[!] Could not fetch from {target_url}: {e}")
        print("[*] Falling back to local file...")
        if os.path.exists("encrypted_menu.txt"):
            with open("encrypted_menu.txt", "r") as f:
                encoded_menu = f.read().strip()
        else:
            print("[-] No local file found either. Exiting.")
            return
            return
    
    # Base64 decode
    encrypted_menu = base64.b64decode(encoded_menu).decode()
    
    print("\nEncrypted Menu:")
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
    print("=" * 60)
    print("Caesar's Pizza Menu - Solver")
    print("=" * 60)
    solve_menu()