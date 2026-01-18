#!/usr/bin/env python3

import base64

# Caesar's Pizza Menu - Caesar Cipher Challenge
def caesar_cipher(text, shift):
    result = ""
    for char in text:
        if char.isalpha():
            ascii_offset = 65 if char.isupper() else 97
            shifted = (ord(char) - ascii_offset + shift) % 26
            result += chr(shifted + ascii_offset)
        else:
            result += char
    return result

def create_menu():
    menu_items = [
        "WELCOME TO CAESARS PIZZA PALACE",
        "TODAY'S SPECIAL MENU:",
        "1. MARGHERITA PIZZA - $12",
        "2. PEPPERONI DELIGHT - $15", 
        "3. CAESAR SALAD - $8",
        "4. GARLIC BREADSTICKS - $6",
        "5. ITALIAN SODA - $4",
        "",
        "SECRET ITEM FOR VIP CUSTOMERS:",
        "FLAG PIZZA - DSCCTF{PIZZA_CIPHER_MASTER_2026}",
        "",
        "THANK YOU FOR VISITING!"
    ]
    
    # Encrypt the menu with Caesar cipher (shift 13 - ROT13)
    encrypted_menu = []
    for line in menu_items:
        encrypted_menu.append(caesar_cipher(line, 13))
    
    return "\n".join(encrypted_menu)

if __name__ == "__main__":
    print("=== Caesar's Pizza Menu Generator ===")
    encrypted = create_menu()
    
    # Base64 encode to make it slightly more challenging
    encoded = base64.b64encode(encrypted.encode()).decode()
    
    print("\nEncrypted Menu (Base64):")
    print(encoded)
    
    # Save to file
    with open("encrypted_menu.txt", "w") as f:
        f.write(encoded)