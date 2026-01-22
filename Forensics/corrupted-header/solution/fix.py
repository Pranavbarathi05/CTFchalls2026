#!/usr/bin/env python3
"""
Solution script for Corrupted Vacation Photo challenge
Fixes the JPEG magic bytes and extracts the flag
"""

def fix_jpeg_header(input_file, output_file='fixed_photo.jpg'):
    """Fix JPEG magic bytes (FF D8 FF)"""
    
    print("=" * 60)
    print("Corrupted Vacation Photo - Solution")
    print("=" * 60)
    
    # Read the corrupted file
    with open(input_file, 'rb') as f:
        data = f.read()
    
    # Show current (corrupted) header
    print(f"\n[*] Current header bytes: {' '.join(f'{b:02X}' for b in data[:10])}")
    print(f"[*] File size: {len(data)} bytes")
    
    # Check if already correct
    if data[:3] == b'\xFF\xD8\xFF':
        print("[!] File header is already correct!")
        print("[*] This file is not corrupted.")
    else:
        print("[!] Header is CORRUPTED!")
        print(f"    Found: {data[:3].hex().upper()}")
        print(f"    Expected: FF D8 FF (JPEG magic bytes)")
    
    # Fix the header
    print("\n[+] Fixing header...")
    fixed = b'\xFF\xD8\xFF' + data[3:]
    
    # Save fixed file
    with open(output_file, 'wb') as f:
        f.write(fixed)
    
    print(f"[+] Fixed file saved as: {output_file}")
    print(f"[*] New header bytes: {' '.join(f'{b:02X}' for b in fixed[:10])}")
    
    # Extract flag
    print("\n[+] Searching for flag...")
    if b'DSCCTF{' in fixed:
        start = fixed.find(b'DSCCTF{')
        end = fixed.find(b'}', start) + 1
        flag = fixed[start:end].decode('ascii')
        print(f"[🚩] FLAG FOUND: {flag}")
    else:
        print("[-] No flag found in file")
    
    print("\n" + "=" * 60)
    print("✓ Done! You can now open the fixed image.")
    print("=" * 60)

if __name__ == '__main__':
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python3 fix.py <corrupted_file.jpg>")
        print("\nTrying default filename: vacation_photo.jpg")
        input_file = 'vacation_photo.jpg'
    else:
        input_file = sys.argv[1]
    
    try:
        fix_jpeg_header(input_file)
    except FileNotFoundError:
        print(f"Error: File '{input_file}' not found!")
        print("Make sure the corrupted file is in the current directory.")
