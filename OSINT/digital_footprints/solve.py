#!/usr/bin/env python3
"""
Digital Footprints OSINT Challenge - Automated Solver
Author: Shadow PB

This script demonstrates the complete solution path for the Digital Footprints challenge.
"""

import subprocess
import zipfile
import os
from pathlib import Path

def extract_metadata(image_path):
    """Extract metadata from image using exiftool"""
    try:
        result = subprocess.run(['exiftool', '-Comment', image_path], 
                              capture_output=True, text=True)
        output = result.stdout.strip()
        if 'Password:' in output:
            password = output.split('Password:')[1].strip()
            return password
        return None
    except Exception as e:
        print(f"Error extracting metadata: {e}")
        return None

def extract_zip_with_password(zip_path, password, extract_to='.'):
    """Extract password-protected ZIP file"""
    try:
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(extract_to, pwd=password.encode())
        return True
    except Exception as e:
        print(f"Error extracting ZIP: {e}")
        return False

def reveal_hidden_text(html_file):
    """Extract hidden text from HTML file"""
    try:
        with open(html_file, 'r') as f:
            content = f.read()
        
        # Find DSCCTF flag pattern
        import re
        flag_pattern = r'DSCCTF\{[^}]+\}'
        matches = re.findall(flag_pattern, content)
        
        if matches:
            return matches[0]
        return None
    except Exception as e:
        print(f"Error reading HTML file: {e}")
        return None

def solve_challenge():
    """Complete automated solution"""
    print("=" * 60)
    print("Digital Footprints OSINT Challenge - Automated Solver")
    print("=" * 60)
    print()
    
    # Step 1: LinkedIn Investigation (simulated)
    print("[*] Step 1: LinkedIn Corporate Intelligence")
    print("    ✓ Found DSC official LinkedIn page")
    print("    ✓ Identified creators: Pranav Barathi & Hiral Jain")
    print("    ✓ Extracted Twitter clues from creator posts")
    print("    ✓ Twitter pattern discovered: @DSC_CTF_2026")
    print()
    
    # Step 2: Twitter Investigation
    print("[*] Step 2: Twitter Account Analysis")
    print("    ✓ Located @DSC_CTF_2026 official account")
    print("    ✓ Found Instagram direction in bio")
    print("    ✓ Extracted handle from banner: @dsc_digital_footprints_2026")
    print()
    
    # Step 3: Instagram Investigation  
    print("[*] Step 3: Instagram Challenge Account")
    print("    ✓ Found @dsc_digital_footprints_2026")
    print("    ✓ Discovered GitHub repository clues")
    print("    ✓ Repository: DSC-CTF-2026/hidden-treasures-026")
    print()
    
    # Step 4: Repository Analysis
    print("[*] Step 4: GitHub Repository Discovery")
    print("    ✓ Found GitHub repo: DSC-CTF-2026/hidden-treasures-026")
    print("    ✓ Identified 3 files: decoy.png, treasure.png, secret.zip")
    print()
    
    # Step 5: Image Analysis
    print("[*] Step 5: Image Metadata Analysis")
    
    # Check if files exist
    treasure_path = "treasure.png"
    secret_zip_path = "secret.zip"
    
    if not os.path.exists(treasure_path):
        print(f"    ❌ {treasure_path} not found in current directory")
        print("    💡 Make sure you're in the repository_files directory")
        return False
    
    # Extract password from metadata
    password = extract_metadata(treasure_path)
    if password:
        print(f"    ✓ Extracted password from metadata: {password}")
    else:
        print("    ❌ Failed to extract password from metadata")
        return False
    print()
    
    # Step 6: File Decryption
    print("[*] Step 6: Password-Protected File Analysis")
    
    if not os.path.exists(secret_zip_path):
        print(f"    ❌ {secret_zip_path} not found")
        return False
    
    # Extract the ZIP file
    if extract_zip_with_password(secret_zip_path, password):
        print(f"    ✓ Successfully extracted {secret_zip_path}")
    else:
        print("    ❌ Failed to extract ZIP file")
        return False
    print()
    
    # Step 7: Hidden Text Discovery
    print("[*] Step 7: Hidden Text Analysis")
    
    secret_file = "secret.txt"
    if not os.path.exists(secret_file):
        print(f"    ❌ {secret_file} not found after extraction")
        return False
    
    # Find the hidden flag
    flag = reveal_hidden_text(secret_file)
    if flag:
        print(f"    ✓ Found hidden flag: {flag}")
        print()
        print("🏆 CHALLENGE SOLVED! 🏆")
        print(f"🚩 Flag: {flag}")
        return True
    else:
        print("    ❌ Failed to find hidden flag in file")
        return False

def main():
    print("Digital Footprints OSINT Challenge")
    print("Testing complete solution path...")
    print()
    
    success = solve_challenge()
    
    if not success:
        print("\n" + "=" * 60)
        print("MANUAL SOLUTION STEPS")
        print("=" * 60)
        print()
        print("1. LINKEDIN CORPORATE INTELLIGENCE:")
        print("   - Search for 'Digital Security Champions DSC' on LinkedIn")
        print("   - Find official company page with challenge creators")
        print("   - Check Pranav Barathi & Hiral Jain profiles")
        print("   - Extract Twitter clues from their shared posts")
        print()
        print("2. TWITTER INVESTIGATION:")
        print("   - Find: @DSC_CTF_2026 (from LinkedIn pattern)")
        print("   - Read bio for Instagram direction")
        print("   - Extract handle from banner: @dsc_digital_footprints_2026")
        print()
        print("3. INSTAGRAM INVESTIGATION:")
        print("   - Visit: @dsc_digital_footprints_2026")
        print("   - Find GitHub repository clues")
        print()
        print("4. GITHUB REPOSITORY:")
        print("   - Find: DSC-CTF-2026/hidden-treasures-026")
        print("   - Download: decoy.png, treasure.png, secret.zip")
        print()
        print("5. METADATA EXTRACTION:")
        print("   - Run: exiftool -Comment treasure.png")
        print("   - Extract password from comments")
        print()
        print("6. FILE DECRYPTION:")
        print("   - Unzip secret.zip with extracted password")
        print("   - Password should be: SecretKey2026")
        print()
        print("7. HIDDEN TEXT:")
        print("   - Open secret.txt in text editor")
        print("   - Select all text (Ctrl+A) to reveal white text")
        print("   - Or change background color to see hidden content")

if __name__ == "__main__":
    main()