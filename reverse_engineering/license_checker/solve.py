#!/usr/bin/env python3

def find_valid_license():
    """
    Reverse engineering the license validation:
    1. Must be 19 characters long
    2. Format: XXXX-YYYY-ZZZZ-WWWW 
    3. Must start with "DSCR"
    4. Checksum of all non-dash characters must equal 1337
    """
    
    prefix = "DSCR"
    target_checksum = 1337
    
    # Calculate current checksum from prefix
    current_checksum = sum(ord(c) for c in prefix)
    
    # We need the remaining characters to sum to (1337 - current_checksum)
    remaining_needed = target_checksum - current_checksum
    
    print(f"Prefix: {prefix}")
    print(f"Current checksum: {current_checksum}")
    print(f"Remaining needed: {remaining_needed}")
    
    # We have 15 more characters to fill (excluding 3 dashes)
    # Let's use 'A' (ASCII 65) characters mostly
    remaining_chars = remaining_needed // 65  # How many 'A's we can use
    remainder = remaining_needed % 65
    
    # Build the license
    license_parts = [prefix]
    
    # Fill remaining parts
    for part in range(3):  # 3 more parts needed
        if part == 0:
            # Second part - use mostly A's
            chars_in_part = min(4, remaining_chars)
            part_str = 'A' * chars_in_part
            if chars_in_part < 4:
                # Fill remaining with calculated character
                missing = 4 - chars_in_part
                if remainder > 0:
                    part_str += chr(remainder)
                    remainder = 0
                    missing -= 1
                part_str += 'A' * missing
            license_parts.append(part_str)
            remaining_chars -= chars_in_part
        else:
            # Fill with A's
            chars_needed = min(4, remaining_chars)
            part_str = 'A' * chars_needed
            if chars_needed < 4:
                part_str += 'A' * (4 - chars_needed)
            license_parts.append(part_str)
            remaining_chars -= chars_needed
    
    license = '-'.join(license_parts)
    
    # Verify checksum
    actual_checksum = sum(ord(c) for c in license if c != '-')
    
    print(f"\nGenerated license: {license}")
    print(f"Actual checksum: {actual_checksum}")
    print(f"Target checksum: {target_checksum}")
    
    if actual_checksum == target_checksum:
        print("✅ License is valid!")
        return license
    else:
        print("❌ License checksum doesn't match")
        
        # Try brute force approach
        print("\nTrying brute force approach...")
        return brute_force_license()

def brute_force_license():
    """Brute force the remaining characters to get exact checksum"""
    prefix = "DSCR-"
    target_checksum = 1337
    prefix_sum = sum(ord(c) for c in prefix if c != '-')
    
    # We need 12 more characters (3 parts of 4 each)
    remaining_needed = target_checksum - prefix_sum
    
    # Simple approach: distribute the sum across 12 characters
    avg_char_value = remaining_needed // 12
    remainder = remaining_needed % 12
    
    license_chars = []
    for i in range(12):
        if i < remainder:
            char_value = avg_char_value + 1
        else:
            char_value = avg_char_value
            
        # Ensure it's a printable ASCII character
        if char_value < 32:
            char_value = 65  # 'A'
        elif char_value > 126:
            char_value = 90   # 'Z'
            
        license_chars.append(chr(char_value))
    
    # Format as license
    part2 = ''.join(license_chars[:4])
    part3 = ''.join(license_chars[4:8]) 
    part4 = ''.join(license_chars[8:12])
    
    license = f"DSCR-{part2}-{part3}-{part4}"
    
    # Verify
    actual_checksum = sum(ord(c) for c in license if c != '-')
    print(f"Brute force license: {license}")
    print(f"Checksum: {actual_checksum} (target: {target_checksum})")
    
    # Manual adjustment if needed
    if actual_checksum != target_checksum:
        diff = target_checksum - actual_checksum
        # Adjust the last character
        last_char_pos = len(license) - 1
        new_char = chr(ord(license[last_char_pos]) + diff)
        if 32 <= ord(new_char) <= 126:  # Printable ASCII
            license = license[:last_char_pos] + new_char
        
        actual_checksum = sum(ord(c) for c in license if c != '-')
        print(f"Adjusted license: {license}")
        print(f"Final checksum: {actual_checksum}")
    
    return license

if __name__ == "__main__":
    print("=== License Checker Reverse Engineering ===")
    print("\nAnalyzing the binary to find valid license format...")
    
    license = find_valid_license()
    
    print(f"\n🔑 Use this license: {license}")
    print("\nNow run the license_checker binary with this key!")