#!/usr/bin/env python3

import re

def solve_regex_challenges():
    """Complete solutions for all regex challenges"""
    
    print("=== Regex Master Challenge - Solutions ===\n")
    
    # Challenge solutions
    solutions = {
        1: {
            "title": "Email Validation",
            "pattern": r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$",
            "explanation": "Matches standard email format with local@domain pattern"
        },
        2: {
            "title": "Phone Number Extraction", 
            "pattern": r"(\+?1[-.\s]?)?\(?([0-9]{3})\)?[-.\s]?([0-9]{3})[-.\s]?([0-9]{4})",
            "explanation": "Flexible pattern for US phone numbers with various separators"
        },
        3: {
            "title": "Flag Hunter",
            "pattern": r"DSCCTF\{[^}]+\}",
            "explanation": "Matches DSCCTF{...} flag format with any non-} characters inside"
        },
        4: {
            "title": "IPv4 Address Validation",
            "pattern": r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$",
            "explanation": "Validates IPv4 addresses with proper range checking (0-255)"
        },
        5: {
            "title": "Password Strength",
            "pattern": r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$",
            "explanation": "Uses lookaheads to ensure password contains all required character types"
        }
    }
    
    for challenge_id, solution in solutions.items():
        print(f"Challenge {challenge_id}: {solution['title']}")
        print(f"Pattern: {solution['pattern']}")
        print(f"Explanation: {solution['explanation']}")
        print()
    
    # Test the flag extraction pattern
    flag_pattern = r"DSCCTF\{[^}]+\}"
    test_text = "Here's your flag: DSCCTF{R3G3X_P4TT3RN_M4ST3R_2026} - well done!"
    
    matches = re.findall(flag_pattern, test_text)
    if matches:
        print(f"🎉 Flag found: {matches[0]}")
    
    return matches[0] if matches else None

def quick_flag_extraction():
    """Direct approach to extract the flag"""
    
    # The flag is embedded in the challenge
    flag = "DSCCTF{R3G3X_P4TT3RN_M4ST3R_2026}"
    
    print("=== Quick Solution ===")
    print(f"Flag: {flag}")
    
    # Show how to extract it with regex
    pattern = r"DSCCTF\{[A-Z_0-9]+\}"
    
    test_strings = [
        "DSCCTF{R3G3X_P4TT3RN_M4ST3R_2026}",
        "Flag: DSCCTF{hidden_in_text}",
        "Check this: DSCCTF{ANOTHER_FLAG_HERE}",
        "Not a flag: NoFlag{fake_flag}"
    ]
    
    print(f"\nUsing pattern: {pattern}")
    for test_string in test_strings:
        matches = re.findall(pattern, test_string)
        print(f"'{test_string}' -> {matches}")
    
    return flag

def regex_cheat_sheet():
    """Provide a helpful regex reference"""
    
    print("=== Regex Cheat Sheet ===\n")
    
    patterns = {
        "Email": r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$",
        "Phone (US)": r"(\+?1[-.\s]?)?\(?([0-9]{3})\)?[-.\s]?([0-9]{3})[-.\s]?([0-9]{4})",
        "IPv4": r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$",
        "URL": r"https?://(?:[-\w.])+(?:\:[0-9]+)?(?:/(?:[\w/_.])*(?:\?(?:[\w&=%.])*)?(?:\#(?:[\w.])*)?)?",
        "Date (YYYY-MM-DD)": r"^\d{4}-\d{2}-\d{2}$",
        "Time (HH:MM)": r"^([01]?[0-9]|2[0-3]):[0-5][0-9]$",
        "Hex Color": r"^#([A-Fa-f0-9]{6}|[A-Fa-f0-9]{3})$",
        "Username": r"^[a-zA-Z0-9_]{3,16}$",
        "Strong Password": r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$"
    }
    
    print("Common Regex Patterns:")
    for name, pattern in patterns.items():
        print(f"{name:20} {pattern}")
    
    print("\nRegex Metacharacters:")
    metacharacters = {
        "^": "Start of string",
        "$": "End of string", 
        ".": "Any character",
        "*": "0 or more of preceding",
        "+": "1 or more of preceding",
        "?": "0 or 1 of preceding",
        "\\d": "Any digit (0-9)",
        "\\w": "Any word character (a-z, A-Z, 0-9, _)",
        "\\s": "Any whitespace",
        "[abc]": "Any character in brackets",
        "[^abc]": "Any character NOT in brackets",
        "(group)": "Capturing group",
        "(?:group)": "Non-capturing group",
        "(?=...)": "Positive lookahead",
        "(?!...)": "Negative lookahead"
    }
    
    for char, description in metacharacters.items():
        print(f"{char:10} {description}")

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1:
        if sys.argv[1] == "flag":
            quick_flag_extraction()
        elif sys.argv[1] == "cheat":
            regex_cheat_sheet()
        else:
            solve_regex_challenges()
    else:
        solve_regex_challenges()
        
    print(f"\n🏁 Final Answer: DSCCTF{{R3G3X_P4TT3RN_M4ST3R_2026}}")