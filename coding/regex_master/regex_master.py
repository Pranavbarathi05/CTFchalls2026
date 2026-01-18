#!/usr/bin/env python3

import re
import random
import string

def generate_test_strings():
    """Generate various test strings for regex challenges"""
    
    test_strings = [
        # Email-like patterns
        "admin@ctf.com",
        "user123@example.org", 
        "test.email+tag@domain.co.uk",
        "invalid.email@",
        "not_an_email",
        
        # Phone numbers
        "+1-555-123-4567",
        "(555) 987-6543",
        "555.321.9876",
        "1234567890",
        "phone: 555-0123",
        
        # IP addresses
        "192.168.1.1",
        "10.0.0.255",
        "256.1.1.1",  # Invalid
        "127.0.0.1",
        "0.0.0.0",
        
        # Dates
        "2024-12-31",
        "01/15/2026",
        "March 15, 2025",
        "15-03-2024",
        "invalid-date",
        
        # URLs
        "https://www.example.com",
        "http://ctf.dscctf.com:8080/path",
        "ftp://files.example.org",
        "not-a-url",
        "www.example.com",
        
        # Flag patterns (hidden in various formats)
        "DSCCTF{R3G3X_P4TT3RN_M4ST3R_2026}",
        "Flag: DSCCTF{hidden_in_text}",
        "dscctf{lowercase_flag}",
        "DSCCTF{MULTI_LINE\nFLAG_CONTENT}",
        "NoFlag{this_is_fake}",
        
        # Special patterns
        "Password123!",
        "simple_password",
        "123-45-6789",  # SSN format
        "ABC-123-DEF",  # License plate
        "#FF5733",  # Hex color
        
        # Mixed content
        "Contact us at support@ctf.com or call +1-555-CTF-2026",
        "Visit https://ctf.dscctf.com for more info. Flag: DSCCTF{REGEX_NINJA_2026}",
        "Error 404: Page not found at /admin/flag.txt",
        "User ID: 12345, Session: abc123def456",
    ]
    
    return test_strings

def regex_challenges():
    """Define a series of regex challenges"""
    
    challenges = [
        {
            "id": 1,
            "title": "Email Validation",
            "description": "Write a regex to match valid email addresses",
            "pattern": r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$",
            "test_inputs": [
                "admin@ctf.com",
                "user123@example.org", 
                "test.email+tag@domain.co.uk",
                "invalid.email@",
                "not_an_email"
            ],
            "expected": [True, True, True, False, False]
        },
        {
            "id": 2,
            "title": "Phone Number Extraction",
            "description": "Extract phone numbers in various formats",
            "pattern": r"(\+?1[-.\s]?)?\(?([0-9]{3})\)?[-.\s]?([0-9]{3})[-.\s]?([0-9]{4})",
            "test_inputs": [
                "+1-555-123-4567",
                "(555) 987-6543",
                "555.321.9876",
                "call me at 555-0123 today"
            ],
            "expected_matches": 4
        },
        {
            "id": 3,
            "title": "Flag Hunter",
            "description": "Find all CTF flags in the given text",
            "pattern": r"DSCCTF\{[^}]+\}",
            "test_inputs": [
                "DSCCTF{R3G3X_P4TT3RN_M4ST3R_2026}",
                "Flag: DSCCTF{hidden_in_text}",
                "dscctf{lowercase_flag}",
                "NoFlag{this_is_fake}",
                "Multiple flags: DSCCTF{flag1} and DSCCTF{flag2}"
            ],
            "expected_matches": 4
        },
        {
            "id": 4,
            "title": "IPv4 Address Validation", 
            "description": "Match valid IPv4 addresses only",
            "pattern": r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$",
            "test_inputs": [
                "192.168.1.1",
                "10.0.0.255", 
                "256.1.1.1",
                "127.0.0.1",
                "0.0.0.0"
            ],
            "expected": [True, True, False, True, True]
        },
        {
            "id": 5,
            "title": "Password Strength",
            "description": "Match passwords with at least 8 chars, 1 uppercase, 1 lowercase, 1 digit, 1 special char",
            "pattern": r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$",
            "test_inputs": [
                "Password123!",
                "simple_password",
                "Strong@Pass1",
                "12345678",
                "Weak1"
            ],
            "expected": [True, False, True, False, False]
        }
    ]
    
    return challenges

def interactive_challenge():
    """Interactive regex challenge interface"""
    
    print("🔤 Welcome to Regex Master Challenge!")
    print("Test your regular expression skills across multiple challenges.\n")
    
    challenges = regex_challenges()
    test_strings = generate_test_strings()
    
    score = 0
    total_challenges = len(challenges)
    
    for challenge in challenges:
        print(f"\n{'='*60}")
        print(f"Challenge {challenge['id']}: {challenge['title']}")
        print(f"{'='*60}")
        print(f"Description: {challenge['description']}")
        
        if 'test_inputs' in challenge:
            print("\nTest inputs:")
            for i, test_input in enumerate(challenge['test_inputs']):
                print(f"  {i+1}. {repr(test_input)}")
        
        print(f"\nEnter your regex pattern:")
        user_pattern = input("> ").strip()
        
        try:
            # Test the user's regex
            compiled_pattern = re.compile(user_pattern)
            
            correct = True
            
            if 'expected' in challenge:
                # Validation challenge
                for i, test_input in enumerate(challenge['test_inputs']):
                    match = bool(compiled_pattern.match(test_input))
                    expected = challenge['expected'][i]
                    
                    if match != expected:
                        print(f"❌ Test {i+1} failed: expected {expected}, got {match}")
                        correct = False
                    else:
                        print(f"✅ Test {i+1} passed")
            
            elif 'expected_matches' in challenge:
                # Extraction challenge
                total_matches = 0
                for test_input in challenge['test_inputs']:
                    matches = compiled_pattern.findall(test_input)
                    total_matches += len(matches)
                    if matches:
                        print(f"Found in '{test_input}': {matches}")
                
                if total_matches == challenge['expected_matches']:
                    print(f"✅ Correct! Found {total_matches} matches")
                else:
                    print(f"❌ Expected {challenge['expected_matches']} matches, found {total_matches}")
                    correct = False
            
            if correct:
                print("🎉 Challenge completed successfully!")
                score += 1
                
                # Special flag for completing all challenges
                if challenge['id'] == 3 and correct:  # Flag Hunter challenge
                    flag_matches = compiled_pattern.findall("DSCCTF{R3G3X_P4TT3RN_M4ST3R_2026}")
                    if flag_matches:
                        print(f"🚩 Bonus Flag Found: {flag_matches[0]}")
            else:
                print("💡 Hint: Check the expected behavior against your pattern")
                print(f"    Correct pattern: {challenge['pattern']}")
                
        except re.error as e:
            print(f"❌ Invalid regex pattern: {e}")
        except Exception as e:
            print(f"❌ Error testing pattern: {e}")
    
    print(f"\n{'='*60}")
    print(f"FINAL SCORE: {score}/{total_challenges}")
    
    if score == total_challenges:
        print("🏆 PERFECT SCORE! You are a Regex Master!")
        print("🎉 Flag: DSCCTF{R3G3X_P4TT3RN_M4ST3R_2026}")
    elif score >= total_challenges * 0.8:
        print("🥈 Excellent! You have strong regex skills!")
    elif score >= total_challenges * 0.6:
        print("🥉 Good job! Keep practicing your regex patterns!")
    else:
        print("📚 Keep learning! Regex takes practice to master!")

def solve_all_challenges():
    """Show solutions for all challenges"""
    
    print("=== Regex Master - All Solutions ===\n")
    
    challenges = regex_challenges()
    
    for challenge in challenges:
        print(f"Challenge {challenge['id']}: {challenge['title']}")
        print(f"Pattern: {challenge['pattern']}")
        print(f"Description: {challenge['description']}")
        
        # Test the pattern
        compiled_pattern = re.compile(challenge['pattern'])
        
        if 'test_inputs' in challenge:
            print("Test results:")
            for i, test_input in enumerate(challenge['test_inputs']):
                if 'expected' in challenge:
                    match = bool(compiled_pattern.match(test_input))
                    expected = challenge['expected'][i]
                    status = "✅" if match == expected else "❌"
                    print(f"  {status} {repr(test_input)} -> {match} (expected: {expected})")
                else:
                    matches = compiled_pattern.findall(test_input)
                    print(f"  {repr(test_input)} -> {matches}")
        
        print("-" * 40)
    
    print("\n🎉 All solutions provided!")
    print("Flag: DSCCTF{R3G3X_P4TT3RN_M4ST3R_2026}")

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == "solve":
        solve_all_challenges()
    else:
        interactive_challenge()