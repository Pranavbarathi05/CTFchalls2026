#!/usr/bin/env python3
"""
Solution for NumberOfones CTF Challenge

Connects to: nc numbers.challenges1.ctf.dscjssstuniv.in 54321
Solves: 10 rounds of counting digit '2' occurrences in number ranges
"""

from pwn import *
import re

# Connection settings
HOST = 'numbers.challenges1.ctf.dscjssstuniv.in'
PORT = 54321

def count_digit_in_range(start, end, digit='2'):
    """
    Count how many times a digit appears in all numbers within a range.
    
    Args:
        start: Starting number (inclusive)
        end: Ending number (inclusive)
        digit: The digit to count (default '2')
    
    Returns:
        Total count of the digit in the range
    """
    count = 0
    for number in range(start, end + 1):
        count += str(number).count(digit)
    return count

def main():
    print(f"[*] Connecting to {HOST}:{PORT}")
    
    # Connect to the challenge server
    io = remote(HOST, PORT)
    
    try:
        # Solve 10 rounds
        for round_num in range(1, 11):
            # Receive and display the round message
            round_msg = io.recvline().decode().strip()
            print(f"\n[Round {round_num}] {round_msg}")
            
            # Receive the question
            question = io.recvline().decode().strip()
            print(f"[Question] {question}")
            
            # Parse the question to extract start and end numbers
            # Format: "How many 2's appear between <start> and <end>?"
            match = re.search(r'between (\d+) and (\d+)', question)
            
            if not match:
                print("[ERROR] Failed to parse question!")
                io.close()
                return
            
            start, end = map(int, match.groups())
            print(f"[Parsed] Range: {start} to {end}")
            
            # Calculate the answer
            answer = count_digit_in_range(start, end, '2')
            print(f"[Answer] {answer}")
            
            # Send the answer
            io.sendline(str(answer).encode())
            
            # Receive feedback
            feedback = io.recvline().decode().strip()
            print(f"[Result] {feedback}")
            
            # Check if we failed
            if "Incorrect" in feedback or "Game over" in feedback:
                print("\n[FAILED] Challenge terminated.")
                io.close()
                return
        
        # All rounds completed successfully - receive the flag
        print("\n[SUCCESS] All rounds completed!")
        print("[*] Receiving flag...")
        
        flag_output = io.recvall(timeout=2).decode().strip()
        print(f"\n{'='*60}")
        print(flag_output)
        print('='*60)
        
        io.close()
        
    except Exception as e:
        print(f"\n[ERROR] {e}")
        io.close()

if __name__ == "__main__":
    main()
