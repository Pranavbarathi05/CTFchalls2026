#!/usr/bin/env python3
from pwn import *

# Connect to the challenge
conn = remote('localhost', 1339)

# Receive prompt
conn.recvuntil(b'Enter a number: ')

# Send a value with floating-point errors
# Values like 6, 7, 8, 10-19, etc. all have precision errors
# that cause x != mathStuff(x)
conn.sendline(b'6')

# Get the flag
response = conn.recvall()
print(response.decode())

conn.close()
