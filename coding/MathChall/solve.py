from pwn import *
import re

HOST = "math.challenges1.ctf.dscjssstuniv.in"
PORT = 8018

def transform(n):
    return n + 1 if bin(n).count("1") % 2 == 0 else n - 1

r = remote(HOST, PORT)

while True:
    line = r.recvline().decode()
    print(line, end="")

    if "accept this truth" in line:
        r.sendline("yes")

    if "What is" in line:
        expr = re.search(r"What is (.*)\?", line).group(1)
        val = eval(expr)
        r.sendline(str(transform(val)))

    if "FLAG" in line:
        print(r.recvall().decode())
        break
