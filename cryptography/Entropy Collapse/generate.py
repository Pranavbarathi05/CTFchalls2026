from Crypto.Util import Counter
from Crypto.Cipher import AES
import os

key = os.urandom(16)
nonce = b'\x00'*8  # intentional reuse

messages = [
b"Remember that the flag is always wrapped in DSCCTF format.",
b"Cryptography is less about secrets and more about mistakes.",
b"Never reuse a nonce in CTR mode. Not even once.",
b"The attacker does not break the cipher. The attacker breaks you.",
b"Confidence is the feeling you have before you understand the problem.",
b"DSCCTF{nonce_reuse_destroyed_ctr_security_2026}"
]

ciphertexts = []

for msg in messages:
    ctr = Counter.new(64, prefix=nonce)
    cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
    ciphertexts.append(cipher.encrypt(msg).hex())

print("\n".join(ciphertexts))
