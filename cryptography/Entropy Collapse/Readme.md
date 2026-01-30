# Entropy Collapse

## Category
Cryptography

## Difficulty
Hard

## Estimated Solve Time
4–8 hours for intermediate players.

---

## Challenge Overview

This challenge demonstrates a classic cryptographic implementation failure: **nonce reuse in CTR mode encryption**.

All provided ciphertexts were encrypted using AES in CTR mode with the **same key and the same nonce**, effectively turning the cipher into a reused stream cipher.

While AES itself is secure, reusing a nonce causes the keystream to repeat — allowing attackers to recover plaintext through XOR analysis.

---

## Key Concept

CTR mode generates ciphertext as:

    Ciphertext = Plaintext ⊕ Keystream

If two messages share the same keystream:

    C1 = P1 ⊕ K  
    C2 = P2 ⊕ K  

XORing the ciphertexts removes the keystream:

    C1 ⊕ C2 = P1 ⊕ P2

This is known as a **many-time pad vulnerability**.

It allows attackers to recover plaintext using crib-dragging techniques.

---

## Intended Solution Path

### 1. Observe Ciphertext Patterns
Participants should notice:

- Multiple ciphertexts  
- Similar lengths  
- Clean hex encoding  

These are strong indicators of a stream cipher.

---

### 2. XOR Ciphertexts

Example approach:

```python
from binascii import unhexlify

c1 = unhexlify(cipher1)
c2 = unhexlify(cipher2)

x = bytes(a ^ b for a, b in zip(c1, c2))
print(x)
```

---

### 3. Perform Crib Dragging

Guess common English words such as:

" the "
" and "
" nonce "
" flag "
" cryptography "
```

---

### 4. Once any plaintext segment is known:

Keystream = Ciphertext ⊕ Plaintext


Use the recovered keystream to decrypt all ciphertexts.