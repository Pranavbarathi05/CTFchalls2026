# 🔐 Cipher Vault

**Category:** Reverse Engineering + Cryptography  
**Difficulty:** Medium–Hard  

---

## 📖 Description

A secure vault program protects sensitive data.

The password is not stored in plain text.  
Instead, the developer left behind an encrypted message using a classical cipher.

Break the cipher to recover the password, then use it to unlock the vault and retrieve the flag.

---

## 📁 Files Provided

vault
cipher.txt


---

## 🎯 Objective

1. Decrypt the cipher to obtain the vault password  
2. Run the vault binary using the decrypted password  
3. Retrieve the flag  

---

## 🚩 Flag Format

DSCCTF{...}


---
# 💡 Hints

### Hint 1 (Easy)
> The cipher uses a repeating key.

---

### Hint 2 (Medium)
> This is a classic polyalphabetic cipher.

---

### Hint 3 (Hard)
> The key is the name of the society hosting this CTF (3 letters).

---

# 🧠 Walkthrough (Official Solution)

⚠️ Spoilers below.

---

##Walkthrough

Step 1 — Inspect the provided files

You are given:

vault
cipher.txt


Open the cipher file:

bash
cat cipher.txt

You should see something like:
Cipher: fqeefyydxow2026
Key Hint: The society hosting this CTF (3 letters)

Step 2 — Identify the cipher

The ciphertext consists of letters and comes with a hint about a repeating key.

This strongly suggests a Vigenère cipher.

From the hint, the key is:

DSC

Step 3 — Decrypt the cipher

Using Vigenère with key DSC, decrypt:

fqeefyydxow2026


You can use tools such as:

CyberChef

dcode.fr

or your own script

The decrypted result is:

cybervault2026
This is the vault password 

Step 4 — Run the binary

Make the file executable (if needed):

chmod +x vault


Run it:

./vault


When prompted, enter:

cybervault2026

Step 5 — Retrieve the flag

After entering the correct password, the program prints:

Access Granted!
Flag: DSCCTF{cipher_breaker_unlocked}



