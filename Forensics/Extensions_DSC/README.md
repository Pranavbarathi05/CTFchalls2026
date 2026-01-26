# 🧩 Challenge 3 — Extensions (DSC Edition)

**Category:** Forensics  
**Difficulty:** Easy → Medium  

---

## 📖 Description

A file recovered from a compromised system claims to be a text file.

But investigators believe it’s hiding something else.

File extensions can lie.  
File signatures don’t.

---

## 📁 Files Provided

flag.txt

---

## 🎯 Objective

Determine the true file type and extract the hidden flag.

---

## 🚩 Flag Format

DSCCTF{...}

---

# 💡 Hints

### Hint 1 (Easy)
> Don’t trust file extensions.

---

### Hint 2 (Medium)
> Try identifying the file type using command-line tools.

---

### Hint 3 (Hard)
> What does the `file` command tell you?

---

# 🧠 Walkthrough (Official Solution)

⚠️ Spoilers below.

---

Step 1 — Inspect the file

You are given:

flag.txt

Although it has a `.txt` extension, that does not guarantee it is actually a text file.

Run:

file flag.txt
This reveals that the file is actually a PNG image.

Step 2 — Rename the file
Rename the file to reflect its true type:

mv flag.txt flag.png
Step 3 — Open the image
Open the image using any image viewer:

xdg-open flag.png
Step 4 — Extract the flag
The image contains hidden data appended to it.

Extract readable strings:

strings flag.png | grep DSCCTF
✅ Final Flag

DSCCTF{extensions_never_lie}
