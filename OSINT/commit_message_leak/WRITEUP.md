# Accidental Commit Message Leak – Writeup

**Author:** @Poorvi-M  
**Category:** OSINT  
**Difficulty:** Easy  
**Suggested Points:** 75  

---

## 🚩 Flag
DSCCTF{commit_messages_leak}

---

## 🧠 Core Idea

This challenge demonstrates a common real-world OSINT mistake where developers
accidentally leak sensitive information inside Git commit messages instead
of source code files.

The flag is not present in any file in the repository.
It can only be discovered by inspecting the commit history and reading commit
messages carefully.

---

## 🧩 Intended Solve Path

1. The player navigates to the challenge directory.
2. The player opens the Git commit history for the repository.
3. The player inspects commit messages instead of only file contents.
4. One commit message contains a leaked token.
5. The token is extracted and submitted as the flag.

---

## 🔍 Example of the Leak

A commit message similar to:

fix session bug – token=DSCCTF{commit_messages_leak}

The secret appears directly in the commit message metadata.

---

## 🔁 Alternate Solution Methods

- Using GitHub Web UI:
  - Open the repository
  - Click History
  - Read commit messages
- Using local Git:
  git log

