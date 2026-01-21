# GitHub Ghost – Internal Writeup

**Author:** @Poorvi-M  
**Difficulty:** Medium  
**Suggested Points:** 150  

---

## Flag
DSCCTF{g1t_n3v3r_f0rg3t5}

---

## Core Idea
This challenge tests GitHub OSINT skills by requiring players to inspect
commit history and recover a secret from a deleted configuration file.

---

## Intended Solve Path
1. Navigate to the challenge folder
2. Open commit history
3. Find the commit where `config.py` was deleted
4. View the deleted file
5. Extract `SECRET_KEY`

---

## Alternate Solutions
- `git log -- osint_github_ghost/`
- `git show <commit_hash>`

---

## Tester Notes
- Flag must not appear in the latest files
- Flag exists only in commit hi
