| Domain                  | Easy | Medium | Hard |
| ----------------------- | ---- | ------ | ---- |
| **Binary Exploitation** | 1    | 1      | 0    |
| **Coding**              | 1    | 4      | 0    |
| **Cryptography**        | 1    | 0      | 0    |
| **Pyjail**              | 0    | 2      | 1    |
| **Reverse Engineering** | 1    | 0      | 1    |
| **Web exploitation**    | 3    | 5      | 1    |
| **OSINT**               | 1    | 0      | 0    |
| **Misc**                | 1    | 3      | 2    |

## Total = 28


# CTF Challenge List - DSCCTF 2026

## Binary Exploitation (2 challenges)

| Challenge | Difficulty | Vulnerability |
|-----------|------------|---------------|
| **Overflow Academy** | Easy | Stack-based buffer overflow with all protections disabled (no canary, no ASLR, executable stack) |
| **Menu Pwner** | Medium | Use-After-Free (UAF) memory corruption in heap allocations; reallocate freed chunks to gain control |

---

## Coding (5 challenges)

| Challenge | Difficulty | Vulnerability |
|-----------|------------|---------------|
| **Has-to-Echo** | Easy | Behavioral pattern matching; must echo input exactly to pass validation checks |
| **Dystopian Arithmetic** | Medium | Logic manipulation where mathematical truths are redefined (2+2=5); accept false premises |
| **Pathfinding Puzzle** | Medium | Graph traversal and shortest path algorithms; collect flag pieces in correct order through maze |
| **Regex Master** | Medium | Regular expression crafting across 5 progressively harder pattern matching scenarios |
| **Tree Traversal Secret** | Medium | Binary tree traversal techniques (inorder/preorder/postorder); correct method reveals flag |

---

## Cryptography (1 challenge)

| Challenge | Difficulty | Vulnerability |
|-----------|------------|---------------|
| **Caesar's Pizza Menu** | Easy | Classical Caesar cipher with shift-based substitution; brute force or frequency analysis |

---

## Pyjail (3 challenges)

| Challenge | Difficulty | Vulnerability |
|-----------|------------|---------------|
| **Prison Break** | Medium | Python sandbox escape with restricted __builtins__; bypass using object introspection |
| **Cipher-Prison** | Medium | Dynamic Caesar cipher rotates keyboard mapping after each input; decode while evading blacklist |
| **Blacklist-Hell** | Hard | Extreme blacklist blocks digits, quotes, underscores, operators; construct payloads with chr()/len() |

---

## Reverse Engineering (2 challenges)

| Challenge | Difficulty | Vulnerability |
|-----------|------------|---------------|
| **License Checker** | Easy | License key validation algorithm; reverse engineer checksum calculation and format requirements |
| **Endgame Protocol** | Hard | Complex obfuscated protocol with balanced true/false responses; reverse logic to extract flag |

---

## Web Exploitation (9 challenges)

| Challenge | Difficulty | Vulnerability |
|-----------|------------|---------------|
| **Plain Sight** | Easy | Flag visible in HTML source, JavaScript, or accessible endpoint; basic reconnaissance |
| **Time Window Exposure** | Easy | Race condition with 100ms exposure window every minute; automate requests to catch flag |
| **Wrong Password** | Easy | Timing side-channel or response analysis reveals information despite wrong credentials |
| **Auth Adventure** | Medium | JWT weak secret key brute-force; algorithm confusion attack (RS256→HS256) |
| **Secure Portal** | Medium | Insecure Direct Object Reference (IDOR); enumerate user IDs to access unauthorized data |
| **Stranger Things** | Medium | HTTP request smuggling or header manipulation reveals alternate response with flag |
| **Flag in Cache** | Medium | Browser cache retention vulnerability; flag removed from server but cached by browser |
| **Overthinker** | Medium | Anti-pattern challenge; solution is trivial but players overthink complexity |
| **Nothing Works** | Hard | Resilience testing; requires extreme persistence or timing-based race condition exploitation |

---

## OSINT (1 challenge)

| Challenge | Difficulty | Vulnerability |
|-----------|------------|---------------|
| **GitHub Ghost** | Easy | Git commit history forensics; recover deleted sensitive file from previous commit |

---

## Miscellaneous (6 challenges)

| Challenge | Difficulty | Vulnerability |
|-----------|------------|---------------|
| **Missing Tools** | Easy | Alternative command usage; `cat` removed but other file readers (less/more/head/tail) available |
| **Echo Chamber** | Medium | TCP self-connect vulnerability or debug test mode bypass; exploit network service logic |
| **Flag is Pattern** | Medium | File metadata or ordering analysis; flag encoded in structure rather than content |
| **Lying QR** | Medium | QR code error correction abuse; displays decoy flag while real flag hidden in redundant data |
| **Don't Read Me** | Hard | Zero-width Unicode steganography (U+200B/U+200C) in visible text encodes binary flag |
| **The Last Input** | Hard | Reverse psychology; correct answer is empty/null input; tests assumption breaking |

---

## Vulnerability Categories Summary

### Memory Exploitation
- Buffer Overflow (stack-based)
- Use-After-Free (heap-based)

### Web Security
- JWT Authentication Bypass
- IDOR (Insecure Direct Object Reference)
- HTTP Request Smuggling
- Race Conditions / Timing Attacks
- Browser Cache Exploitation

### Cryptography & Encoding
- Caesar Cipher
- Character Encoding Manipulation

### Sandbox Escape
- Python Jail Bypass Techniques
- Blacklist Evasion via Dynamic Construction
- Object Introspection Abuse

### Reverse Engineering
- Algorithm Reconstruction
- Protocol Analysis
- Binary Static Analysis

### Steganography
- QR Code Error Correction Abuse
- Unicode Zero-Width Character Hiding

### OSINT
- Git History Analysis
- Deleted File Recovery

### Logic & Algorithms
- Graph Traversal (BFS/DFS)
- Tree Algorithms
- Pattern Recognition
- Regular Expressions

### Miscellaneous
- Linux Alternative Tools
- Network Protocol Exploitation
- Lateral Thinking / Anti-Patterns

---

## Statistics

**Total Challenges:** 29  
**Difficulty Breakdown:**
- Easy: 8 challenges (28%)
- Medium: 16 challenges (55%)
- Hard: 5 challenges (17%)

**Category Distribution:**
- Web Exploitation: 9 (31%)
- Miscellaneous: 6 (21%)
- Coding: 5 (17%)
- Pyjail: 3 (10%)
- Binary Exploitation: 2 (7%)
- Reverse Engineering: 2 (7%)
- Cryptography: 1 (3%)
- OSINT: 1 (3%)
