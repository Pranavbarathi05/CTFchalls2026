| Domain                  | Easy | Medium | Hard |
| ----------------------- | ---- | ------ | ---- |
| **Binary Exploitation** | 2    | 1      | 0    |
| **Coding**              | 0    | 4      | 0    |
| **Cryptography**        | 3    | 0      | 1    |
| **Forensics**           | 8    | 0      | 0    |
| **Pyjail**              | 1    | 1      | 1    |
| **Reverse Engineering** | 3    | 1      | 1    |
| **Web exploitation**    | 6    | 5      | 1    |
| **OSINT**               | 2    | 2      | 0    |
| **Misc**                | 2    | 3      | 3    |

## Total = 54


# CTF Challenge Port Mapping

**Complete reference for all challenge ports**  
**Last Updated:** 2026-01-23

---

## All Challenges with Ports

| External Port | Internal Port | Challenge Name | Category | Path |
|--------------|---------------|----------------|----------|------|
| 1337 | 1337 | cipher-prison | Pyjail | `pyjail/cipher-prison` |
| 1338 | 1338 | blacklist-hell | Pyjail | `pyjail/blacklist-hell` |
| 1339 | 1339 | math-prison | Reverse Engineering | `reverse_engineering/math-prison` |
| 2222 | 22 | missing_tools | Misc | `Misc/missing_tools` |
| 5001 | 5000 | robots-watching | Web | `web_exploitation/robots-watching` |
| 5002 | 5000 | cookie-recipe | Web | `web_exploitation/cookie-recipe` |
| 5003 | 5000 | curl-unfurl | Web | `web_exploitation/curl-unfurl` |
| 8001 | 8001 | caesars_pizza_menu | Cryptography | `cryptography/caesars_pizza_menu` |
| 8002 | 8002 | license_checker | Reverse Engineering | `reverse_engineering/license_checker` |
| 42552 | 42552 | Conditions | Reverse Engineering | `//ctf.dscjssstuniv.in:42552` |
| 8003 | 5000 | Time_window_Exposure | Web | `web_exploitation/Time_window_Exposure` |
| 8004 | 8004 | pathfinding_puzzle | Coding | `coding/pathfinding_puzzle` |
| 8005 | 8005 | tree_traversal_secret | Coding | `coding/tree_traversal_secret` |
| 8006 | 8006 | regex_master | Coding | `coding/regex_master` |
| 8007 | 8007 | secure_portal | Web | `web_exploitation/secure_portal` |
| 8008 | 8008 | auth_adventure | Web | `web_exploitation/auth_adventure` |
| 8009 | 8000 | flag_in_cache | Web | `web_exploitation/flag_in_cache` |
| 8010 | 8000 | nothing-works | Web | `web_exploitation/nothing-works` |
| 8011 | 8000 | overthinker | Web | `web_exploitation/overthinker` |
| 8012 | 8000 | plain-sight | Web | `web_exploitation/plain-sight` |
| 8013 | 8000 | stranger-things | Web | `web_exploitation/stranger-things` |
| 8014 | 8000 | wrong_password | Web | `web_exploitation/wrong_password` |
| 8015 | 8015 | Formality Breach | Misc | `Misc/Formality breach` |
| 8080 | 80 | echo_chamber | Misc | `Misc/echo_chamber` |
| 9001 | 9001 | overflow_academy | Binary Exploitation | `binary_exploitation/overflow_academy` |
| 9999 | 9999 | menu_pwner | Binary Exploitation | `binary_exploitation/menu_pwner` |

**Access URLs:**
- Pyjail challenges: `nc localhost <PORT>`
- Web/Coding/Crypto challenges: `http://localhost:<PORT>`
- Missing Tools (SSH): `ssh ctfplayer@localhost -p 2222` (password: `startwithbasics`)


# CTF Challenge List - DSCCTF 2026

## Binary Exploitation (3 challenges)

| Challenge | Difficulty | Vulnerability |
|-----------|------------|---------------|
| **Overflow Academy** | Easy | Stack-based buffer overflow with all protections disabled (no canary, no ASLR, executable stack) |
| **Zeros and Ones** | Easy | Simple 8-bit binary to ASCII conversion; decode binary string to reveal flag |
| **Menu Pwner** | Medium | Use-After-Free (UAF) memory corruption in heap allocations; reallocate freed chunks to gain control |

---

## Coding (5 challenges)

| Challenge | Difficulty | Vulnerability |
|-----------|------------|---------------|
| **Dystopian Arithmetic** | Medium | Logic manipulation where mathematical truths are redefined (2+2=5); accept false premises |
| **Pathfinding Puzzle** | Medium | Graph traversal and shortest path algorithms; collect flag pieces in correct order through maze |
| **Regex Master** | Medium | Regular expression crafting across 5 progressively harder pattern matching scenarios |
| **Tree Traversal Secret** | Medium | Binary tree traversal techniques (inorder/preorder/postorder); correct method reveals flag |

---

## Cryptography (1 challenge)

| Challenge | Difficulty | Vulnerability |
|-----------|------------|---------------|
| **Caesar's Pizza Menu** | Easy | Classical Caesar cipher with shift-based substitution; brute force or frequency analysis |
| **328** | Hard | sha256 layered on ascii and base64hex |
| **Binary Walk** | Easy | use binwalk to extract and decode binary + base64 + binary to check ShadowPB discord bio |
| **All Bases Covered** | Easy | basic base64hex |

---

## Pyjail (3 challenges)

| Challenge | Difficulty | Vulnerability |
|-----------|------------|---------------|
| **Prison Break** | Medium | Python sandbox escape with restricted __builtins__; bypass using object introspection |
| **Cipher-Prison** | Medium | Dynamic Caesar cipher rotates keyboard mapping after each input; decode while evading blacklist |
| **Blacklist-Hell** | Hard | Extreme blacklist blocks digits, quotes, underscores, operators; construct payloads with chr()/len() |

---

## Reverse Engineering (3 challenges)

| Challenge | Difficulty | Vulnerability |
|-----------|------------|---------------|
| **License Checker** | Easy | License key validation algorithm; reverse engineer checksum calculation and format requirements |
| **Math Prison** | Easy | Floating-point precision exploitation; reverse engineer cubic formula to find input where inverse fails |
| **Endgame Protocol** | Hard | Complex obfuscated protocol with balanced true/false responses; reverse logic to extract flag |
| **Has-to-Echo** | Easy | Behavioral pattern matching; must echo input exactly to pass validation checks |

---

## Web Exploitation (12 challenges)

| Challenge | Difficulty | Vulnerability |
|-----------|------------|---------------|
| **Plain Sight** | Easy | Flag visible in HTML source, JavaScript, or accessible endpoint; basic reconnaissance |
| **Time Window Exposure** | Easy | Race condition with 100ms exposure window every minute; automate requests to catch flag |
| **Wrong Password** | Easy | Timing side-channel or response analysis reveals information despite wrong credentials |
| **Robots Watching** | Easy | Robots.txt enumeration and information disclosure |
| **Cookie Recipe** | Easy | Cookie manipulation and client-side security bypass |
| **Curl Unfurl** | Easy | HTTP request manipulation and header abuse |
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

## Miscellaneous (7 challenges)

| Challenge | Difficulty | Vulnerability |
|-----------|------------|---------------|
| **Missing Tools** | Easy | Alternative command usage; `cat` removed but other file readers (less/more/head/tail) available |
| **Formality Breach** | Easy | Social engineering; fake Google Form allows infinite edits; `/viewanalytics` reveals flag |
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

**Total Challenges:** 40  
**Difficulty Breakdown:**
- Easy: 13 challenges (32%)
- Medium: 18 challenges (45%)
- Hard: 5 challenges (12%)
- Forensics: 5 challenges (12%)

**Category Distribution:**
- Web Exploitation: 12 (30%)
- Miscellaneous: 7 (17%)
- Coding: 5 (12%)
- Pyjail: 3 (7%)
- Binary Exploitation: 3 (7%)
- Reverse Engineering: 3 (7%)
- OSINT: 2 (5%)
- Forensics: 5 (14%)
- Cryptography: 1 (3%)
