# Regex Master

A comprehensive string processing challenge testing regular expression skills across multiple real-world scenarios.

---

## Challenge Info

| Field | Value |
|-------|-------|
| **Name** | Regex Master |
| **Category** | String Processing / Coding |
| **Difficulty** | Medium |
| **Flag** | `DSCCTF{R3G3X_P4TT3RN_M4ST3R_2026}` |
| **Author** | ShadowPB |
| **Port** | 8006 |

---

## Challenge Description

🔤 Welcome to the ultimate Regular Expression challenge! Test your pattern matching skills across multiple real-world scenarios.

Master the art of regular expressions through a series of progressively challenging pattern matching tasks. From email validation to complex text extraction, prove your regex expertise!

Perfect score on all challenges unlocks the final flag.

---

## Files

- `regex_master.py` - Interactive challenge with 5 regex tasks
- `solve.py` - Complete solutions with explanations
- `flag.txt` - Target flag
- `description.md` - Challenge description
- `Dockerfile` - Container setup
- `docker-compose.yml` - Easy deployment

---

## Quick Start

### Interactive Mode
```bash
# Run the interactive challenge
python3 regex_master.py

# Complete all 5 challenges for perfect score
```

### Solution Mode
```bash
# See all solutions
python3 solve.py

# Get cheat sheet
python3 solve.py cheat

# Quick flag extraction
python3 solve.py flag
```

---

## Challenge Categories

### 1. Email Validation ✉️
**Objective**: Write a regex to match valid email addresses

**Test Cases**:
- `admin@ctf.com` ✅
- `user123@example.org` ✅
- `test.email+tag@domain.co.uk` ✅
- `invalid.email@` ❌
- `not_an_email` ❌

**Solution**:
```regex
^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$
```

### 2. Phone Number Extraction 📞
**Objective**: Extract phone numbers in various formats

**Test Cases**:
- `+1-555-123-4567`
- `(555) 987-6543`
- `555.321.9876`
- `call me at 555-0123 today`

**Solution**:
```regex
(\+?1[-.\s]?)?\(?([0-9]{3})\)?[-.\s]?([0-9]{3})[-.\s]?([0-9]{4})
```

### 3. Flag Hunter 🚩
**Objective**: Find all CTF flags in mixed text

**Test Cases**:
- `DSCCTF{R3G3X_P4TT3RN_M4ST3R_2026}`
- `Flag: DSCCTF{hidden_in_text}`
- `Multiple flags: DSCCTF{flag1} and DSCCTF{flag2}`
- `dscctf{lowercase_flag}` (shouldn't match)

**Solution**:
```regex
DSCCTF\{[^}]+\}
```

### 4. IPv4 Address Validation 🌐
**Objective**: Match valid IPv4 addresses only (0-255 range)

**Test Cases**:
- `192.168.1.1` ✅
- `10.0.0.255` ✅
- `256.1.1.1` ❌ (out of range)
- `127.0.0.1` ✅
- `0.0.0.0` ✅

**Solution**:
```regex
^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$
```

### 5. Password Strength 🔒
**Objective**: Match passwords with:
- At least 8 characters
- 1 uppercase letter
- 1 lowercase letter  
- 1 digit
- 1 special character

**Test Cases**:
- `Password123!` ✅
- `simple_password` ❌
- `Strong@Pass1` ✅
- `12345678` ❌

**Solution**:
```regex
^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$
```

---

## Learning Objectives

- **Regex Syntax**: Understanding metacharacters and quantifiers
- **Pattern Matching**: Designing patterns for specific requirements
- **Input Validation**: Real-world data validation techniques
- **Text Extraction**: Mining information from unstructured text
- **Advanced Features**: Lookaheads, groups, and anchors

---

## Regex Cheat Sheet

### Basic Metacharacters
| Symbol | Meaning |
|--------|---------|
| `^` | Start of string |
| `$` | End of string |
| `.` | Any character |
| `*` | 0 or more |
| `+` | 1 or more |
| `?` | 0 or 1 |
| `\d` | Any digit |
| `\w` | Word character |
| `\s` | Whitespace |

### Character Classes
```regex
[abc]      # Any of a, b, c
[^abc]     # NOT a, b, or c
[a-z]      # Lowercase letters
[A-Z]      # Uppercase letters
[0-9]      # Digits
[a-zA-Z0-9]# Alphanumeric
```

### Quantifiers
```regex
{n}        # Exactly n times
{n,}       # n or more times
{n,m}      # Between n and m times
*          # 0 or more (same as {0,})
+          # 1 or more (same as {1,})
?          # 0 or 1 (same as {0,1})
```

### Groups and Lookaheads
```regex
(group)    # Capturing group
(?:group)  # Non-capturing group
(?=...)    # Positive lookahead
(?!...)    # Negative lookahead
(?<=...)   # Positive lookbehind
(?<!...)   # Negative lookbehind
```

---

## Common Regex Patterns

### Email
```regex
^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$
```

### URL
```regex
https?://(?:[-\w.])+(?:\:[0-9]+)?(?:/(?:[\w/_.])*(?:\?(?:[\w&=%.])*)?(?:\#(?:[\w.])*)?)?
```

### Date (YYYY-MM-DD)
```regex
^\d{4}-\d{2}-\d{2}$
```

### Time (HH:MM)
```regex
^([01]?[0-9]|2[0-3]):[0-5][0-9]$
```

### Hex Color
```regex
^#([A-Fa-f0-9]{6}|[A-Fa-f0-9]{3})$
```

### Credit Card
```regex
^(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3[0-9]{13})$
```

---

## Advanced Techniques

### Lookahead for Password Validation
```regex
# Must contain uppercase, lowercase, digit, special char
^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$
```

### Named Groups
```python
import re
pattern = r'(?P<year>\d{4})-(?P<month>\d{2})-(?P<day>\d{2})'
match = re.search(pattern, '2024-12-25')
print(match.group('year'))   # 2024
print(match.group('month'))  # 12
```

### Conditional Matching
```regex
# Match IPv4 or IPv6
^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$|^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$
```

---

## Testing Tools

### Online Validators
- [regex101.com](https://regex101.com) - Interactive regex tester
- [regexr.com](https://regexr.com) - Visual regex builder
- [regexpal.com](https://regexpal.com) - Simple online tester

### Python Testing
```python
import re

pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
test_strings = ['test@example.com', 'invalid@']

for test in test_strings:
    match = re.match(pattern, test)
    print(f"{test}: {'Valid' if match else 'Invalid'}")
```

---

## Performance Tips

### Optimization Strategies
1. **Anchor patterns** with `^` and `$` when appropriate
2. **Use non-capturing groups** `(?:...)` instead of `(...)`
3. **Avoid catastrophic backtracking** with nested quantifiers
4. **Pre-compile patterns** in loops: `pattern = re.compile(r'...')`
5. **Use specific character classes** instead of `.` when possible

### Example Optimization
```python
# Slow - catastrophic backtracking
slow_pattern = r'(a+)+b'

# Fast - atomic grouping
fast_pattern = r'a+b'
```

---

## Hints

1. Start with simple patterns and build complexity gradually
2. Test edge cases, especially boundary conditions
3. Use online regex testers for debugging
4. Remember that regex engines are greedy by default
5. Perfect score requires getting ALL test cases correct

This challenge develops practical regex skills essential for text processing, data validation, and security analysis.