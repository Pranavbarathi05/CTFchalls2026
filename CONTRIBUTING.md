# Contributing Guidelines

Thank you for your interest in contributing to CTFchalls2026! This document provides guidelines for contributing new challenges, improvements, and fixes to our CTF platform.

---

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [How Can I Contribute?](#how-can-i-contribute)
- [Challenge Contribution Guidelines](#challenge-contribution-guidelines)
- [Pull Request Process](#pull-request-process)
- [Style Guidelines](#style-guidelines)
- [Testing Requirements](#testing-requirements)
- [Directory Structure](#directory-structure)

---

## Code of Conduct

### Our Standards

- **Be respectful** - Treat all contributors with respect
- **Be constructive** - Provide helpful feedback
- **Be inclusive** - Welcome diverse perspectives
- **Be ethical** - Don't exploit vulnerabilities for malicious purposes
- **Be educational** - Focus on learning and teaching security concepts

### Unacceptable Behavior

- Harassment, discrimination, or trolling
- Publishing others' private information
- Malicious exploitation of platform vulnerabilities
- Submitting intentionally broken or malicious code

---

## How Can I Contribute?

### 1. 🎯 Submit New Challenges

We welcome new challenge submissions in the following categories:
- Web Exploitation
- Binary Exploitation (PWN)
- Reverse Engineering
- Cryptography
- Forensics
- Miscellaneous
- Pyjail
- OSINT
- Coding/Programming

### 2. 🐛 Report Bugs

Found an issue? Please report:
- Unintended solutions (exploits)
- Broken challenges
- Deployment issues
- Documentation errors

### 3. 📚 Improve Documentation

Help us improve:
- Challenge descriptions
- Solution writeups
- Deployment guides
- Architecture documentation

### 4. 🔧 Fix Issues

Check our [Issues](https://github.com/Pranavbarathi05/CTFchalls2026/issues) page for:
- `good-first-issue` - Easy tasks for newcomers
- `help-wanted` - Tasks needing assistance
- `bug` - Known issues to fix

---

## Challenge Contribution Guidelines

### General Requirements

All challenges must include:

1. **Challenge Files**
   - Source code (well-commented)
   - Dockerfile and docker-compose.yml
   - Build scripts if needed

2. **Documentation**
   - README.md with challenge description
   - Solution/writeup (in `/solve` directory)
   - Hints (optional, in `/hints` directory)

3. **Testing**
   - Verified working deployment
   - Tested intended solution
   - Checked for unintended solutions

4. **Flag Format**
   - Must follow format: `DSCCTF{...}`
   - Should be descriptive and related to challenge
   - Example: `DSCCTF{h3ll0_w0rld_2026}`

### Challenge Quality Standards

#### ✅ Good Challenges

- **Educational** - Teaches a specific security concept
- **Fair difficulty** - Matches stated difficulty level
- **Clear objectives** - Players know what to find
- **No guessing** - Solution is logical, not random
- **Tested** - Works reliably without crashes
- **Documented** - Clear setup and solution instructions

#### ❌ Avoid

- **Guessy challenges** - Requiring random guessing
- **Unstable services** - Frequent crashes or timeouts
- **Unclear objectives** - Players don't know what to do
- **Poor documentation** - Missing setup or solution info
- **Broken challenges** - Don't work as intended
- **Excessive resources** - Require > 512MB RAM or > 1 CPU

---

## Pull Request Process

### Before Submitting

1. **Fork the repository**
   ```bash
   git clone https://github.com/Pranavbarathi05/CTFchalls2026.git
   cd CTFchalls2026
   git checkout -b feature/your-challenge-name
   ```

2. **Create your challenge directory**
   ```bash
   mkdir -p category/challenge-name
   cd category/challenge-name
   ```

3. **Follow the directory structure** (see below)

4. **Test locally**
   ```bash
   docker-compose up --build
   # Test challenge functionality
   # Verify intended solution works
   # Check for unintended solutions
   ```

5. **Update documentation**
   - Add challenge to main README.md
   - Update ARCHITECTURE.md if needed
   - Create challenge-specific README.md

### Submitting Pull Request

1. **Commit your changes**
   ```bash
   git add .
   git commit -m "Add: [Category] Challenge Name"
   ```

2. **Push to your fork**
   ```bash
   git push origin feature/your-challenge-name
   ```

3. **Create Pull Request**
   - Use template below
   - Reference any related issues
   - Add screenshots/demos if applicable

### Pull Request Template

```markdown
## Challenge Information

**Challenge Name:** 
**Category:** 
**Difficulty:** (Easy/Medium/Hard)
**Points:** (100/200/300/400/500)
**Flag:** DSCCTF{...}

## Description

Brief description of what the challenge teaches.

## Testing Checklist

- [ ] Challenge builds successfully with Docker
- [ ] Intended solution tested and works
- [ ] No unintended solutions found
- [ ] Documentation is complete
- [ ] Flag follows DSCCTF{...} format
- [ ] Resource limits defined (if applicable)
- [ ] README.md included
- [ ] Solution writeup included

## Additional Notes

Any special setup requirements or notes for reviewers.
```

### Review Process

1. **Automated checks** - CI/CD will verify basic requirements
2. **Maintainer review** - We'll test your challenge
3. **Feedback** - We may request changes
4. **Approval** - Once approved, we'll merge!

**Expected timeline:** 3-7 days for review

---

## Style Guidelines

### Code Style

**Python:**
```python
# Use black formatter
# Install: pip install black
black your_file.py

# Follow PEP 8
# Max line length: 88 characters
```

**JavaScript/Node.js:**
```javascript
// Use Prettier
// Install: npm install -g prettier
prettier --write your_file.js

// Use semicolons
// 2-space indentation
```

**Bash:**
```bash
# Use shellcheck
# Install: sudo apt install shellcheck
shellcheck your_script.sh

# 2-space indentation
# Quote variables: "$variable"
```

### Docker Best Practices

```dockerfile
# Use specific versions, not 'latest'
FROM python:3.11-slim

# Run as non-root user
RUN useradd -m -u 1000 ctfuser
USER ctfuser

# Multi-stage builds for smaller images
# Copy only necessary files
# Clean up in same layer to reduce size
```

### Documentation Style

- Use Markdown formatting
- Include code examples
- Add comments for clarity
- Use emojis sparingly for readability
- Keep line length reasonable (80-100 chars)

---

## Testing Requirements

### Local Testing

Before submitting, test:

1. **Build successfully**
   ```bash
   docker-compose up --build
   ```

2. **Service is accessible**
   ```bash
   curl http://localhost:PORT
   # or
   nc localhost PORT
   ```

3. **Intended solution works**
   ```bash
   cd solve
   python3 solver.py
   # Should output: DSCCTF{...}
   ```

4. **No unintended solutions**
   - Try common bypass techniques
   - Test edge cases
   - Check for info leaks

5. **Resource usage acceptable**
   ```bash
   docker stats
   # Memory should stay under limits
   ```

### Security Testing

- [ ] No hardcoded credentials in code
- [ ] No sensitive data in Docker images
- [ ] Service doesn't expose unnecessary ports
- [ ] Input validation is proper
- [ ] No obvious command injection
- [ ] Resource limits prevent DoS

---

## Directory Structure

### For New Challenges

```
category/challenge-name/
├── challenge/
│   ├── Dockerfile          # Container definition
│   ├── docker-compose.yml  # Service configuration
│   ├── flag.txt            # The flag (DSCCTF{...})
│   ├── src/                # Source code
│   │   └── app.py          # Main application
│   └── description.md      # Challenge description for CTFd
├── solve/
│   ├── solver.py           # Automated solution script
│   └── writeup.md          # Detailed solution explanation
├── hints/                  # Optional hints
│   ├── hint1.md
│   └── hint2.md
└── README.md               # Challenge documentation
```

### README.md Template for Challenges

```markdown
# Challenge Name

Brief one-line description.

## Challenge Info

| Field         | Value |
|---------------|-------|
| **Name**      | Challenge Name |
| **Category**  | Web/PWN/Reverse/etc |
| **Difficulty**| Easy/Medium/Hard |
| **Points**    | 100-500 |
| **Flag**      | DSCCTF{...} |
| **Port**      | 1337 (if applicable) |

## Description

Full challenge description that players will see.

## Learning Objectives

What security concept does this teach?

## Deployment

```bash
docker-compose up -d --build
```

## Solution

High-level overview of the solution approach.
See `/solve/writeup.md` for detailed solution.

## Author

Your Name (@your_github_username)
```

---

## Architecture Considerations

When contributing challenges, consider:

### Resource Allocation

- **EC2-1** - Web challenges (lightweight HTTP)
- **EC2-2** - Coding, Crypto, Light challenges
- **EC2-3** - PWN, Pyjail, Heavy challenges

### Container Limits

```yaml
# For heavy workloads (PWN/Pyjail)
deploy:
  resources:
    limits:
      memory: 256m
      cpus: '0.5'
    pids: 100  # For pyjail only

# Security options
security_opt:
  - no-new-privileges:true
```

### Networking

- **HTTP services** - Use Traefik labels for HTTPS
- **TCP services** - Expose specific ports
- **No direct port exposure** - Use reverse proxy

See [ARCHITECTURE.md](ARCHITECTURE.md) for full details.

---

## Commit Message Guidelines

Follow conventional commits format:

```
<type>: <short summary>

<optional body>

<optional footer>
```

**Types:**
- `feat:` - New challenge or feature
- `fix:` - Bug fix
- `docs:` - Documentation changes
- `style:` - Code style changes (formatting)
- `refactor:` - Code refactoring
- `test:` - Adding tests
- `chore:` - Maintenance tasks

**Examples:**
```
feat: Add SQL injection challenge (Web)

Added beginner-friendly SQL injection challenge teaching
basic authentication bypass techniques.

Refs: #42

---

fix: Correct flag format in Caesar cipher challenge

Changed flag from DSCCTF{caesar123} to follow naming convention
DSCCTF{c43s4r_c1ph3r_2026}

Closes: #56

---

docs: Update deployment guide for EC2-3

Added resource limit explanation and troubleshooting steps
for OOM issues.
```

---

## Recognition

Contributors will be recognized in:

- Challenge author credit (README.md)
- Main repository CONTRIBUTORS.md file
- CTF platform "Challenge Authors" page
- Social media shoutouts (with permission)

### Hall of Fame

Top contributors each month:
- Most challenges contributed
- Best challenge quality
- Most helpful reviews

---

## Questions?

- **GitHub Issues:** https://github.com/Pranavbarathi05/CTFchalls2026/issues
- **Discussions:** https://github.com/Pranavbarathi05/CTFchalls2026/discussions
- **Email:** admin@dscjssstuniv.in

We appreciate your contributions to making this CTF platform better! 🎯🔒

---

**Last Updated:** 2026-02-01
