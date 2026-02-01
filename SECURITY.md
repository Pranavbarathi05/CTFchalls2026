# Security Policy

## About This Repository

This repository contains CTF (Capture The Flag) challenges with **intentional vulnerabilities** designed for educational purposes. The challenges are meant to be solved by exploiting these vulnerabilities.

## Supported Versions

CTF challenges are supported for the duration of the active event and maintained thereafter.

| Version | Status | Support |
| ------- | ------ | ------- |
| 2026 Challenges | ✅ Active | Currently maintained and deployed |
| 2025 Challenges | 📦 Archived | No longer receiving updates |

## What to Report

### ✅ **DO Report These:**

1. **Unintended Solutions** - Ways to solve challenges that bypass the intended path
2. **Infrastructure Vulnerabilities** - Security issues with deployment scripts, Docker configurations, or server setup
3. **Information Leaks** - Flags or solutions visible without solving the challenge
4. **Broken Challenges** - Challenges that cannot be solved as intended due to bugs
5. **Dockerfile/Compose Issues** - Security misconfigurations in container setup
6. **Resource Exhaustion** - DoS vulnerabilities that could affect other players

### ❌ **DO NOT Report These:**

1. **Intended Challenge Vulnerabilities** - SQL injection, XSS, buffer overflows, etc. in challenge files (these are the point!)
2. **Challenge Solutions** - Please don't spoil the fun for others
3. **Easy/Hard Difficulty** - Subjective opinions about challenge difficulty

## Reporting a Vulnerability

### For Unintended Vulnerabilities or Infrastructure Issues:

1. **Private Disclosure Required**
   - 📧 Email: security@dscjssstuniv.in (or your actual contact)
   - 🔒 Use encrypted communication if possible
   - ⚠️ **DO NOT** open public GitHub issues for security concerns

2. **Include in Your Report:**
   - Challenge name and category
   - Clear description of the issue
   - Steps to reproduce
   - Whether it's an unintended solution or infrastructure issue
   - Your suggested fix (optional)

3. **Response Timeline:**
   - Initial acknowledgment: Within 48 hours
   - Status update: Within 7 days
   - Fix deployment: Depends on severity
     - Critical (flag leaks): Within 24 hours
     - High (unintended solutions): Within 3-5 days
     - Medium (minor issues): Within 1-2 weeks

4. **What to Expect:**
   - **Accepted**: We'll fix the issue, credit you (if desired), and may offer CTF points as a bounty
   - **Working as Intended**: We'll explain why it's intentional
   - **Declined**: We'll provide reasoning if we decide not to fix it

## Hall of Fame

Security researchers who help us improve challenge quality:

- *Your name could be here!*

## Responsible Disclosure

- Please allow us reasonable time to fix issues before public disclosure
- We commit to acknowledging and addressing reports promptly
- We appreciate researchers who help us maintain fair and secure CTF infrastructure

## Contact

- **Event Organizers**: DSC JSS STUN University
- **Security Contact**: [Add your contact email]
- **GitHub Issues**: Only for non-security bugs and feature requests

---

**Note**: This repository is for educational purposes. All vulnerabilities in challenge files are intentional. Breaking into production infrastructure or other players' instances is strictly prohibited.
