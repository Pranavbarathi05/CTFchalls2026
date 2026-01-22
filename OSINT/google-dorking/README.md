# The Google Dorking Challenge

An OSINT challenge teaching Google dorking techniques and information disclosure through exposed documents.

## Challenge Info

| Field | Value |
|-------|-------|
| **Name** | The Google Dorking Challenge |
| **Category** | OSINT |
| **Difficulty** | Easy |
| **Points** | 100 |
| **Flag** | `DSCCTF{g00gl3_d0rk1ng_f1nd5_3v3ryth1ng_2026}` |

---

## Description

🔍 The Google Dorking Challenge [OSINT] - 100 pts

SecureTech Industries is a security company that provides enterprise solutions.

They have a website, but that's not all...
Sometimes companies accidentally expose internal documents online.

Your mission: Find the hidden document that contains sensitive information!

---

## Solution

### In a Real Scenario:

You would use Google dorks like:

```
site:securetech-industries.local filetype:pdf
site:securetech-industries.local filetype:pdf "confidential"
site:securetech-industries.local filetype:pdf "security audit"
site:securetech-industries.local filetype:pdf "flag"
```

### For This CTF:

1. Navigate to the `challenge/` directory
2. Look for PDF or document files
3. Open `SecureTech_Security_Audit_Q4_2025.pdf.txt`
4. Find the embedded training flag in the document
5. Flag: `DSCCTF{g00gl3_d0rk1ng_f1nd5_3v3ryth1ng_2026}`

---

## Learning Objectives

- **Google Dorking**: Advanced search operators for finding specific information
- **Information Disclosure**: How exposed documents can leak sensitive data
- **OSINT Techniques**: Open Source Intelligence gathering methods
- **Document Security**: Understanding why document exposure is dangerous

---

## Key Concepts

### What is Google Dorking?

Google Dorking (or Google Hacking) uses advanced search operators to find information that organizations may not want public:

**Common Operators:**
```
site:         Search within specific domain
filetype:     Find specific file types  
intitle:      Search in page titles
inurl:        Search in URLs
intext:       Search in page content
cache:        View cached version
```

### Powerful Dork Examples:

```bash
# Find exposed PDFs
site:example.com filetype:pdf

# Find confidential documents
site:example.com filetype:pdf "confidential"

# Find exposed Excel files
site:example.com filetype:xlsx

# Find configuration files
site:example.com filetype:env

# Find exposed database backups
site:example.com filetype:sql

# Find exposed directory listings
intitle:"index of" site:example.com

# Find login pages
inurl:admin site:example.com

# Find exposed API keys
site:example.com "api_key"

# Find exposed credentials
site:example.com filetype:txt password

# Find exposed git repos
site:example.com inurl:.git
```

---

## Real-World Impact

### What Can Be Found:

- ✅ Employee directories and contact info
- ✅ Internal memos and reports
- ✅ Financial documents
- ✅ Confidential presentations
- ✅ Source code and technical specs
- ✅ Login credentials
- ✅ API keys and tokens
- ✅ Customer data

### Famous Examples:

1. **Government Documents**: Classified information inadvertently published
2. **Corporate Leaks**: M&A documents, financial reports
3. **Healthcare**: HIPAA violations through exposed patient records
4. **Defense Contractors**: Technical specifications for military equipment
5. **Social Security Numbers**: Exposed in poorly secured PDFs

---

## Defense Strategies

### For Organizations:

1. **Audit Public Exposure**
   ```bash
   # Check what Google has indexed
   site:yourcompany.com
   ```

2. **Use robots.txt** (but don't rely on it alone)
   ```
   User-agent: *
   Disallow: /internal/
   ```

3. **Remove Indexed Content**
   - Google Search Console → Request removal
   - Update robots.txt and wait for re-crawl

4. **Metadata Scrubbing**
   - Remove author names, timestamps
   - Strip sensitive comments from documents
   - Use PDF sanitization tools

5. **Access Controls**
   - Authentication on sensitive directories
   - Whitelist IP addresses
   - Use VPN for internal resources

6. **Regular Monitoring**
   - Set up Google Alerts for: `site:yourcompany.com confidential`
   - Monitor for exposed data regularly

---

## Advanced Dorking Techniques

### Combining Operators:

```bash
# Multiple conditions
site:example.com filetype:pdf (confidential OR secret OR internal)

# Exclude results
site:example.com -www -blog

# Date ranges
site:example.com after:2024-01-01

# Wildcard searches
site:*.example.com
```

### Finding Specific Vulnerabilities:

```bash
# Login pages
inurl:login site:example.com

# phpMyAdmin installations
intitle:"phpMyAdmin" inurl:index.php

# WordPress installs
site:example.com inurl:wp-content

# Apache server info
intitle:"Apache Status" "Apache Server Status for"

# Open cameras
inurl:view.shtml intitle:"Network Camera"
```

---

## Tools for Google Dorking

1. **Google Hacking Database (GHDB)**
   - https://www.exploit-db.com/google-hacking-database
   - Collection of useful dorks

2. **Dorking Tools:**
   - Pagodo: Automated Google dorking
   - GooFuzz: Fuzzing with Google dorks
   - dork-cli: Command-line dorking

3. **Browser Extensions:**
   - Google Hacking Diggity
   - OSINT tools extensions

---

## Simulation Setup

Since this is a CTF challenge, we can't actually index content on Google. Instead:

1. Provide the files locally
2. Describe what dorks would find them
3. Players manually search through files
4. Learn the concepts without actually spamming Google

### Creating Realistic Scenarios:

- Use naming conventions that match real documents
- Add metadata that would normally be indexed
- Include content snippets that would appear in search results

---

## Ethical Considerations

### Legal Aspects:
- Using Google dorks on public data is legal
- Accessing the found data might not be
- Always get permission for security testing
- Follow responsible disclosure practices

### Ethical Hacking:
- Don't download massive amounts of data
- Don't distribute found sensitive information
- Report findings to organizations responsibly
- Respect privacy and confidentiality

---

## Practice Resources

**Try Dorking On:**
- github.com (find exposed API keys)
- pastebin.com (search for leaks)
- Your own domain (see what's exposed)

**Learning Resources:**
- Google Search Operators official docs
- Exploit-DB Google Hacking Database
- OSINT Framework tools list

---

## Files

```
google-dorking/
├── challenge/
│   ├── index.html                           # Company website
│   └── SecureTech_Security_Audit_Q4_2025.pdf.txt  # "Leaked" document
├── description.md                            # Challenge description
└── README.md                                # This file
```

---

## Deployment Notes

This challenge is **file-based** rather than web-based, so:
- No Docker container needed
- Files provided as part of challenge download
- Players search through local files
- Simulates what they would find via Google

### Alternative: Web Version

If you want to make it more realistic:
1. Host files on a test domain
2. Submit to Google for indexing (takes time)
3. Or use a local search engine simulation

---

## Flag

`DSCCTF{g00gl3_d0rk1ng_f1nd5_3v3ryth1ng_2026}`

The flag message: "Google dorking finds everything" - because it really does!

---

## Extension Ideas

**Make it harder:**
- Multiple documents, only one has the flag
- Need to combine multiple dorks
- Flag split across multiple documents
- Require finding specific version of document

**Additional challenges:**
- Find employee email format from LinkedIn
- Locate subdomain using certificate transparency
- Find organization's infrastructure via Shodan queries
