# Digital Footprints - OSINT Challenge Writeup

**Author:** Pranav Barathi & Hiral Jain  
**Difficulty:** Easy  
**Points:** 200  
**Flag:** `DSCCTF{tr4c3d_th3_d1g1t4l_tr41l_2026}`

## Challenge Description

This OSINT challenge requires you to follow a digital trail across multiple platforms to uncover a hidden flag. Starting with the Digital Security Champions (DSC) LinkedIn presence, you'll need to investigate corporate profiles, analyze social media accounts, extract metadata from images, and discover hidden content.

## Solution Walkthrough

### Step 1: LinkedIn Corporate Intelligence

The investigation begins with finding the DSC official LinkedIn page:

1. **Company Page Discovery:** Search for "Digital Security Champions DSC" on LinkedIn
2. **Creator Identification:** Find challenge creators listed in About section
   - Pranav Barathi (OSINT Specialist & Co-Creator)
   - Hiral Jain (@spaggetti99, Social Media Intelligence Expert)
3. **Profile Investigation:** Visit both creators' individual profiles
4. **Shared Posts Analysis:** Look for shared posts about Digital Footprints challenge

### Step 2: LinkedIn Clue Extraction

Both creators have shared posts with Twitter directions:

**Pranav's Post (Part 1):**
- Reveals Twitter account pattern: @DSC_[CHALLENGE_TYPE]_2026
- Indicates Twitter bio contains first half of clue

**Hiral's Post (Part 2):**  
- Explains need to combine Twitter bio + banner secret
- Confirms Twitter leads to Instagram

### Step 3: Twitter Investigation

Following the pattern @DSC_[TYPE]_2026 leads to @DSC_CTF_2026:

**Account Analysis:**
- **Bio:** "Find our dedicated investigation account on Instagram 📸"
- **Banner:** Contains hidden text "@dsc_digital_footprints_2026"
- **Tweets:** Confirm Instagram account naming pattern

### Step 4: Instagram Discovery

Navigate to @dsc_digital_footprints_2026:
- Dedicated challenge account
- Contains GitHub repository clues
- Leads to DSC-CTF-2026/hidden-treasures-026

The `treasure.png` file contains crucial information in its metadata:

```bash
exiftool -Comment treasure.png
```

This reveals:
```
Comment: Password: SecretKey2026
```

### Step 5: GitHub Repository Analysis

Navigate to DSC-CTF-2026/hidden-treasures-026:
- **Repository:** `DSC-CTF-2026/hidden-treasures-026`
- **Key Files:** 
  - `decoy.png` - Red herring image
  - `treasure.png` - Contains metadata with password
  - `secret.zip` - Password-protected archive

### Step 6: Image Metadata Analysis

Using the extracted password, decrypt the ZIP file:

```bash
unzip secret.zip
# Enter password: SecretKey2026
```

This extracts `secret.txt`, which appears empty at first glance.

### Step 7: Password-Protected File Extraction

Using the extracted password, decrypt the ZIP file:

```bash
unzip secret.zip
# Enter password: SecretKey2026
```

This extracts `secret.txt`, which appears empty at first glance.

### Step 8: Hidden Text Discovery

The `secret.txt` file uses white text on a white background to hide content:

**Method 1 - Text Editor Selection:**
- Open the file in any text editor
- Select all text (Ctrl+A)
- The hidden flag becomes visible

**Method 2 - HTML Source Inspection:**
```html
<div style="color: white; background-color: white;">
DSCCTF{tr4c3d_th3_d1g1t4l_tr41l_2026}
</div>
```

**Method 3 - Command Line:**
```bash
grep -o 'DSCCTF{[^}]*}' secret.txt
```

## Technical Skills Required

1. **Corporate Intelligence (CORPINT)**
   - Company page investigation
   - Employee/creator identification
   - Professional network analysis

2. **Social Media Intelligence (SOCINT)**
   - Cross-platform investigation
   - Username pattern recognition
   - Content correlation analysis

3. **Twitter Investigation**
   - Bio analysis
   - Banner image examination
   - Account verification techniques

4. **Instagram OSINT**
   - Dedicated account discovery
   - Challenge-specific content analysis
5. **GitHub Repository Analysis**
   - Repository discovery techniques  
   - File analysis and download
   - Commit history examination

6. **Digital Forensics**
   - Image metadata extraction
   - EXIF data analysis
   - File format understanding

7. **Steganography**
   - Hidden text techniques
   - CSS/HTML obfuscation
   - Visual steganography concepts

8. **Password Security**
   - Archive decryption
   - Password extraction
   - Multi-layer security

## Automated Solution

The challenge includes an automated solver (`solve.py`) that demonstrates the complete solution path:

```bash
cd repository_files/
python3 ../solve.py
```

## Learning Objectives

This challenge teaches participants:

1. **Corporate OSINT:** Starting investigations with official organizational presence
2. **Multi-Platform Correlation:** Connecting information across LinkedIn, Twitter, Instagram, and GitHub  
3. **Professional Network Analysis:** Understanding how corporate social media structures work
4. **Systematic Investigation:** Following a logical progression through multiple platforms
5. **Pattern Recognition:** Identifying naming conventions and organizational structures

## Prevention/Mitigation

In real-world scenarios, this challenge highlights:

- **Metadata Leakage:** Always strip sensitive information from files before sharing
- **Social Media OPSEC:** Be aware of what information you reveal across platforms
- **Password Security:** Don't embed passwords in metadata or easily discoverable locations
- **Information Correlation:** How seemingly unrelated data points can be connected

## Tools Used

- `exiftool` - Metadata extraction
- `unzip` - Archive extraction  
- Text editor - Hidden content revelation
- Web browser - Repository access
- Social media platforms - Intelligence gathering

## Flag

```
DSCCTF{tr4c3d_th3_d1g1t4l_tr41l_2026}
```

---

**Note:** This writeup assumes the GitHub repository `DSC-CTF-2026/hidden-treasures-026` has been set up with the appropriate social media accounts containing the necessary clues.