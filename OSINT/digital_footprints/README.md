# Digital Footprints

A comprehensive **OSINT challenge** that tests social media investigation, metadata analysis, and hidden content discovery skills.

---

## Challenge Info

| Field | Value |
|------|------|
| **Name** | Digital Footprints |
| **Category** | osint |
| **Difficulty** | Easy |
| **Flag** | `DSCCTF{tr4c3d_th3_d1g1t4l_tr41l_2026}` |
| **Author** | ShadowPB and Spaghetti99 |
| **Skills Required** | Social media investigation, metadata analysis, steganography |

---

## Description

Every digital creator leaves traces across the web. The Digital Security Champions (DSC) organization has been sharing updates about their latest OSINT challenge project through their professional network. Your mission is to follow their digital breadcrumbs across multiple social media platforms to uncover a hidden repository and extract the flag through multiple layers of obfuscation.

This challenge combines:
- **Corporate Intelligence**: Starting with official organization profiles
- **Cross-Platform Investigation**: Following clues from LinkedIn to Twitter to Instagram
- **Repository Discovery**: Finding hidden GitHub repositories
- **Metadata Analysis**: Extracting information from image files
- **Steganography**: Uncovering hidden content in plain sight

---

## Step-by-Step Solution

### Step 1: LinkedIn Investigation (Starting Point)

Begin your investigation with the DSC official LinkedIn page:

**LinkedIn Company Page Discovery:**
1. Search for "Digital Security Champions DSC" on LinkedIn
2. Locate the official company page with ~2,800 followers
3. Check the About section to identify challenge creators: Pranav Barathi & Hiral Jain
4. Visit both creators' individual LinkedIn profiles

**Creator Profile Analysis:**
1. **Pranav Barathi**: Look for shared posts about Digital Footprints challenge
2. **Hiral Jain (@spaggetti99)**: Check shared posts for Twitter clues
3. Read both creators' post comments carefully
4. Extract two-part Twitter instructions from their shared posts

### Step 2: Twitter Investigation

Follow LinkedIn clues to Twitter:

**Twitter Account Discovery:**
1. Use pattern from LinkedIn: @DSC_[TYPE]_2026 = @DSC_CTF_2026
2. Visit @DSC_CTF_2026 official account
3. Read bio for Instagram direction
4. Examine banner image for hidden Instagram handle
5. Check recent tweets for account naming patterns

**Information Extraction:**
- Bio: "Find our dedicated investigation account on Instagram"  
- Banner: Contains "@dsc_digital_footprints_2026"
- Tweets: Confirm naming pattern @dsc_[project_name]_[year]

### Step 3: Instagram Investigation
2. Check bio links and tagged locations
3. Examine image captions for coded messages

### Step 2: Repository Discovery

The social media clues should lead to a GitHub repository:
- Repository name might be coded or cryptic
- Look for recently created repositories
- Check repository descriptions and README files
- The repository should contain exactly 3 files

### Step 3: Image Analysis

Once you find the repository, analyze the images:

**Image 1: "decoy.png"**
- Contains text: "This is not the flag"
- Serves as misdirection

**Image 2: "treasure.png"**  
- Contains text: "The flag is in this image"
- Contains hidden metadata with password

**Metadata Extraction:**
```bash
# Using exiftool to examine metadata
exiftool treasure.png

# Look specifically for comments
exiftool -Comment treasure.png

# Alternative tools
identify -verbose treasure.png
strings treasure.png
```

The password will be found in the image metadata comments section.

### Step 4: Password-Protected File

**File: "secret.txt"**
- Encrypted/password-protected text file
- Use the password found in image metadata
- File appears empty when decrypted

**Decryption methods:**
```bash
# If it's a ZIP file
unzip -P [password] secret.txt

# If it's GPG encrypted
gpg --decrypt secret.txt

# If it's base64 encoded with password
```

### Step 5: Hidden Text Discovery

The decrypted file contains the flag hidden in white text:
- Text color: #FFFFFF (white)
- Background color: #FFFFFF (white)  
- Flag is invisible but present in the file

**Discovery methods:**
1. **Select All**: Ctrl+A to highlight all text
2. **Change Background**: Copy to text editor and change background color
3. **HTML Inspection**: View source if it's an HTML file
4. **Hex Analysis**: Use hex editor to see hidden characters

```bash
# Using cat to display hidden content
cat secret.txt

# Using hexdump to see all characters
hexdump -C secret.txt

# Using strings command
strings secret.txt
```

### Step 6: Flag Extraction

The hidden text should reveal:
```
DSCCTF{h1dd3n_1n_pl41n_s1ght_2026}
```

---

## Challenge Files Structure

```
digital_footprints/
├── description.md
├── README.md
├── flag.txt
├── social_media_trail/
│   ├── twitter_clues.txt
│   ├── instagram_hints.txt
│   └── linkedin_trail.txt
└── repository_files/
    ├── decoy.png
    ├── treasure.png (with metadata)
    └── secret.txt (encrypted)
```

---

## Social Media Clue Examples

**Twitter Post Example:**
"Just pushed some code to my latest project 📂 Repository name starts with 'hidden' and ends with numbers from our founding year 🔍 #CTF #OSINT"

**Instagram Story:**
Image of code editor with visible GitHub URL in the background

**LinkedIn Post:**
"Excited to announce our new project repository! Link in bio leads to more details about our secret initiative."

---

## Technical Implementation

### Creating the Metadata Image:
```bash
# Add password to image metadata
exiftool -Comment="Password: SecretKey2026" treasure.png

# Verify metadata
exiftool -Comment treasure.png
```

### Creating Hidden Text File:
```html
<!-- secret.txt content -->
<div style="color: #FFFFFF; background-color: #FFFFFF;">
DSCCTF{h1dd3n_1n_pl41n_s1ght_2026}
</div>
```

### Password Protection:
```bash
# Encrypt the file
zip -P SecretKey2026 secret.zip secret.txt
```

---

## Learning Objectives

- **Social Media Investigation**: Understanding how to track digital footprints across platforms
- **OSINT Methodology**: Systematic approach to information gathering
- **Metadata Analysis**: Extracting hidden information from file properties
- **Steganography Basics**: Finding hidden content in images and text
- **Multi-layer Problem Solving**: Combining multiple investigation techniques
- **Tool Proficiency**: Using exiftool, strings, hex editors, and other analysis tools

---

## Difficulty Justification

**Medium Difficulty** because:
- Requires knowledge of multiple OSINT techniques
- Involves several tools and analysis methods
- Multi-step process with different skill requirements
- Real-world applicable investigation skills
- Combines technical and investigative elements

---

## Setup Instructions

1. Create social media accounts or posts with clues
2. Set up GitHub repository with the three required files
3. Prepare images with proper metadata
4. Create password-protected encrypted file
5. Test the complete investigation path

---

## Variations and Extensions

- Add more social media platforms
- Include additional layers of encryption
- Use different steganography techniques
- Add time-based clues or limited-time posts
- Include GPS coordinates or location-based clues