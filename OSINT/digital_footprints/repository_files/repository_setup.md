# Repository Files for Digital Footprints Challenge

## GitHub Repository Setup

### Repository Name: `DSC_Digital_Footprint`
### Organization: `DSC`
### URL: `https://github.com/DSC/DSC_Digital_Footprint`

### Repository Description:
"Digital footprints investigation challenge - Three files, multiple layers, one flag 🔍"

### README.md Content:
```markdown
# Hidden Treasures

Welcome to the final stage of the Digital Footprints investigation! 🕵️

You've successfully followed the clues across social media platforms and discovered this repository. Congratulations on making it this far!

## Challenge Files

This repository contains exactly three files:

1. **decoy.png** - Not what you're looking for, but worth checking anyway
2. **treasure.png** - The real treasure lies within (check the metadata!)
3. **secret.txt** - The final piece of the puzzle (password required)

## Instructions

1. Examine both images carefully
2. One contains hidden information in its metadata
3. Use that information to unlock the final file
4. The flag is closer than you think...

*Hint: Sometimes the most obvious hiding place is the best hiding place*

Good luck! 🚩
```

## File Creation Instructions

### 1. decoy.png
Create a simple image with text "THIS IS NOT THE FLAG" in bold letters.

**Command to create:**
```bash
# Using ImageMagick
convert -size 800x400 xc:lightgray -fill black -font Arial-Bold -pointsize 48 \
        -gravity center -annotate 0 "THIS IS NOT THE FLAG" decoy.png

# Add basic metadata
exiftool -Title="Decoy Image" -Description="This is just a decoy" decoy.png
```

### 2. treasure.png  
Create an image with text "THE FLAG IS IN THIS IMAGE" and embed the password in metadata.

**Command to create:**
```bash
# Create the image
convert -size 800x400 xc:lightblue -fill darkblue -font Arial-Bold -pointsize 36 \
        -gravity center -annotate 0 "THE FLAG IS IN THIS IMAGE" treasure.png

# Add the crucial metadata with password
exiftool -Comment="Password: SecretKey2026" \
         -Title="Treasure Image" \
         -Description="The real treasure is in the details" \
         treasure.png

# Verify metadata
exiftool -Comment treasure.png
```

### 3. secret.txt
Create an HTML file with white text on white background containing the flag.

**Content:**
```html
<!DOCTYPE html>
<html>
<head>
    <title>Secret Message</title>
    <style>
        body { 
            background-color: #FFFFFF; 
            margin: 50px;
            font-family: monospace;
        }
        .hidden { 
            color: #FFFFFF; 
            background-color: #FFFFFF;
            font-size: 18px;
            line-height: 1.5;
        }
    </style>
</head>
<body>
    <div class="hidden">
        Congratulations on making it this far in the Digital Footprints investigation!
        
        You successfully:
        ✓ Followed social media clues across multiple platforms
        ✓ Discovered this hidden repository 
        ✓ Extracted the password from image metadata
        ✓ Unlocked this encrypted file
        
        Your flag is: DSCCTF{h1dd3n_1n_pl41n_s1ght_2026}
        
        Well done, digital detective! 🕵️🚩
    </div>
</body>
</html>
```

**Encryption command:**
```bash
# Create password-protected ZIP
zip -P SecretKey2026 secret.zip secret.txt

# Alternative: GPG encryption
gpg --cipher-algo AES256 --compress-algo 2 --symmetric \
    --output secret.txt.gpg secret.txt
# (Use password: SecretKey2026)
```

## Repository Timeline

1. **Initial commit:** "Added challenge files for Digital Footprints OSINT investigation"
2. **Commit 2:** "Updated image metadata and file descriptions" 
3. **Commit 3:** "Final adjustments to challenge difficulty"

## Commit Messages Should Include:
- References to metadata importance
- Hints about examining files closely
- Mentions of "hidden in plain sight"
- Timestamps within the last week

## Access Control
- Repository should be **public**
- Allow issues and discussions for participant questions
- Enable GitHub Pages if secret.txt is HTML (for additional discovery method)

## Additional Repository Features

### Issues Section:
Create a sample issue titled "Metadata extraction help needed" with discussion about exiftool usage.

### Discussions:
Enable discussions with categories:
- General (for overall challenge discussion)
- Q&A (for technical questions about tools)
- Ideas (for alternative solution approaches)

### Topics/Tags:
- osint
- ctf
- digital-footprints  
- metadata
- steganography
- investigation