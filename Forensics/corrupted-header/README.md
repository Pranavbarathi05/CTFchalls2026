# Corrupted Vacation Photo

A forensics challenge teaching about file signatures (magic bytes) and basic hex editing.

## Challenge Info

| Field | Value |
|-------|-------|
| **Name** | Corrupted Vacation Photo |
| **Category** | Forensics |
| **Difficulty** | Easy |
| **Points** | 100 |
| **Flag** | `DSCCTF{m4g1c_byt3s_r3st0r3d_2026}` |

---

## Description

📸 Corrupted Vacation Photo [forensics] - 100 pts

I was going through my old vacation photos and found this gem!

But something's wrong... the file won't open! 😢

My photo viewer says it's corrupted or not a valid JPEG file.
Can you help me fix it? There might be something important in this photo!

💡 Hint: All files have "magic bytes" at the start that identify the file type.

---

## Solution

### Step 1: Identify the Problem

Check the file header:
```bash
hexdump -C vacation_photo.jpg | head -n 5
# or
xxd vacation_photo.jpg | head -n 5
```

You'll see it starts with `00 00 00` instead of the correct JPEG magic bytes.

### Step 2: Look Up Correct Magic Bytes

JPEG files should start with: `FF D8 FF`

### Step 3: Fix the Header

**Using hexedit (Linux):**
```bash
hexedit vacation_photo.jpg
# Press Tab to switch to hex mode
# Replace first 3 bytes: 00 00 00 → FF D8 FF
# Press Ctrl+X to save and exit
```

**Using HxD (Windows):**
1. Open vacation_photo.jpg
2. Select first 3 bytes
3. Overwrite with: FF D8 FF
4. Save file

**Using Python:**
```python
with open('vacation_photo.jpg', 'rb') as f:
    data = f.read()

# Replace first 3 bytes
fixed = b'\xFF\xD8\xFF' + data[3:]

with open('fixed_photo.jpg', 'wb') as f:
    f.write(fixed)
```

**Using dd (Linux):**
```bash
# Create a file with correct header
printf '\xFF\xD8\xFF' > header.bin

# Get the rest of the file (skip first 3 bytes)
dd if=vacation_photo.jpg of=rest.bin bs=1 skip=3

# Combine
cat header.bin rest.bin > fixed_photo.jpg
```

### Step 4: Extract the Flag

Once fixed, either:
1. Open the image (might show garbled data but still "valid")
2. Or strings the file:

```bash
strings fixed_photo.jpg | grep DSCCTF
```

Flag: `DSCCTF{m4g1c_byt3s_r3st0r3d_2026}`

---

## Learning Objectives

- **File Signatures**: Understanding magic bytes and file identification
- **Hex Editing**: Basic hex editor usage and binary manipulation
- **Forensics**: File repair and data recovery techniques
- **File Formats**: How operating systems identify file types

---

## Key Concepts

### What Are Magic Bytes?

Magic bytes (or file signatures) are specific byte sequences at the start of files that identify their format. Operating systems and applications use these to determine file types, regardless of the extension.

**Common File Signatures:**

| File Type | Magic Bytes (Hex) | ASCII |
|-----------|-------------------|-------|
| JPEG | FF D8 FF | ... |
| PNG | 89 50 4E 47 | .PNG |
| GIF | 47 49 46 38 | GIF8 |
| PDF | 25 50 44 46 | %PDF |
| ZIP | 50 4B 03 04 | PK.. |
| EXE | 4D 5A | MZ |
| ELF | 7F 45 4C 46 | .ELF |

### Why This Matters

1. **File Recovery**: Corrupted headers can be fixed
2. **File Identification**: True type regardless of extension
3. **Malware Analysis**: Detect file type mismatches
4. **Data Carving**: Extract files from disk images
5. **Steganography**: Hidden data detection

### File vs Extension

The extension (.jpg, .txt, .exe) is just a name convention. The operating system uses magic bytes to determine actual file type:

```bash
# A .txt file with PNG magic bytes will open as image
echo -e '\x89PNG' > fake.txt
# (then add PNG data)
```

---

## Tools for Hex Editing

### Command-Line:
```bash
# View hex
hexdump -C file.jpg
xxd file.jpg
od -A x -t x1z file.jpg

# Edit hex
hexedit file.jpg        # Linux
bvi file.jpg            # Vi-like hex editor
```

### GUI Tools:
- **HxD** (Windows) - Free, powerful
- **Hex Fiend** (Mac) - Fast, clean interface
- **010 Editor** (All platforms) - Professional
- **GHex** (Linux) - GNOME hex editor
- **ImHex** (All platforms) - Modern, open-source

### Online:
- HexEd.it - Web-based hex editor
- hexed.it - Another web option

---

## Real-World Applications

### Digital Forensics:
- Recover deleted files by signature
- Identify files with wrong extensions
- Repair corrupted files
- Detect hidden/embedded files

### Malware Analysis:
- Identify packed executables
- Detect file type spoofing
- Find embedded payloads

### Data Recovery:
- Fix damaged boot sectors
- Repair file system structures
- Extract data from corrupted media

### CTF & Security:
- Steganography challenges
- File format exploitation
- Reverse engineering

---

## Common File Signature Reference

```
PDF:        25 50 44 46 2D                    %PDF-
JPEG:       FF D8 FF                          ...
PNG:        89 50 4E 47 0D 0A 1A 0A          .PNG....
GIF89a:     47 49 46 38 39 61                GIF89a
GIF87a:     47 49 46 38 37 61                GIF87a
ZIP:        50 4B 03 04                       PK..
RAR:        52 61 72 21 1A 07                Rar!..
7Z:         37 7A BC AF 27 1C                7z....
GZIP:       1F 8B                             ..
BMP:        42 4D                             BM
TIFF (LE):  49 49 2A 00                       II*.
TIFF (BE):  4D 4D 00 2A                       MM.*
ICO:        00 00 01 00                       ....
WAV:        52 49 46 46 ... 57 41 56 45      RIFF...WAVE
AVI:        52 49 46 46 ... 41 56 49 20      RIFF...AVI 
MP3:        FF FB or FF F3 or 49 44 33       ...or ID3
FLAC:       66 4C 61 43                       fLaC
OGG:        4F 67 67 53                       OggS
MP4:        00 00 00 ... 66 74 79 70         ....ftyp
DOC:        D0 CF 11 E0 A1 B1 1A E1          ........
DOCX:       50 4B 03 04 (ZIP format)         PK..
XLS:        D0 CF 11 E0 A1 B1 1A E1          ........
EXE/DLL:    4D 5A                             MZ
ELF:        7F 45 4C 46                       .ELF
CLASS:      CA FE BA BE                       ....
```

---

## Advanced Challenge Ideas

**Harder variations:**
1. Multiple corrupted bytes throughout file
2. Correct header but corrupted file structure
3. Steganography in the "broken" image
4. Need to identify file type first (no extension)
5. Multiple files concatenated together

**Example:**
```python
# PNG with JPEG extension and wrong header
# Players must:
# 1. Identify it's actually PNG (not JPEG)
# 2. Fix the PNG magic bytes
# 3. Extract hidden data
```

---

## Testing

```bash
# Check original (corrupted) file
file challenge/vacation_photo.jpg
# Output: data (not recognized as JPEG)

# Check header
xxd challenge/vacation_photo.jpg | head -n 1
# Output: 00000000: 0000 00e0 0010 4a46...

# Fix it
python3 << 'EOF'
with open('challenge/vacation_photo.jpg', 'rb') as f:
    data = f.read()
fixed = b'\xFF\xD8\xFF' + data[3:]
with open('fixed.jpg', 'wb') as f:
    f.write(fixed)
EOF

# Verify fix
file fixed.jpg
# Output: fixed.jpg: JPEG image data...

# Extract flag
strings fixed.jpg | grep DSCCTF
```

---

## Files

```
corrupted-header/
├── challenge/
│   └── vacation_photo.jpg    # Corrupted JPEG file
├── solution/
│   └── fix.py               # Solution script
├── description.md            # Challenge description
└── README.md                # This file
```

---

## Solution Script

Create `solution/fix.py`:
```python
#!/usr/bin/env python3

import sys

def fix_jpeg_header(input_file, output_file):
    """Fix JPEG magic bytes (FF D8 FF)"""
    with open(input_file, 'rb') as f:
        data = f.read()
    
    # Check current header
    print(f"Current header: {data[:3].hex()}")
    
    # Replace with correct JPEG header
    fixed = b'\xFF\xD8\xFF' + data[3:]
    
    with open(output_file, 'wb') as f:
        f.write(fixed)
    
    print(f"Fixed header: {fixed[:3].hex()}")
    print(f"Saved to: {output_file}")
    
    # Try to extract flag
    if b'DSCCTF{' in fixed:
        start = fixed.find(b'DSCCTF{')
        end = fixed.find(b'}', start) + 1
        flag = fixed[start:end].decode('ascii')
        print(f"\nFlag found: {flag}")

if __name__ == '__main__':
    fix_jpeg_header('vacation_photo.jpg', 'fixed_photo.jpg')
```

---

## Flag

`DSCCTF{m4g1c_byt3s_r3st0r3d_2026}`

The flag message: "magic bytes restored" - because that's exactly what players had to do!

---

## Resources

- **File Signatures Table**: https://en.wikipedia.org/wiki/List_of_file_signatures
- **GCK's File Signatures**: https://www.garykessler.net/library/file_sigs.html
- **Hex Workshop**: Professional hex editing tool
- **010 Editor Templates**: Pre-made file format templates
