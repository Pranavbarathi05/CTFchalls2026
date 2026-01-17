# Lying QR — Official Writeup

## Overview

The provided QR code is **completely valid** and decodes to a **fake flag**.
However, QR codes use strong error correction, allowing subtle pixel
manipulation without breaking readability.

The real flag is hidden using **LSB steganography** with a light obfuscation
layer.

---

## Step 1: Verify the QR

Scanning `qr.png` reveals:
  DSCCTF{th1s_1s_n0t_th3_fl4g}

## Step 2: Inspect the Image

Basic checks:
- `strings` → nothing useful
- EXIF data → nothing interesting

This suggests **image-level steganography**.

---

## Step 3: Extract LSB Data

Extract the least significant bit of the red channel across pixels.
The output is **not readable ASCII**, indicating obfuscation.

---

## Step 4: XOR Decode

The extracted bitstream is XOR-encoded with a short repeating key.

After XOR decoding, the bitstream converts cleanly to ASCII.

---

## Step 5: Recover the Flag

Decoded output:
  DSCCTF{qr_c0d3s_l13_wh3n_y0u_trust_th3m_2026}

refer extract_flag.py for the solution code.