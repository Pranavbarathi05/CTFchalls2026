from PIL import Image

FLAG = "DSCCTF{qr_c0d3s_l13_wh3n_y0u_trust_th3m_2026}"
KEY = "QR"   # short XOR key (medium difficulty)

# Convert flag to binary
flag_bits = ''.join(format(ord(c), '08b') for c in FLAG)
key_bits = ''.join(format(ord(c), '08b') for c in KEY)

# XOR encode bits
encoded_bits = ""
for i, bit in enumerate(flag_bits):
    encoded_bits += str(int(bit) ^ int(key_bits[i % len(key_bits)]))

encoded_bits += "00000000"  # null terminator

img = Image.open("qr.png").convert("RGB")
pixels = img.load()

width, height = img.size
idx = 0
OFFSET = 200   # small offset (medium)

for y in range(height):
    for x in range(width):
        if idx < OFFSET:
            idx += 1
            continue

        bit_index = idx - OFFSET
        if bit_index >= len(encoded_bits):
            break

        r, g, b = pixels[x, y]
        r = (r & ~1) | int(encoded_bits[bit_index])
        pixels[x, y] = (r, g, b)
        idx += 1

    if bit_index >= len(encoded_bits):
        break

img.save("qr.png")
print("[+] flag embedded")
