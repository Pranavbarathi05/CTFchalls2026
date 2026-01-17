from PIL import Image

KEY = "QR"

img = Image.open("qr.png").convert("RGB")
pixels = img.load()

width, height = img.size
bits = ""

OFFSET = 200
count = 0

for y in range(height):
    for x in range(width):
        if count < OFFSET:
            count += 1
            continue
        r, g, b = pixels[x, y]
        bits += str(r & 1)
        count += 1

chars = []
key_bits = ''.join(format(ord(c), '08b') for c in KEY)

for i in range(0, len(bits), 8):
    byte = bits[i:i+8]
    if len(byte) < 8:
        break

    decoded = ""
    for j in range(8):
        decoded += str(int(byte[j]) ^ int(key_bits[(i + j) % len(key_bits)]))

    if decoded == "00000000":
        break

    chars.append(chr(int(decoded, 2)))

print("".join(chars))
