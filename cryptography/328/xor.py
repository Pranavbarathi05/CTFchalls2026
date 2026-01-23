h1 = "89050253A9D41C3161D7987CF20DB108E5224B70B160218D1F7774A82EE113D1"
h2 = "66aaabd695804fab560ad24087fb2d93dfb67c10740d05f875719731c9107fe0"

b1 = bytes.fromhex(h1)
b2 = bytes.fromhex(h2)

x = bytes(a ^ b for a, b in zip(b1, b2))

print("XOR hex:", x.hex())
print("XOR raw:", x)
print("XOR raw (latin1):", x.decode("latin1"))
