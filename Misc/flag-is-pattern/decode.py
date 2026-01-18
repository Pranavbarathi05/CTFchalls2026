import os

files = []

for f in os.listdir("challenge"):
    path = os.path.join("challenge", f)
    size = os.path.getsize(path)
    files.append((size, f))

# Sort by size
files.sort()

msg = ""
for size, fname in files:
    with open(os.path.join("challenge", fname)) as f:
        msg += f.read(1)  # first character only

print(msg)
