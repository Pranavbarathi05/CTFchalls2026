import os
import string
import random

message = "ORDERMATTERS"

os.makedirs("challenge", exist_ok=True)

for i, ch in enumerate(message):
    # file size strictly increases
    size = 100 + i * 50

    # first character encodes the message
    content = ch + ''.join(
        random.choices(string.ascii_letters, k=size - 1)
    )

    fname = f"data_{i}.txt"
    with open(os.path.join("challenge", fname), "w") as f:
        f.write(content)

print("Files generated (stable encoding).")
