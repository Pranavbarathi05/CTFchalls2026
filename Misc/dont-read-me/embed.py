flag = "DSCCTF{r34dm3_m34n5_r34d_m3_2026}"

bits = "".join(format(ord(c), "08b") for c in flag)

out = []
for b in bits:
    out.append("\u200b" if b == "0" else "\u200c")

hidden = "".join(out)

with open("README.md", "a", encoding="utf-8") as f:
    f.write("\n\n" + hidden)
