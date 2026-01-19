import requests

def reverse_snap(s):
    out = []
    for i, c in enumerate(s):
        out.append(chr((ord(c) - 1) ^ (i % 42)))
    return ''.join(out)

data = requests.get("http://localhost:8000/snap").text
print(reverse_snap(data))
