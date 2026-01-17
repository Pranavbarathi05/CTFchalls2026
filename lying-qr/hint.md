
---

## Hints (optional, progressive)

1. **Hint 1 (free)**  
   The QR code is valid — but QR codes allow small errors.

2. **Hint 2 (50 pts)**  
   Try looking beyond what your QR scanner shows you.

3. **Hint 3 (100 pts)**  
   Least Significant Bits can hide more than you expect.

4. **Hint 4 (full)**  
   The hidden data is XOR-encoded before being embedded.

---

## Testing Checklist

- [x] QR scans correctly on phone
- [x] Scanner shows a fake flag
- [x] No metadata leaks the real flag
- [x] Naive LSB extraction gives garbage
- [x] XOR decoding reveals readable text
- [x] Real flag successfully recovered
