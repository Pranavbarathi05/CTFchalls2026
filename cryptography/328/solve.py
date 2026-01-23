import base64

# The encoded input - this is the base64-encoded data we need to decode
dec_str = """ODggNzIgMTAzIDEyMiA3OCA0OSAxMjAgNTIgNzggMTA2IDc4IDk5IDEwMSA2OCA3NyA1MiA4OCA3MiAxMDMgNTAgNzggODYgMTIwIDUyIDc3IDEyMiA4MiA5OSAxMDEgNjggODkgMTIwIDg4IDcyIDEwMyAxMjIgNzcgODYgMTIwIDUyIDc4IDEwNiA3NCA5OSAxMDEgNjggNzcgMTIyIDg4IDcyIDEwMyA1MCA3OCAxMDggMTIwIDUyIDc3IDEyMiA3NCA5OSAxMDEgNjggODkgNDggODggNzIgMTAzIDEyMiA3OSA4NiAxMjAgNTIgNzggMTA2IDg2IDk5IDEwMSA2OCA3NyA0OSA4OCA3MiAxMDMgNTAgNzcgNDkgMTIwIDUyIDc3IDEyMiA5MCA5OSAxMDEgNjggODkgMTIwIDg4IDcyIDEwMyAxMjIgNzcgODYgMTIwIDUyIDc4IDEwNiA5MCA5OSAxMDEgNjggNzcgNTIgODggNzIgMTAzIDUwIDc3IDEwOCAxMjAgNTIgNzcgMTIyIDc4IDk5IDEwMSA2OCA4OSA0OCA4OCA3MiAxMDMgMTIyIDc4IDcwIDEyMCA1MiA3OCAxMDYgODYgOTkgMTAxIDY4IDc3IDUxIDg4IDcyIDEwMyA1MCA3NyA4NiAxMjAgNTIgNzcgMTIyIDc0IDk5IDEwMSA2OCA4OSAxMjIgODggNzIgMTAzIDEyMiA3OCA4NiAxMjAgNTIgNzggMTA2IDkwIDk5IDEwMSA2OCA3NyA1MyA4OCA3MiAxMDMgNTAgNzcgMTA4IDEyMCA1MiA3NyAxMjIgNzAgOTkgMTAxIDY4IDg5IDQ4IDg4IDcyIDEwMyAxMjIgNzcgNDkgMTIwIDUyIDc4IDEwNiA4NiA5OSAxMDEgNjggNzcgNDkgODggNzIgMTAzIDUwIDc3IDg2IDEyMCA1MiA3NyAxMjIgMTAwIDk5IDEwMSA2OCA4OSAxMjIgODggNzIgMTAzIDEyMiA3NyAxMDggMTIwIDUyIDc4IDEwNiA5MCA5OSAxMDEgNjggNzcgNDggODggNzIgMTAzIDUwIDc3IDEwOCAxMjAgNTIgNzcgMTIyIDkwIDk5IDEwMSA2OCA4OSA0OCA4OCA3MiAxMDMgMTIyIDc5IDcwIDEyMCA1MiA3OCAxMDYgODYgOTkgMTAxIDY4IDc3IDEyMCA4OCA3MiAxMDMgNTAgNzcgODYgMTIwIDUyIDc3IDEyMiA3OCA5OSAxMDEgNjggODkgMTIyIDg4IDcyIDEwMyAxMjIgNzggODYgMTIwIDUyIDc4IDEwNiA5MCA5OSAxMDEgNjggNzcgNTEgODggNzIgMTAzIDUwIDc3IDEwOCAxMjAgNTIgNzcgMTIyIDEwOCA5OSAxMDEgNjggODkgNDggODggNzIgMTAzIDEyMiA3NyAxMDggMTIwIDUyIDc4IDEwNiA4NiA5OSAxMDEgNjggNzcgNDggODggNzIgMTAzIDUwIDc3IDg2IDEyMCA1MiA3NyAxMDkgNzQgOTkgMTAxIDY4IDc3IDQ4IDg4IDcyIDEwMyAxMjIgNzkgODYgMTIwIDUyIDc3IDEyMiA3NCA5OSAxMDEgNjggNzcgMTIwIDg4IDcyIDEwMyAxMjIgNzggMTA4IDEyMCA1MiA3OCAxMDYgOTAgOTkgMTAxIDY4IDg5IDQ5IDg4IDcyIDEwMyA1MCA3OCA4NiAxMjAgNTIgNzcgMTIyIDEwOCA5OSAxMDEgNjggODkgMTIwIDg4IDcyIDEwMyA1MCA3OCA3MCAxMjAgNTIgNzcgMTIyIDY2IDk5IDEwMSA2OCA3NyAxMjIgODggNzIgMTAzIDEyMiA3NyAxMDggMTIwIDUyIDc3IDEyMiA3OCA5OSAxMDEgNjggNzcgNTIgODggNzIgMTAzIDEyMiA3OCAxMDggMTIwIDUyIDc4IDEwNiA3NCA5OSAxMDEgNjggODkgMTIyIDg4IDcyIDEwMyAxMjIgNzcgMTA4IDEyMCA1MiA3OCAxMDYgNzggOTkgMTAxIDY4IDc3IDExOSA4OCA3MiAxMDMgMTIyIDc5IDg2IDEyMCA1MiA3NyAxMjIgNzQgOTkgMTAxIDY4IDg5IDQ4IDg4IDcyIDEwMyA1MCA3NyA4NiAxMjAgNTIgNzggMTA2IDg2IDk5IDEwMSA2OCA4OSA0OCA4OCA3MiAxMDMgNTAgNzcgMTA4IDEyMCA1MiA3NyAxMjIgMTA0IDk5IDEwMSA2OCA4OSA0OSA4OCA3MiAxMDMgNTAgNzcgODYgMTIwIDUyIDc3IDEyMiA2NiA5OSAxMDEgNjggNzcgNTAgODggNzIgMTAzIDUwIDc3IDg2IDEyMCA1MiA3NyAxMjIgODYgOTkgMTAxIDY4IDc3IDEyMiA4OCA3MiAxMDMgNTAgNzggMTA4IDEyMCA1MiA3NyAxMjIgNzggOTkgMTAxIDY4IDc3IDEyMSA4OCA3MiAxMDMgNTAgNzcgODYgMTIwIDUyIDc4IDEwNiA3MCA5OSAxMDEgNjggODkgMTIxIDg4IDcyIDEwMyAxMjIgNzcgNDkgMTIwIDUyIDc4IDEwNiA3OCA5OSAxMDEgNjggODkgMTIxIDg4IDcyIDEwMyAxMjIgNzkgNzAgMTIwIDUyIDc4IDEwNiA3MCA5OSAxMDEgNjggNzcgNTEgODggNzIgMTAzIDUwIDc3IDQ5IDEyMCA1MiA3OCAxMDYgODIgOTkgMTAxIDY4IDc3IDQ5IDg4IDcyIDEwMyA1MCA3OCA4NiAxMjAgNTIgNzcgMTIyIDgyIDk5IDEwMSA2OCA3NyA1MCA4OCA3MiAxMDMgMTIyIDc4IDEwOCAxMjAgNTIgNzggMTA2IDg2IDk5IDEwMSA2OCA3NyAxMjEgODggNzIgMTAzIDEyMiA3OCA0OSAxMjAgNTIgNzggMTA2IDkwIDk5IDEwMSA2OCA4OSA0OCA4OCA3MiAxMDMgMTIyIDc3IDcwIDEyMCA1MiA3OCAxMDYgNzQgOTkgMTAxIDY4IDc3IDQ5"""

print("="*80)
print("MULTI-STAGE DECODING PIPELINE")
print("="*80)

# STAGE 1: Decode base64 to get decimal string
# The base64 string decodes to space-separated decimal numbers
decimal_text = base64.b64decode(dec_str).decode()
print("\n[Stage 1] Base64 → Decimal string")
print(f"First 100 chars: {decimal_text[:100]}...")

# STAGE 2: Convert decimal numbers to ASCII characters
# Each decimal number represents the ASCII code of a character
nums = [int(x) for x in decimal_text.split()]
b64_string = "".join(chr(n) for n in nums)
print("\n[Stage 2] Decimal → ASCII (Base64 string)")
print(f"First 100 chars: {b64_string[:100]}...")

# STAGE 3: Decode the base64 string to get hex-encoded data
# This gives us a string containing \x escape sequences
hex_with_escapes = base64.b64decode(b64_string).decode('latin-1')
print("\n[Stage 3] Base64 → Hex string with \\x notation")
print(f"First 100 chars: {repr(hex_with_escapes[:100])}...")

# STAGE 4: Parse the \xNN escape sequences to get the actual text
# Each \xNN represents a hexadecimal byte value that decodes to an ASCII character
final = ""
i = 0
while i < len(hex_with_escapes):
    if hex_with_escapes[i:i+2] == '\\x':
        # Found a \xNN sequence - extract NN and convert to character
        hex_code = hex_with_escapes[i+2:i+4]
        char = bytes.fromhex(hex_code).decode('ascii')
        final += char
        i += 4
    else:
        # Regular character (like the '+' separator)
        final += hex_with_escapes[i]
        i += 1

print("\n[Stage 4] Parse \\xNN sequences → Final decoded string")
print(f"Result: {final}")

# STAGE 5: Extract the two hash values
# The decoded string contains two hashes separated by '+'
hash1, hash2 = final.strip().split('+')

print("\n" + "="*80)
print("EXTRACTED HASHES")
print("="*80)
print(f"Hash 1: {hash1}")
print(f"Hash 2: {hash2}")

# STAGE 6: XOR the two hashes to get the target
# XOR operation: each byte of hash1 is XORed with the corresponding byte of hash2
def xor_hex_strings(hex1, hex2):
    """XOR two hexadecimal strings byte by byte"""
    bytes1 = bytes.fromhex(hex1)
    bytes2 = bytes.fromhex(hex2)
    xor_result = bytes([b1 ^ b2 for b1, b2 in zip(bytes1, bytes2)])
    return xor_result.hex()

target_hash = xor_hex_strings(hash1, hash2)

print("\n" + "="*80)
print("FINAL RESULT (XOR OF THE TWO HASHES)")
print("="*80)
print(f"Target Hash: {target_hash}")
print("="*80)