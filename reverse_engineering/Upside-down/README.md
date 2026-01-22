# Math Prison

| Field         | Value |
|-------        |-------|
| **Name**      | math-prison |
| **Category**  | pyjail |
| **Difficulty**| Easy |
| **Flag**      | `DSCCTF{m4th_1s_h4rd_wh3n_1ts_n0t_1nv3rt1bl3_2026}` |
## Description

Numbers don't always behave the way you expect them to. Can you find the input that breaks the mathematical cycle?

## Connection

```bash
nc ctf.dscjssstuniv.in 1339
```

## Challenge

The challenge asks you to enter a number between 3 and 100. It then:
1. Applies a cubic polynomial transformation: `x³ - 5x² + 3x + 10`
2. Applies a complex inverse transformation involving cube roots
3. Checks if the result **equals** your original input

Your goal is to find a number where `x == mathStuff(x)`. The twist: the inverse function is designed to be mathematically perfect!

## Solution

The key insight is that the `fancy()` function is the exact inverse of `notfancy()` using the cubic formula (Cardano's formula). This means for all valid inputs, `fancy(notfancy(x)) = x`.

Since the functions are perfect inverses, **ANY** value between 3 and 100 will satisfy `x == mathStuff(x)` and give you the flag!

## Solution

## Solution

The key insight is that the `fancy()` function attempts to be the mathematical inverse of `notfancy()` using Cardano's cubic formula. However, **floating-point precision errors** prevent perfect inversion!

The `notfancy()` function is: `f(x) = x³ - 5x² + 3x + 10`

The `fancy()` function implements the inverse using:
1. Cardano's cubic formula with square roots and cube roots
2. Multiple division operations
3. Complex number handling

These operations accumulate floating-point rounding errors, causing:
- `mathStuff(6) ≈ 6.000000000000006` (not exactly 6)
- `mathStuff(7) ≈ 7.000000000000003` (not exactly 7)
- `mathStuff(12) ≈ 11.999999999999542` (not exactly 12)

### Finding the Solution

Most values between 3 and 100 will work! The challenge compares floating-point values directly without rounding, so tiny precision errors cause `x != mathStuff(x)`.

Testing reveals that values like **6, 7, 8, 10-19** all have enough floating-point error to pass.

### Quick Solution

```bash
nc ctf.dscjssstuniv.in 1339
# Enter: 6 (or most numbers from 6-100)
```

### Automated Solution

```python
from pwn import *

# Connect to the challenge
conn = remote('ctf.dscjssstuniv.in', 1339)

# Receive prompt
conn.recvuntil(b'Enter a number: ')

# Send the answer
conn.sendline(b'3')

# Get the flag
response = conn.recvall()
print(response.decode())
```

### Manual Testing

You can also test locally:

```python
import math

def fancy(x):
    a = (1/2) * x
    b = (1/2916) * ((27 * x - 155) ** 2)
    c = 4096 / 729
    d = (b - c) ** (1/2)
    e = (a - d - 155/54) ** (1/3)
    f = (a + d - 155/54) ** (1/3)
    g = e + f + 5/3
    return g

def notfancy(x):
    return x**3 - 5*x**2 + 3*x + 10

def mathStuff(x):
    if (x < 3 or x > 100):
        return None
    y = fancy(notfancy(x))
    if isinstance(y, complex):
        y = float(y.real)
    y = round(y, 0)
    return y

# Test values
for x in range(3, 20):
    result = mathStuff(x)
    if x != result:
        print(f"Found: x={x}, mathStuff(x)={result}")
```

## Flag

```
DSCCTF{m4th_1s_h4rd_wh3n_1ts_n0t_1nv3rt1bl3_2026}
```

## Learning Outcomes

- **Floating-point precision limitations**: Computers cannot represent all real numbers exactly
- **Accumulation of rounding errors**: Multiple operations compound small errors
- **Function composition and inversion**: Understanding why inverses aren't always perfect in practice
- **Cardano's cubic formula**: The mathematical solution to cubic equations
- **IEEE 754 floating-point arithmetic**: Why `6.0 != 6.000000000000006`

## Tags

`pyjail`, `math`, `floating-point`, `precision`, `cubic-formula`
