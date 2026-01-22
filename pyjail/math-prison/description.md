# Math Prison

**Difficulty:** Medium  
**Category:** Pyjail  
**Points:** 200

## Challenge Description

Numbers don't always behave the way you expect them to. Can you find the input that breaks the mathematical cycle?

The server presents a mathematical puzzle where you must input a number between 3 and 100. The system applies complex transformations and checks if the output equals your input. Find a number where this doesn't hold true to retrieve the flag.

## Hints

1. Floating-point arithmetic isn't always exact
2. Try values near the boundaries
3. Complex cubic calculations can lose precision
4. The inverse of a function isn't always perfect

## Connection

```bash
nc localhost 1339
```

## Files

- `challenge.py` - The main challenge script
- `namo.txt` - Contains the flag
