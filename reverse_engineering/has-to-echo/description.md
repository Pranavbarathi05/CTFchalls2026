# Has-to-Echo

**Category:** Reverse Engineering  
**Difficulty:** Easy  
**Port:** 1340

## Connection

Challengers can access this challenge with a single command:

```bash
nc ctf.dscjssstuniv.in 1340
```

## Challenge Description

A simple echo challenge where you must understand how the transform function modifies your input to create input that echoes back to itself.

## Files

- `challenge.py` - The main challenge script
- `flag.txt` - Contains the flag

## Solution

Find a string where `transform(s) == s`. Since the transform adds the character index to each byte modulo 128, you need characters where `(ord(c) + i) % 128 == ord(c)`.

This happens when the index `i` is a multiple of 128, but since ASCII characters are 0-127, the first position (index 0) always works for any character.

The simplest solution is an empty string or newline.

## Deployment

```bash
# Build and run
docker-compose up -d --build

# Test locally
nc localhost 1340

# View logs
docker-compose logs -f

# Stop
docker-compose down
```
