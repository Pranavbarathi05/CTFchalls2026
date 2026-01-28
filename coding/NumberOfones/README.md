# NumberOfones - CTF Coding Challenge

## Challenge Description

A Python coding challenge where you must count the occurrences of the digit '2' within a given range of numbers. You have 60 seconds to answer 10 rounds correctly to get the flag.

## Challenge Details

- **Category**: Coding
- **Difficulty**: Easy
- **Time Limit**: 60 seconds total
- **Rounds**: 10 questions
- **Port**: 54321

## How It Works

The challenge presents 10 rounds. In each round:
1. You're given a range of numbers (e.g., between 123 and 456)
2. You must count how many times the digit '2' appears in all numbers within that range
3. You have 60 seconds total to complete all 10 rounds
4. One wrong answer ends the challenge

### Example

Question: "How many 2's appear between 20 and 25?"

Numbers in range: 20, 21, 22, 23, 24, 25
- 20: one '2'
- 21: one '2'
- 22: two '2's
- 23: one '2'
- 24: one '2'
- 25: one '2'

**Answer**: 7

## Intended Solution

The challenge is designed to be automated since:
1. Manual counting would be too slow
2. 60 seconds for 10 rounds is tight
3. The ranges can be large (up to 2000)

### Algorithm

For each number in the range [start, end]:
1. Convert the number to a string
2. Count occurrences of '2' in that string
3. Sum up all occurrences

### Python Implementation

```python
def solve(start, end, digit='2'):
    count = 0
    for number in range(start, end + 1):
        count += str(number).count(digit)
    return count
```

## Running the Solution

1. Make sure you have pwntools installed:
   ```bash
   pip install pwntools
   ```

2. Update the hostname in `solve.py` if needed:
   ```python
   # Remote connection
   io = remote('numbers.challenges1.ctf.dscjssstuniv.in', 54321)
   
   # Or for local testing:
   # io = process(['python3', '../src/chall.py'])
   ```

3. Run the solve script:
   ```bash
   cd solve
   python3 solve.py
   ```

The script will automatically:
- Connect to the challenge
- Parse each question
- Calculate the answer
- Submit the response
- Display the flag after 10 successful rounds

## Flag

After successfully completing all 10 rounds, you'll receive:
```
dscctf{5up3r_345y_pr06r4mm1n6_ch4ll3n63}
```

## Deployment

The challenge is deployed using Docker:

```bash
cd src
docker-compose up -d --build
```

Access it via:
```bash
nc <host> 54321
```

## Learning Objectives

- Basic programming and automation
- String manipulation
- Time-constrained problem solving
- Network interaction with pwntools
