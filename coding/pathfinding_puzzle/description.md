# Pathfinding Puzzle

**Author:** Shadow PB  
**Category:** Algorithms  
**Difficulty:** Medium  
**Points:** 200

---

## Challenge Description

🗺️ Welcome to the Pathfinding Puzzle! Your mission is to find the shortest path through a maze and collect the hidden flag pieces along the way.

You're given a 10x10 maze with a start point (S) and end point (E). Walls are marked with '#' and open paths with '.'. However, there are special characters scattered throughout the maze that form parts of the flag when collected in the correct order.

**Your task:** Find the shortest path from start to end and collect the flag pieces to reveal the complete flag.

---

## Files Provided
- `pathfinding.py` - Interactive challenge runner

---

## Usage
```bash
python3 pathfinding.py
# Follow the interactive prompts
```

---

## Maze Legend
- `S` = Start position
- `E` = End position  
- `#` = Wall (impassable)
- `.` = Open path
- `Letters` = Flag pieces to collect

---

## Hints

💡 **Hint 1 (Free):** BFS guarantees the shortest path in unweighted graphs

💡 **Hint 2 (75 pts):** The flag pieces are collected in the order you visit them

💡 **Hint 3 (125 pts):** Don't forget to exclude basic maze elements (S, E, ., #) from the flag

💡 **Hint 4 (175 pts):** The maze is designed so the shortest path collects the flag correctly

---

## Flag Format
`DSCCTF{...}`