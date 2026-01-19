# Pathfinding Puzzle

An algorithmic challenge focusing on graph traversal and shortest path algorithms.

---

## Challenge Info

| Field | Value |
|-------|-------|
| **Name** | Pathfinding Puzzle |
| **Category** | Algorithms / Coding |
| **Difficulty** | Medium |
| **Flag** | `DSCCTF{P4TH_4LG0R1THM_M4ST3R_2026}` |
| **Author** | ShadowPB |
| **Port** | 8004 |

---

## Challenge Description

🗺️ Welcome to the Pathfinding Puzzle! Your mission is to find the shortest path through a maze and collect the hidden flag pieces along the way.

You're given a 10x10 maze with a start point (S) and end point (E). Walls are marked with '#' and open paths with '.'. However, there are special characters scattered throughout the maze that form parts of the flag when collected in the correct order.

---

## Files

- `pathfinding.py` - Interactive challenge and maze generator
- `solve.py` - Complete solution with BFS implementation
- `flag.txt` - Target flag
- `description.md` - Challenge description
- `Dockerfile` - Container setup
- `docker-compose.yml` - Easy deployment

---

## Quick Start

### Interactive Mode
```bash
# Run the interactive challenge
python3 pathfinding.py

# Or with Docker
docker run -it pathfinding-puzzle
```

### Solve Mode
```bash
# Get the complete solution
python3 solve.py

# Or see the solver in action
python3 pathfinding.py solve
```

---

## Maze Structure

```
S . # . . . # . . D
. # . # . # . # . S
. . . . . . . . . C
# # # . # # # . # .
. . . . . . . . . C
. # # # . # # # . T
. . . . . . . . . F
# . # # # # # . # {
. . . . . . . . . P
E . # . # . # . . A
```

**Legend:**
- `S` = Start position
- `E` = End position  
- `#` = Wall (impassable)
- `.` = Open path
- `Other letters` = Flag pieces to collect

---

## Algorithm Requirements

### Pathfinding Constraints
- **Movement**: Only 4 directions (up, down, left, right)
- **Goal**: Find the SHORTEST path from S to E
- **Obstacles**: Cannot pass through walls (#)
- **Collection**: Gather flag pieces along the optimal route

### Recommended Algorithm: BFS
```python
from collections import deque

def bfs_shortest_path(maze, start, end):
    queue = deque([(start[0], start[1], [])])
    visited = set([(start[0], start[1])])
    directions = [(0, 1), (1, 0), (0, -1), (-1, 0)]
    
    while queue:
        row, col, path = queue.popleft()
        
        if (row, col) == end:
            return path + [(row, col)]
        
        for dr, dc in directions:
            new_row, new_col = row + dr, col + dc
            
            if (0 <= new_row < len(maze) and 
                0 <= new_col < len(maze[0]) and
                (new_row, new_col) not in visited and
                maze[new_row][new_col] != '#'):
                
                visited.add((new_row, new_col))
                queue.append((new_row, new_col, path + [(row, col)]))
    
    return None
```

---

## Solution Approach

### Step 1: Parse the Maze
- Identify start position (S) and end position (E)
- Map out walls (#) and open paths (.)
- Note special characters for flag collection

### Step 2: Implement Pathfinding
- Use BFS for guaranteed shortest path
- Track visited cells to avoid cycles
- Store path history for reconstruction

### Step 3: Extract Flag
- Follow the optimal path from start to end
- Collect characters along the path (excluding S, E, ., #)
- Concatenate collected characters in order

### Expected Path
```python
# Example shortest path coordinates
path = [(0,0), (1,0), (2,0), (2,1), (2,2), ..., (9,0)]

# Characters collected along path
flag_pieces = ['D', 'S', 'C', 'C', 'T', 'F', '{', 'P', 'A', ...]
flag = ''.join(flag_pieces)  # DSCCTF{P4TH_4LG0R1THM_M4ST3R_2026}
```

---

## Learning Objectives

- **Graph Theory**: Understanding maze as a graph structure
- **BFS Algorithm**: Breadth-first search for shortest paths
- **Pathfinding**: Navigation through constrained environments
- **Algorithm Optimization**: Efficiency in graph traversal
- **Problem Decomposition**: Breaking complex problems into steps

---

## Algorithm Comparison

| Algorithm | Time Complexity | Space Complexity | Guarantees |
|-----------|----------------|------------------|------------|
| BFS | O(V + E) | O(V) | Shortest path |
| DFS | O(V + E) | O(V) | Any path |
| A* | O(b^d) | O(b^d) | Optimal with heuristic |
| Dijkstra | O(V²) | O(V) | Shortest weighted path |

**For this challenge, BFS is optimal** because:
- All edges have equal weight (1 step)
- We need the shortest path
- Maze is relatively small (10x10)

---

## Implementation Tips

### Python BFS Template
```python
from collections import deque

def solve_maze(maze):
    # Find start and end positions
    start = find_position(maze, 'S')
    end = find_position(maze, 'E')
    
    # BFS implementation
    queue = deque([(start[0], start[1], [])])
    visited = set([start])
    
    while queue:
        row, col, path = queue.popleft()
        
        if (row, col) == end:
            return path + [(row, col)]
            
        # Explore neighbors
        for dr, dc in [(0,1), (1,0), (0,-1), (-1,0)]:
            new_row, new_col = row + dr, col + dc
            
            if is_valid_move(maze, new_row, new_col, visited):
                visited.add((new_row, new_col))
                queue.append((new_row, new_col, path + [(row, col)]))
    
    return None  # No path found
```

---

## Alternative Approaches

### A* Search (Overkill but educational)
```python
import heapq

def a_star(maze, start, end):
    def heuristic(pos):
        return abs(pos[0] - end[0]) + abs(pos[1] - end[1])
    
    heap = [(0, start, [])]
    visited = set()
    
    while heap:
        cost, pos, path = heapq.heappop(heap)
        
        if pos in visited:
            continue
        visited.add(pos)
        
        if pos == end:
            return path + [pos]
        
        # Explore neighbors with priority
        for new_pos in get_neighbors(maze, pos):
            new_cost = len(path) + 1 + heuristic(new_pos)
            heapq.heappush(heap, (new_cost, new_pos, path + [pos]))
```

---

## Hints

1. BFS guarantees the shortest path in unweighted graphs
2. The flag pieces are collected in the order you visit them
3. Don't forget to exclude basic maze elements (S, E, ., #) from flag
4. Visualize your path to debug collection issues
5. The maze is designed so the shortest path collects the flag correctly

This challenge teaches fundamental graph algorithms while providing practical pathfinding experience.