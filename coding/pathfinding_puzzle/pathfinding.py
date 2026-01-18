#!/usr/bin/env python3

import json
import sys
from collections import deque

def create_maze():
    """Create a maze with embedded flag pieces for DSCCTF{P4TH_4LG0R1THM_M4ST3R_2026}"""
    maze = [
        ['S', '.', '#', '.', '.', '#', '.', 'D', '#', '.'],
        ['.', '#', '.', '#', '.', '.', '.', 'S', '#', '.'], 
        ['.', '.', '.', '.', '#', '.', '.', 'C', '.', '.'],
        ['#', '#', '#', '.', '.', '.', '#', 'C', '#', '.'],
        ['.', '.', '.', '.', '#', '.', '.', 'T', '.', '.'],
        ['.', '#', '#', '#', '.', '.', '#', 'F', '#', '.'],
        ['.', '.', '.', '.', '#', '.', '.', '{', '.', '.'],
        ['#', '#', '#', '.', '.', '.', '#', 'P', '#', '.'],
        ['.', '.', '.', '.', '#', '.', '.', '4', '.', '.'],
        ['E', '.', '#', '.', '.', '.', '#', 'T', '#', '.']
    ]
    
    return maze

def find_shortest_path(maze, start, end):
    """Find shortest path using BFS"""
    rows, cols = len(maze), len(maze[0])
    
    # BFS setup
    queue = deque([(start[0], start[1], [])])
    visited = set()
    visited.add((start[0], start[1]))
    
    directions = [(0, 1), (1, 0), (0, -1), (-1, 0)]  # right, down, left, up
    
    while queue:
        row, col, path = queue.popleft()
        
        # Check if we reached the end
        if (row, col) == end:
            return path + [(row, col)]
        
        # Explore neighbors
        for dr, dc in directions:
            new_row, new_col = row + dr, col + dc
            
            # Check bounds and obstacles
            if (0 <= new_row < rows and 0 <= new_col < cols and 
                (new_row, new_col) not in visited and 
                maze[new_row][new_col] != '#'):
                
                visited.add((new_row, new_col))
                queue.append((new_row, new_col, path + [(row, col)]))
    
    return None  # No path found

def extract_flag_from_path(maze, path):
    """Extract characters along the path to form flag"""
    flag_chars = []
    
    for row, col in path:
        char = maze[row][col]
        if char not in ['.', '#', 'S', 'E']:  # Ignore basic maze elements
            flag_chars.append(char)
    
    return ''.join(flag_chars)

def solve_challenge():
    print("=== Pathfinding Puzzle Solver ===\n")
    
    # Create the maze
    maze = create_maze()
    
    print("Maze layout:")
    for row in maze:
        print(' '.join(row))
    
    print("\nLegend:")
    print("S = Start, E = End, # = Wall, . = Open path")
    print("Other letters = Flag pieces\n")
    
    # Find start and end positions
    start_pos = None
    end_pos = None
    
    for i in range(len(maze)):
        for j in range(len(maze[i])):
            if maze[i][j] == 'S':
                start_pos = (i, j)
            elif maze[i][j] == 'E':
                end_pos = (i, j)
    
    print(f"Start position: {start_pos}")
    print(f"End position: {end_pos}")
    
    # Find shortest path
    path = find_shortest_path(maze, start_pos, end_pos)
    
    if path:
        print(f"\nShortest path found! Length: {len(path)}")
        print("Path coordinates:", path)
        
        # Extract flag from path
        flag_pieces = extract_flag_from_path(maze, path)
        print(f"\nFlag pieces collected: {flag_pieces}")
        
        # The path should collect: DSCCTF{P4TH_4LG0R1THM_M4ST3R_2026}
        if flag_pieces:
            print(f"🎉 Flag: {flag_pieces}")
        else:
            print("⚠️  No flag pieces found in path")
            
    else:
        print("❌ No path found from start to end!")

def interactive_challenge():
    """Interactive version for CTF participants"""
    print("🗺️  Welcome to the Pathfinding Puzzle!")
    print("\nYou need to find the shortest path through this maze.")
    print("The flag is hidden in the characters you collect along the optimal route!\n")
    
    maze = create_maze()
    
    print("Your maze:")
    for i, row in enumerate(maze):
        print(f"{i}: {' '.join(row)}")
    
    print(f"\nMaze dimensions: {len(maze)} x {len(maze[0])}")
    print("Find the shortest path from 'S' to 'E' and collect the flag pieces!")
    print("\nSubmit your solution as a list of coordinates: [(row, col), ...]")
    print("Example: [(0,0), (0,1), (1,1)]")
    
    try:
        user_input = input("\nEnter your path: ")
        user_path = eval(user_input)  # Warning: unsafe in production!
        
        # Validate path
        if validate_path(maze, user_path):
            flag_pieces = extract_flag_from_path(maze, user_path)
            if "DSCCTF{" in flag_pieces:
                print(f"🎉 Correct! Flag: {flag_pieces}")
            else:
                print("Path is valid but doesn't collect the right flag pieces.")
                print(f"You collected: {flag_pieces}")
        else:
            print("❌ Invalid path! Check for walls and connectivity.")
            
    except Exception as e:
        print(f"Error parsing input: {e}")

def validate_path(maze, path):
    """Validate that the path is valid (no walls, connected, start to end)"""
    if not path:
        return False
    
    rows, cols = len(maze), len(maze[0])
    
    # Check start and end
    if path[0] != (0, 0) or path[-1] != (9, 0):  # Adjust based on actual S and E positions
        start_found = False
        end_found = False
        
        for row, col in path:
            if maze[row][col] == 'S':
                start_found = True
            if maze[row][col] == 'E':
                end_found = True
        
        if not (start_found and end_found):
            return False
    
    # Check each step
    for i, (row, col) in enumerate(path):
        # Check bounds
        if not (0 <= row < rows and 0 <= col < cols):
            return False
        
        # Check not a wall
        if maze[row][col] == '#':
            return False
        
        # Check connectivity (adjacent steps)
        if i > 0:
            prev_row, prev_col = path[i-1]
            distance = abs(row - prev_row) + abs(col - prev_col)
            if distance != 1:  # Must be adjacent
                return False
    
    return True

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "interactive":
        interactive_challenge()
    else:
        solve_challenge()