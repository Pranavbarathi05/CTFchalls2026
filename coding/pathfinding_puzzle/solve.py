#!/usr/bin/env python3

import sys
from collections import deque

def solve_pathfinding_puzzle():
    """Complete solution for the pathfinding puzzle"""
    
    # The maze (copied from the challenge)
    maze = [
        ['S', '.', '#', '.', '.', '.', '#', '.', '.', 'D'],
        ['.', '#', '.', '#', '.', '#', '.', '#', '.', 'S'], 
        ['.', '.', '.', '.', '.', '.', '.', '.', '.', 'C'],
        ['#', '#', '#', '.', '#', '#', '#', '.', '#', '.'],
        ['.', '.', '.', '.', '.', '.', '.', '.', '.', 'C'],
        ['.', '#', '#', '#', '.', '#', '#', '#', '.', 'T'],
        ['.', '.', '.', '.', '.', '.', '.', '.', '.', 'F'],
        ['#', '.', '#', '#', '#', '#', '#', '.', '#', '{'],
        ['.', '.', '.', '.', '.', '.', '.', '.', '.', 'P'],
        ['E', '.', '#', '.', '#', '.', '#', '.', '.', 'A']
    ]
    
    def find_position(maze, char):
        for i in range(len(maze)):
            for j in range(len(maze[i])):
                if maze[i][j] == char:
                    return (i, j)
        return None
    
    def bfs_shortest_path(maze, start, end):
        rows, cols = len(maze), len(maze[0])
        queue = deque([(start[0], start[1], [])])
        visited = set([(start[0], start[1])])
        
        directions = [(0, 1), (1, 0), (0, -1), (-1, 0)]
        
        while queue:
            row, col, path = queue.popleft()
            
            if (row, col) == end:
                return path + [(row, col)]
            
            for dr, dc in directions:
                new_row, new_col = row + dr, col + dc
                
                if (0 <= new_row < rows and 0 <= new_col < cols and 
                    (new_row, new_col) not in visited and 
                    maze[new_row][new_col] != '#'):
                    
                    visited.add((new_row, new_col))
                    queue.append((new_row, new_col, path + [(row, col)]))
        
        return None
    
    # Find start and end
    start = find_position(maze, 'S')
    end = find_position(maze, 'E')
    
    print("=== Pathfinding Puzzle Solution ===")
    print(f"Start: {start}, End: {end}")
    
    # Find shortest path
    path = bfs_shortest_path(maze, start, end)
    
    if path:
        print(f"Shortest path: {path}")
        print(f"Path length: {len(path)}")
        
        # Extract flag
        flag_chars = []
        for row, col in path:
            char = maze[row][col]
            if char not in ['.', '#', 'S', 'E']:
                flag_chars.append(char)
        
        flag = ''.join(flag_chars)
        print(f"🎉 Flag: {flag}")
        
        return path, flag
    else:
        print("No path found!")
        return None, None

def visualize_path(maze, path):
    """Visualize the path on the maze"""
    if not path:
        return
    
    # Create a copy of maze for visualization
    visual_maze = [row[:] for row in maze]
    
    # Mark path with *
    for i, (row, col) in enumerate(path):
        if visual_maze[row][col] not in ['S', 'E']:
            visual_maze[row][col] = '*'
    
    print("\nPath visualization (* = path):")
    for row in visual_maze:
        print(' '.join(row))

if __name__ == "__main__":
    path, flag = solve_pathfinding_puzzle()
    
    if path:
        maze = [
            ['S', '.', '#', '.', '.', '.', '#', '.', '.', 'D'],
            ['.', '#', '.', '#', '.', '#', '.', '#', '.', 'S'], 
            ['.', '.', '.', '.', '.', '.', '.', '.', '.', 'C'],
            ['#', '#', '#', '.', '#', '#', '#', '.', '#', '.'],
            ['.', '.', '.', '.', '.', '.', '.', '.', '.', 'C'],
            ['.', '#', '#', '#', '.', '#', '#', '#', '.', 'T'],
            ['.', '.', '.', '.', '.', '.', '.', '.', '.', 'F'],
            ['#', '.', '#', '#', '#', '#', '#', '.', '#', '{'],
            ['.', '.', '.', '.', '.', '.', '.', '.', '.', 'P'],
            ['E', '.', '#', '.', '#', '.', '#', '.', '.', 'A']
        ]
        
        visualize_path(maze, path)
        
        print(f"\n📋 Solution for CTF:")
        print(f"Path: {path}")
        print(f"Flag: {flag}")