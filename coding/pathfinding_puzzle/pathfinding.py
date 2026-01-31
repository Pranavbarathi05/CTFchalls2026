#!/usr/bin/env python3

import json
from collections import deque


def create_maze():
    """
    Maze where shortest path spells the flag:
    DSCCTF{P4TH}
    """

    maze = [
        ['S','D','S','C','C','T','F','{','P','4'],
        ['#','#','#','#','#','#','#','#','#','T'],
        ['#','.','.','.','.','.','.','.','#','H'],
        ['#','.','#','#','#','#','#','.','#','}'],
        ['#','.','#','.','.','.','#','.','.','E'],
        ['#','.','#','.','#','.','#','#','.','#'],
        ['#','.','.','.','#','.','.','.','.','#'],
        ['#','#','#','#','#','#','#','#','#','#'],
    ]

    return maze


def find_shortest_path(maze, start, end):
    rows, cols = len(maze), len(maze[0])

    queue = deque([(start[0], start[1], [])])
    visited = {(start[0], start[1])}

    directions = [(0,1),(1,0),(0,-1),(-1,0)]

    while queue:
        r, c, path = queue.popleft()

        if (r, c) == end:
            return path + [(r, c)]

        for dr, dc in directions:
            nr, nc = r + dr, c + dc

            if (0 <= nr < rows and
                0 <= nc < cols and
                (nr, nc) not in visited and
                maze[nr][nc] != '#'):

                visited.add((nr, nc))
                queue.append((nr, nc, path + [(r, c)]))

    return None


def extract_flag_from_path(maze, path):
    chars = []

    for r, c in path:
        ch = maze[r][c]
        if ch not in ['.', '#', 'S', 'E']:
            chars.append(ch)

    return ''.join(chars)


def validate_path(maze, path):
    if not path:
        return False

    rows, cols = len(maze), len(maze[0])

    sr, sc = path[0]
    er, ec = path[-1]

    if maze[sr][sc] != 'S' or maze[er][ec] != 'E':
        return False

    for i, (r, c) in enumerate(path):
        if not (0 <= r < rows and 0 <= c < cols):
            return False

        if maze[r][c] == '#':
            return False

        if i > 0:
            pr, pc = path[i - 1]
            if abs(r - pr) + abs(c - pc) != 1:
                return False

    return True


def find_start_end(maze):
    start = end = None

    for i in range(len(maze)):
        for j in range(len(maze[i])):
            if maze[i][j] == 'S':
                start = (i, j)
            if maze[i][j] == 'E':
                end = (i, j)

    return start, end


def interactive_challenge():
    print("🗺️ Pathfinding Puzzle Challenge\n")

    maze = create_maze()
    start, end = find_start_end(maze)

    print("Maze:")
    for i, row in enumerate(maze):
        print(f"{i}: {' '.join(row)}")

    print("\nCoordinates format:")
    print("[[row,col],[row,col],...]")

    example = find_shortest_path(maze, start, end)

    print("\nExample shortest path:")
    print(example)
    print(f"Shortest length: {len(example)}")

    while True:
        try:
            user_input = input("\nEnter path (or 'q'): ")

            if user_input.lower() == 'q':
                break

            user_path = json.loads(user_input)
            user_path = [tuple(p) for p in user_path]

            if validate_path(maze, user_path):
                collected = extract_flag_from_path(maze, user_path)

                print("✅ Valid path!")
                print("Collected:", collected)

                if "DSCCTF{" in collected:
                    print("🎉 FLAG:", collected)
                else:
                    print("⚠ Flag incomplete")

            else:
                print("❌ Invalid path")

        except Exception as e:
            print("Input error:", e)


if __name__ == "__main__":
    interactive_challenge()
