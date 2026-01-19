# Tree Traversal Secret

A data structures challenge focusing on binary tree traversal algorithms and pattern recognition.

---

## Challenge Info

| Field | Value |
|-------|-------|
| **Name** | Tree Traversal Secret |
| **Category** | Data Structures / Algorithms |
| **Difficulty** | Medium |
| **Flag** | `DSCCTF{TR33_TR4V3RS4L_S3CR3T_M4ST3R_2026}` |
| **Author** | ShadowPB |
| **Port** | 8005 |

---

## Challenge Description

🌳 Welcome to the Tree Traversal Secret challenge! You've been given a binary tree that contains a hidden message, but you need to traverse it in the correct order to reveal the secret flag.

Binary trees can be traversed in multiple ways, each revealing the nodes in a different sequence. The flag is hidden within the tree structure, but only the correct traversal method will reveal it in readable form.

---

## Files

- `tree_traversal.py` - Interactive challenge with tree implementation
- `solve.py` - Complete solution showing all traversal methods
- `flag.txt` - Target flag
- `description.md` - Challenge description
- `Dockerfile` - Container setup
- `docker-compose.yml` - Easy deployment

---

## Quick Start

### Interactive Mode
```bash
# Run the interactive challenge
python3 tree_traversal.py

# Test different traversal methods
# Try options 1-5 until you find the correct one
```

### Solution Mode
```bash
# See all traversal results
python3 solve.py

# Or get solutions directly
python3 tree_traversal.py solve
```

---

## Tree Traversal Methods

### Available Traversal Algorithms

1. **Inorder** (Left → Root → Right)
   ```python
   def inorder(node):
       if node:
           inorder(node.left)
           visit(node)
           inorder(node.right)
   ```

2. **Preorder** (Root → Left → Right) ⭐ *This reveals the flag!*
   ```python
   def preorder(node):
       if node:
           visit(node)
           preorder(node.left)
           preorder(node.right)
   ```

3. **Postorder** (Left → Right → Root)
   ```python
   def postorder(node):
       if node:
           postorder(node.left)
           postorder(node.right)
           visit(node)
   ```

4. **Level Order** (Breadth-First)
   ```python
   def level_order(root):
       if not root:
           return []
       queue = [root]
       result = []
       while queue:
           node = queue.pop(0)
           result.append(node.val)
           if node.left:
               queue.append(node.left)
           if node.right:
               queue.append(node.right)
       return result
   ```

5. **Reverse Inorder** (Right → Root → Left)
   ```python
   def reverse_inorder(node):
       if node:
           reverse_inorder(node.right)
           visit(node)
           reverse_inorder(node.left)
   ```

---

## Solution Approach

### Step 1: Understand the Challenge
- The flag characters are stored as node values in a binary tree
- Different traversal orders produce different character sequences
- Only one traversal method reveals the flag in correct format

### Step 2: Test Each Traversal Method
```python
traversals = {
    "Inorder": inorder_traversal(root),
    "Preorder": preorder_traversal(root),      # ← Correct method!
    "Postorder": postorder_traversal(root),
    "Level Order": level_order_traversal(root),
    "Reverse Inorder": reverse_inorder_traversal(root)
}

for name, result in traversals.items():
    result_str = ''.join(result)
    print(f"{name}: {result_str}")
    if "DSCCTF{" in result_str and result_str.endswith("}"):
        print(f"🎉 FLAG FOUND in {name} traversal!")
```

### Step 3: Extract the Flag
- The **Preorder traversal** reveals: `DSCCTF{TR33_TR4V3RS4L_S3CR3T_M4ST3R_2026}`
- This happens because the tree was constructed to store flag characters in preorder sequence

---

## Learning Objectives

- **Binary Trees**: Understanding tree data structure
- **Traversal Algorithms**: Different methods of visiting nodes
- **Recursion**: Implementing recursive tree algorithms
- **Pattern Recognition**: Identifying meaningful output sequences
- **Algorithm Analysis**: Understanding when to use each traversal type

---

## Tree Traversal Use Cases

| Traversal Type | Common Use Cases |
|----------------|------------------|
| **Inorder** | Binary Search Trees (sorted output), Expression evaluation |
| **Preorder** | Tree copying, Prefix notation, Directory listing |
| **Postorder** | Tree deletion, Postfix notation, File size calculation |
| **Level Order** | Tree printing, Serialization, Breadth-first operations |

---

## Implementation Details

### Tree Node Structure
```python
class TreeNode:
    def __init__(self, val=0, left=None, right=None):
        self.val = val      # Character value
        self.left = left    # Left child
        self.right = right  # Right child
```

### Tree Construction
The tree is built such that when traversed in **preorder**, it yields:
```
D-S-C-C-T-F-{-T-R-E-E-_-T-R-A-V-E-R-S-A-L-_-S-E-C-R-E-T-_-M-A-S-T-E-R-_-2-0-2-6-}
```

### Example Tree Structure
```
       D
      / \
     S   C
    / \ / \
   C  C T  F
     /   \
    T     {...}
   /       \
  F         R
           / \
          A   S
             / \
            T   E
               / \
              R   _
             /     \
            2       0
           /         \
          2           6
         /           /
        6           }
```

---

## Advanced Concepts

### Iterative Implementations
```python
def iterative_preorder(root):
    if not root:
        return []
    
    result = []
    stack = [root]
    
    while stack:
        node = stack.pop()
        result.append(node.val)
        
        # Push right first, then left (stack is LIFO)
        if node.right:
            stack.append(node.right)
        if node.left:
            stack.append(node.left)
    
    return result
```

### Morris Traversal (Space-Optimized)
```python
def morris_inorder(root):
    result = []
    current = root
    
    while current:
        if not current.left:
            result.append(current.val)
            current = current.right
        else:
            # Find inorder predecessor
            predecessor = current.left
            while predecessor.right and predecessor.right != current:
                predecessor = predecessor.right
            
            if not predecessor.right:
                predecessor.right = current
                current = current.left
            else:
                predecessor.right = None
                result.append(current.val)
                current = current.right
    
    return result
```

---

## Time and Space Complexity

| Traversal | Time Complexity | Space Complexity |
|-----------|----------------|------------------|
| Recursive | O(n) | O(h) where h = height |
| Iterative | O(n) | O(h) for stack |
| Morris | O(n) | O(1) constant space |

---

## Hints

1. Try all traversal methods systematically
2. Look for output that resembles a CTF flag format
3. The correct traversal produces readable text
4. Preorder traversal visits root first, then subtrees
5. The tree was designed with a specific traversal in mind

This challenge reinforces fundamental tree algorithms while demonstrating how data structure choice affects output patterns.