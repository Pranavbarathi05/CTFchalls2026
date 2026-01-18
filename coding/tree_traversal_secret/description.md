# Tree Traversal Secret

**Author:** Shadow PB  
**Category:** Data Structures  
**Difficulty:** Medium  
**Points:** 200

---

## Challenge Description

🌳 Welcome to the Tree Traversal Secret challenge! You've been given a binary tree that contains a hidden message, but you need to traverse it in the correct order to reveal the secret flag.

Binary trees can be traversed in multiple ways, each revealing the nodes in a different sequence. The flag is hidden within the tree structure, but only the correct traversal method will reveal it in readable form.

**Your task:** Find the correct tree traversal method that reveals the hidden flag.

---

## Files Provided
- `tree_traversal.py` - Interactive challenge with tree implementation

---

## Usage
```bash
python3 tree_traversal.py
# Try different traversal options (1-5)
```

---

## Traversal Methods Available
1. Inorder (Left → Root → Right)
2. Preorder (Root → Left → Right) 
3. Postorder (Left → Right → Root)
4. Level Order (Breadth-First)
5. Reverse Inorder (Right → Root → Left)

---

## Hints

💡 **Hint 1 (Free):** Try all traversal methods systematically

💡 **Hint 2 (75 pts):** Look for output that resembles a CTF flag format

💡 **Hint 3 (125 pts):** The correct traversal produces readable text

💡 **Hint 4 (175 pts):** Preorder traversal visits root first, then subtrees

---

## Flag Format
`DSCCTF{...}`