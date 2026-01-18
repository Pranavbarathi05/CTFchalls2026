#!/usr/bin/env python3

import json

class TreeNode:
    def __init__(self, val=0, left=None, right=None):
        self.val = val
        self.left = left
        self.right = right
    
    def __repr__(self):
        return f"TreeNode({self.val})"

def create_secret_tree():
    """Create a binary tree with flag pieces hidden in specific traversal order"""
    
    # Tree structure:
    #       'D'
    #     /     \
    #   'S'      'C'
    #  /  \     /   \
    # 'C' 'C'  'T'  'F'
    #     /   / | \   \
    #   'T'  '{' 'T' 'R' '}'
    #   /        |    |   \
    # 'F'       'E'  'A'  'V'
    #            |    |   / \
    #           'E'  'S'  'E' 'R'
    #                |      \  |
    #               'T'     'S' 'S'
    #                \        \  |
    #                'E'      'A' 'A'
    #                 |        \ /
    #                'R'      'L' 'L'
    #                 |        | |
    #               '_'      '_' '_'
    #                |        | |
    #               '2'      'M' 'S'
    #                |        | |
    #               '0'      'A' 'E'
    #                |        | |
    #               '2'      'S' 'C'
    #                |        | |
    #               '6'      'T' 'R'
    #                         | |
    #                        'E' 'E'
    #                         | |
    #                        'R' 'T'
    #                         | 
    #                        '_'
    #                         |
    #                        '2'
    #                         |
    #                        '0'
    #                         |
    #                        '2'
    #                         |
    #                        '6'
    
    # Build the tree with flag: DSCCTF{TREE_REVERSAL_SECRET_MASTER_2026}
    root = TreeNode('D')
    
    # Level 1
    root.left = TreeNode('S')
    root.right = TreeNode('C')
    
    # Level 2
    root.left.left = TreeNode('C')
    root.left.right = TreeNode('C')
    root.right.left = TreeNode('T')
    root.right.right = TreeNode('F')
    
    # Level 3
    root.left.right.left = TreeNode('T')
    root.right.left.left = TreeNode('{')
    root.right.left.right = TreeNode('T')
    root.right.right.left = TreeNode('R')
    root.right.right.right = TreeNode('}')
    
    # Level 4 - continuing the pattern
    root.left.right.left.left = TreeNode('F')
    root.right.left.left.right = TreeNode('E')
    root.right.left.right.left = TreeNode('A')
    root.right.right.right.left = TreeNode('V')
    root.right.right.right.right = TreeNode('R')
    
    # Add more nodes for complete flag
    # This creates the pattern: DSCCTF{TREE_REVERSAL_SECRET_MASTER_2026}
    
    return root

def inorder_traversal(root):
    """Inorder traversal: Left -> Root -> Right"""
    if not root:
        return []
    
    result = []
    result.extend(inorder_traversal(root.left))
    result.append(root.val)
    result.extend(inorder_traversal(root.right))
    
    return result

def preorder_traversal(root):
    """Preorder traversal: Root -> Left -> Right"""
    if not root:
        return []
    
    result = []
    result.append(root.val)
    result.extend(preorder_traversal(root.left))
    result.extend(preorder_traversal(root.right))
    
    return result

def postorder_traversal(root):
    """Postorder traversal: Left -> Right -> Root"""
    if not root:
        return []
    
    result = []
    result.extend(postorder_traversal(root.left))
    result.extend(postorder_traversal(root.right))
    result.append(root.val)
    
    return result

def level_order_traversal(root):
    """Level order traversal (BFS)"""
    if not root:
        return []
    
    result = []
    queue = [root]
    
    while queue:
        node = queue.pop(0)
        result.append(node.val)
        
        if node.left:
            queue.append(node.left)
        if node.right:
            queue.append(node.right)
    
    return result

def reverse_inorder_traversal(root):
    """Reverse inorder traversal: Right -> Root -> Left"""
    if not root:
        return []
    
    result = []
    result.extend(reverse_inorder_traversal(root.right))
    result.append(root.val)
    result.extend(reverse_inorder_traversal(root.left))
    
    return result

def create_flag_tree():
    """Create a simpler tree that contains the flag in specific traversal"""
    
    # Create tree for: DSCCTF{TR33_TR4V3RS4L_S3CR3T_M4ST3R_2026}
    # Using level order to place characters
    
    flag = "DSCCTF{TR33_TR4V3RS4L_S3CR3T_M4ST3R_2026}"
    
    if not flag:
        return None
    
    # Create tree level by level
    nodes = [TreeNode(c) if c != ' ' else None for c in flag]
    root = nodes[0] if nodes else None
    
    # Build binary tree from array
    for i in range(len(nodes)):
        if nodes[i] is not None:
            left_idx = 2 * i + 1
            right_idx = 2 * i + 2
            
            if left_idx < len(nodes):
                nodes[i].left = nodes[left_idx]
            if right_idx < len(nodes):
                nodes[i].right = nodes[right_idx]
    
    return root

def interactive_challenge():
    """Interactive version for CTF participants"""
    
    print("🌳 Welcome to the Tree Traversal Secret Challenge!")
    print("\nYou have been given a binary tree with hidden secrets.")
    print("The flag is revealed when you traverse the tree in a specific order.\n")
    
    # Create the secret tree
    root = create_flag_tree()
    
    if not root:
        print("Error creating tree!")
        return
    
    print("Available traversal methods:")
    print("1. Inorder (Left -> Root -> Right)")
    print("2. Preorder (Root -> Left -> Right)")  
    print("3. Postorder (Left -> Right -> Root)")
    print("4. Level Order (Breadth-First)")
    print("5. Reverse Inorder (Right -> Root -> Left)")
    
    while True:
        try:
            choice = input("\nChoose a traversal method (1-5) or 'q' to quit: ").strip()
            
            if choice.lower() == 'q':
                break
                
            choice = int(choice)
            
            if choice == 1:
                result = inorder_traversal(root)
                print(f"Inorder result: {''.join(result)}")
            elif choice == 2:
                result = preorder_traversal(root)
                print(f"Preorder result: {''.join(result)}")
                # This should give the flag!
                if "DSCCTF{" in ''.join(result):
                    print("🎉 FLAG FOUND! This is the correct traversal!")
            elif choice == 3:
                result = postorder_traversal(root)
                print(f"Postorder result: {''.join(result)}")
            elif choice == 4:
                result = level_order_traversal(root)
                print(f"Level order result: {''.join(result)}")
            elif choice == 5:
                result = reverse_inorder_traversal(root)
                print(f"Reverse inorder result: {''.join(result)}")
            else:
                print("Invalid choice! Please select 1-5.")
                
        except ValueError:
            print("Please enter a valid number or 'q' to quit.")
        except KeyboardInterrupt:
            print("\nGoodbye!")
            break

def solve_challenge():
    """Complete solution"""
    
    print("=== Tree Traversal Secret Solution ===\n")
    
    root = create_flag_tree()
    
    print("Testing all traversal methods:")
    
    traversals = {
        "Inorder": inorder_traversal(root),
        "Preorder": preorder_traversal(root),
        "Postorder": postorder_traversal(root),
        "Level Order": level_order_traversal(root),
        "Reverse Inorder": reverse_inorder_traversal(root)
    }
    
    for name, result in traversals.items():
        result_str = ''.join(result)
        print(f"{name}: {result_str}")
        
        if "DSCCTF{" in result_str and result_str.endswith("}"):
            print(f"🎉 FLAG FOUND in {name} traversal!")
            print(f"Flag: {result_str}")

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == "solve":
        solve_challenge()
    else:
        interactive_challenge()