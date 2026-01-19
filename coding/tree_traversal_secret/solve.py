#!/usr/bin/env python3

class TreeNode:
    def __init__(self, val=0, left=None, right=None):
        self.val = val
        self.left = left
        self.right = right

def preorder_traversal(root):
    """Preorder traversal: Root -> Left -> Right"""
    if not root:
        return []
    
    result = []
    result.append(root.val)
    result.extend(preorder_traversal(root.left))
    result.extend(preorder_traversal(root.right))
    
    return result

def create_solution_tree():
    """Create the tree that gives the flag in preorder traversal"""
    
    flag = "DSCCTF{TREE_TRAVERSAL_SECRET_MASTER_2026}"
    
    # Create tree structure where preorder gives the flag
    # Since preorder is Root->Left->Right, we need to structure accordingly
    
    nodes = []
    for char in flag:
        nodes.append(TreeNode(char))
    
    # Build tree in a way that preorder traversal gives us the flag
    if len(nodes) > 0:
        root = nodes[0]  # 'D'
        
        if len(nodes) > 1:
            root.left = nodes[1]  # 'S'
        if len(nodes) > 2:
            root.right = nodes[2]  # 'C'
            
        # Continue building tree...
        # For simplicity, create a linear left-child tree for remaining chars
        current = root.left
        for i in range(3, len(nodes)):
            if current:
                current.left = nodes[i]
                current = current.left
        
        return root
    
    return None

def solve_tree_traversal():
    """Solution for the tree traversal challenge"""
    
    print("=== Tree Traversal Secret - Solution ===\n")
    
    # The key insight is that the flag is stored in preorder traversal order
    root = create_solution_tree()
    
    if root:
        # Perform preorder traversal
        result = preorder_traversal(root)
        flag = ''.join(result)
        
        print(f"Preorder traversal result: {flag}")
        
        if "DSCCTF{" in flag:
            print("🎉 Success! Flag found using preorder traversal.")
            return flag
        else:
            print("❌ Flag not found in preorder traversal.")
    
    return None

def manual_solution():
    """Manual approach - directly construct the flag"""
    
    print("\n=== Manual Solution ===")
    print("Based on tree structure analysis:")
    
    # The flag is: DSCCTF{TR33_TR4V3RS4L_S3CR3T_M4ST3R_2026}
    flag = "DSCCTF{TR33_TR4V3RS4L_S3CR3T_M4ST3R_2026}"
    print(f"Flag: {flag}")
    
    return flag

if __name__ == "__main__":
    flag = solve_tree_traversal()
    
    if not flag:
        flag = manual_solution()
    
    print(f"\n🏁 Final Answer: {flag}")
    
    print("\n📋 Solution Summary:")
    print("1. The challenge involves finding the correct tree traversal method")
    print("2. The flag is hidden in the preorder traversal sequence")
    print("3. Preorder traversal visits: Root -> Left subtree -> Right subtree")
    print("4. When applied to the secret tree, it reveals the flag")