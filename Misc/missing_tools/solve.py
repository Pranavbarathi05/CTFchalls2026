#!/usr/bin/env python3

import subprocess
import time
import paramiko

def test_challenge():
    """Test the missing tools challenge"""
    
    print("=== Missing Tools Challenge Solver ===\n")
    
    # Wait for container to be ready
    print("Waiting for SSH service to be ready...")
    time.sleep(5)
    
    try:
        # Create SSH client
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        # Connect to the container
        print("Connecting to SSH service...")
        ssh.connect('missingtools.challenges2.ctf.dscjssstuniv.in', port=2222, username='ctf', password='ctf', timeout=10)
        
        print("✅ Successfully connected to SSH service\n")
        
        # Test 1: List files in home directory
        print("1. Listing files in home directory:")
        stdin, stdout, stderr = ssh.exec_command('ls -la')
        output = stdout.read().decode()
        print(output)
        
        # Test 2: Try cat command (should fail)
        print("2. Trying 'cat flag.txt' (should fail):")
        stdin, stdout, stderr = ssh.exec_command('cat flag.txt')
        error = stderr.read().decode()
        print(f"Error: {error.strip()}")
        
        # Test 3: Try alternative methods
        alternatives = [
            ('less', 'less flag.txt'),
            ('head', 'head flag.txt'), 
            ('tail', 'tail flag.txt'),
            ('more', 'more flag.txt'),
            ('grep', 'grep . flag.txt'),
            ('awk', 'awk "{print}" flag.txt'),
            ('sed', 'sed "" flag.txt'),
            ('python3', 'python3 -c "print(open(\'flag.txt\').read().strip())"'),
            ('vim (view mode)', 'vim -R +"%p|q!" flag.txt 2>/dev/null'),
        ]
        
        print("\n3. Testing alternative file reading methods:")
        print("=" * 50)
        
        successful_methods = []
        
        for method_name, command in alternatives:
            print(f"\nTrying {method_name}:")
            stdin, stdout, stderr = ssh.exec_command(command)
            output = stdout.read().decode().strip()
            error = stderr.read().decode().strip()
            
            if output and "DSCCTF{" in output:
                print(f"✅ SUCCESS: {output}")
                successful_methods.append(method_name)
            elif error:
                print(f"❌ Error: {error}")
            else:
                print(f"⚠️  No output or flag not found")
        
        print(f"\n{'='*50}")
        print(f"Summary: {len(successful_methods)} working methods found")
        print(f"Working methods: {', '.join(successful_methods)}")
        
        ssh.close()
        
    except Exception as e:
        print(f"❌ Connection failed: {e}")
        return False
    
    return True

def demonstrate_solutions():
    """Show all possible solutions for educational purposes"""
    print("\n=== All Possible Solutions ===")
    
    solutions = [
        "less flag.txt",
        "more flag.txt", 
        "head flag.txt",
        "tail flag.txt",
        "grep . flag.txt",
        "grep '' flag.txt",
        "awk '{print}' flag.txt",
        "sed '' flag.txt",
        "sed -n 'p' flag.txt",
        "sort flag.txt",
        "tac flag.txt",
        "rev flag.txt | rev",
        "cut -c1- flag.txt",
        "python3 -c \"print(open('flag.txt').read())\"",
        "python3 -c \"import sys; sys.stdout.write(open('flag.txt').read())\"",
        "vim flag.txt  # then :q to exit",
        "nano flag.txt  # then Ctrl+X to exit",
        "emacs flag.txt  # then Ctrl+X Ctrl+C to exit",
        "od -c flag.txt  # octal dump",
        "hexdump -C flag.txt",
        "xxd flag.txt",
        "strings flag.txt",
        "curl file:///home/ctf/flag.txt",
        "while read line; do echo $line; done < flag.txt",
        "exec < flag.txt; read line; echo $line",
        "mapfile -t lines < flag.txt; echo ${lines[0]}",
    ]
    
    print("Here are all the ways to read the flag file:")
    for i, solution in enumerate(solutions, 1):
        print(f"{i:2d}. {solution}")
    
    print(f"\nTotal: {len(solutions)} different methods!")

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == "solutions":
        demonstrate_solutions()
    else:
        success = test_challenge()
        if success:
            demonstrate_solutions()
        else:
            print("\n⚠️  Make sure the Docker container is running:")
            print("docker-compose up -d")