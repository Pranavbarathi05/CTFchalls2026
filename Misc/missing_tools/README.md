# Missing Tools

**Name:** Missing Tools  
**Category:** Miscellaneous  
**Difficulty:** Easy  
**Points:** 100  
**Flag:** `DSCCTF{M1SS1NG_T00LS_N0_PR0BL3M_2026}`

---

## Overview

🔧 A Linux system administration challenge where common file reading tools have been removed from the system. Players must find alternative methods to read the flag file.

---

## Challenge Setup

The challenge consists of an Ubuntu Docker container with:
- SSH server running on port 2222
- User account `ctf` with password `ctf`
- Flag file in `/home/ctf/flag.txt`
- Missing `cat` command to create the puzzle

---

## Deployment Instructions

### Quick Start
```bash
./start.sh
```

### Manual Deployment
```bash
# Build and start the container
docker-compose up -d

# Verify it's running
docker ps | grep missing_tools

# Connect to test
ssh ctf@localhost -p 2222
# Password: ctf
```

### Cleanup
```bash
docker-compose down
```

---

## Challenge Interaction

### Player Experience
1. **Connection**: SSH into the container with provided credentials
2. **Discovery**: Find flag.txt in home directory  
3. **Problem**: Discover that `cat` command is missing
4. **Solution**: Use alternative file reading methods

### Expected Solution Flow
```bash
# Connect to the challenge
ssh ctf@localhost -p 2222

# List files
ls -la

# Try common approach (fails)
cat flag.txt
# bash: cat: command not found

# Use alternatives
less flag.txt           # View with pager
head flag.txt           # Show first lines
tail flag.txt           # Show last lines
grep . flag.txt         # Use grep to display
python3 -c "print(open('flag.txt').read())"  # Python
# ... many other methods
```

---

## Solution Methods

There are **25+ different ways** to solve this challenge:

### Text Viewers/Pagers
- `less flag.txt`
- `more flag.txt`  
- `head flag.txt`
- `tail flag.txt`

### Text Processing
- `grep . flag.txt`
- `awk '{print}' flag.txt`
- `sed '' flag.txt`
- `sort flag.txt`

### Editors (View Mode)
- `vim flag.txt` (then `:q`)
- `nano flag.txt` (then Ctrl+X)

### Programming Languages  
- `python3 -c "print(open('flag.txt').read())"`

### Binary/Hex Tools
- `od -c flag.txt`
- `hexdump -C flag.txt`
- `strings flag.txt`

### Network Tools
- `curl file:///home/ctf/flag.txt`

### Shell Scripting
- `while read line; do echo $line; done < flag.txt`

---

## Testing

### Automated Testing
```bash
# Install requirements
pip3 install -r requirements.txt

# Run solver
python3 solve.py

# Show all solutions  
python3 solve.py solutions
```

### Manual Testing
```bash
# Start challenge
./start.sh

# Connect and test
ssh ctf@localhost -p 2222
# Try: less flag.txt
```

---

## Educational Value

### Skills Developed
- **Linux Command Knowledge**: Learning file manipulation beyond basic commands
- **Problem Solving**: Adapting when standard tools are unavailable
- **Creative Thinking**: Finding multiple approaches to the same goal
- **System Administration**: Understanding command locations and alternatives

### Difficulty Justification
- **Easy**: Multiple valid solutions exist
- **Beginner-Friendly**: Teaches fundamental Linux skills
- **Engaging**: "Aha moment" when finding alternatives

---

## Technical Details

### Container Specifications
- **Base Image**: Ubuntu:latest
- **SSH Port**: 2222 (mapped from 22)
- **User**: ctf:ctf
- **Missing Commands**: cat (removed from /usr/bin/cat and /bin/cat)
- **Available Tools**: vim, nano, less, python3, curl, standard shell utilities

### Security Considerations
- SSH password authentication enabled
- Root login disabled
- Non-privileged user account
- Standard Ubuntu security defaults maintained

---

## Troubleshooting

### Common Issues

**Container won't start:**
```bash
# Check Docker daemon
docker ps
docker-compose logs
```

**SSH connection refused:**
```bash
# Wait for SSH service
sleep 10
# Check port mapping
docker port missing_tools_ctf
```

**Can't connect to SSH:**
- Verify port 2222 is available
- Check firewall settings
- Ensure container is running: `docker ps`

---

## Extensions

### Difficulty Variations
- **Harder**: Remove more commands (less, more, head, tail)
- **Advanced**: Remove text editors and Python  
- **Expert**: Implement command aliasing to fake commands

### Additional Learning
- Add multiple flag pieces requiring different methods
- Include binary files requiring hex viewers
- Add network-based flag retrieval

---

## File Structure
```
missing_tools/
├── Dockerfile              # Container definition
├── docker-compose.yml      # Orchestration config  
├── description.md           # Challenge description
├── README.md               # This documentation
├── solve.py                # Automated solver & tester
├── requirements.txt        # Python dependencies
└── start.sh                # Quick start script
```