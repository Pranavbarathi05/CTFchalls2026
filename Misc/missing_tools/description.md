# Missing Tools Challenge

**Author:** Shadow PB  
**Category:** Miscellaneous  
**Difficulty:** Easy  
**Points:** 100

---

## Challenge Description

🔧 Welcome to the Command Center! You've been given SSH access to a Linux system, but something seems to be missing...

The system administrator has been "cleaning up" the server and may have removed some commonly used tools. Your mission is to locate and read the flag file despite the missing utilities.

**Connection Details:**
- Host: `ctf.dscjssstuniv.in`
- Port: `2222`  
- Username: `ctf`
- Password: `ctf`

**Your task:** Find and read the flag file located in the home directory.

---

## Files Provided
- `docker-compose.yml` - Container orchestration
- `Dockerfile` - Challenge environment

---

## Deployment
```bash
# Build and start the challenge
docker-compose up -d

# Connect to the challenge
ssh ctf@ctf.dscjssstuniv.in -p 2222
# Password: ctf
```

---

## Connection
```bash
ssh ctf@ctf.dscjssstuniv.in -p 2222
```
When prompted, use password: `ctf`

---

## Hints

💡 **Hint 1 (Free):** Try listing the files in your home directory first

💡 **Hint 2 (25 pts):** What happens when you try the most common file reading command?

💡 **Hint 3 (50 pts):** There are many ways to view file contents in Linux - think alternatives!

💡 **Hint 4 (75 pts):** Text editors, pagers, and even programming languages can read files

---

## Learning Objectives

This challenge teaches:
- **Linux Command Alternatives**: Understanding multiple ways to accomplish the same task
- **Problem Solving**: Adapting when standard tools are unavailable  
- **System Knowledge**: Knowing where commands are located and how they work
- **Creative Thinking**: Finding unconventional solutions to common problems

---

## Flag Format
`DSCCTF{...}`