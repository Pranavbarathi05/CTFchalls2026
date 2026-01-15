# PyJail KeySwapper Challenge

A CTF challenge combining a Python jail with a dynamic key-swapping cipher.

## Deployment

### Using Docker Compose (Recommended)

```bash
cd pyjail-keyswap
docker-compose up -d
```

The challenge will be available at `nc localhost 1337`

### Manual Docker Build

```bash
docker build -t pyjail-keyswap .
docker run -d -p 1337:1337 --name pyjail-keyswap pyjail-keyswap
```

### Using ncat directly (for testing)

```bash
ncat -lvnp 1337 -e "python3 challenge/jail.py"
```

## Connection

```bash
nc <host> 1337
# or
ncat <host> 1337
```

## Challenge Mechanics

1. **Dynamic KeySwapper**: Uses Caesar cipher on alphanumeric characters
   - Rotation starts at 0
   - Increases by 7 after each command
   - Alphabet: `abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789`

2. **Blacklist**: Common dangerous keywords and characters are blocked
   - `import`, `exec`, `eval`, `open`, etc.
   - `_`, `.`, `[`, `]`, `\` characters

3. **Restricted Builtins**: Only safe functions available
   - `print`, `len`, `range`, `list`, `int`, `float`, etc.

## Difficulty

**Hard** - Requires understanding of:
- Python sandbox escapes
- Caesar/substitution ciphers
- Scripting to handle rotating cipher

## Flag

```
DSCCTF{dyn4m1c_k3ysw4p_j41l_br34k3r_2026}
```

## Hints (for players)

1. The rotation formula is: `new_rotation = (current + 7) % 62`
2. Write a script to encode your payloads
3. Think about what's NOT blocked
4. The prompt shows the current rotation

## Files

```
pyjail-keyswap/
├── challenge/
│   ├── jail.py          # Main challenge code
│   └── flag.txt         # Flag file
├── solve/
│   └── solver.py        # Solution helper script
├── Dockerfile           # Docker image definition
├── docker-compose.yml   # Docker compose config
├── xinetd.conf          # xinetd service config
└── README.md            # This file
```

## Security Notes

- Runs as `nobody` user
- 2-minute timeout per connection
- Memory and CPU limits via Docker
- Read-only container
- Rate limited to 5 connections per source IP
