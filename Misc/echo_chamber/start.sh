# Echo Chamber - Setup Instructions

## Quick Start

1. **Build and run the challenge:**
   ```bash
   cd echo_chamber
   docker-compose up -d
   ```

2. **Test the application:**
   ```bash
   curl "http://localhost:8070/?scanner=50000"
   ```

3. **Run the exploit:**
   ```bash
   python3 solve.py
   ```

4. **Clean up:**
   ```bash
   docker-compose down
   ```

## Manual Exploitation

The challenge can also be solved manually by understanding the TCP self-connect vulnerability:

1. Send POST requests with JSON payloads
2. Use the `scanner` parameter to define port ranges
3. Craft payloads with `signal: "Echo"` and appropriate commands
4. The application will attempt to connect to ports in the range `scanner` to `scanner + 37`
5. When conditions align, the connection will loop back to itself
6. The JSON payload will be processed and the command executed

## Security Note

This challenge demonstrates a real networking vulnerability. The TCP self-connect behavior has been documented and can occur in production environments under specific conditions.