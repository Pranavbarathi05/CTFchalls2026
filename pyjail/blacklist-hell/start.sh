#!/bin/bash

echo "[+] Starting Blacklist-Hell PyJail Challenge..."
docker-compose up -d --build

echo ""
echo "[✓] Challenge is running on port 1338"
echo ""
echo "Test with: nc localhost 1338"
echo ""
echo "To view logs: docker-compose logs -f"
echo "To stop: docker-compose down"
