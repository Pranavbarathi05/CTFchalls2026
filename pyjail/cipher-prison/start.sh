#!/bin/bash
# Quick start script for the PyJail KeySwapper challenge

set -e

echo "=== PyJail KeySwapper Challenge ==="
echo ""

# Check if docker is available
if ! command -v docker &> /dev/null; then
    echo "[!] Docker not found. Please install Docker first."
    exit 1
fi

# Check if docker-compose is available
if command -v docker-compose &> /dev/null; then
    COMPOSE_CMD="docker-compose"
elif docker compose version &> /dev/null 2>&1; then
    COMPOSE_CMD="docker compose"
else
    echo "[!] Docker Compose not found. Using plain Docker..."
    echo "[*] Building image..."
    docker build -t pyjail-keyswap .
    echo "[*] Starting container..."
    docker run -d -p 1337:1337 --name pyjail-keyswap --rm pyjail-keyswap
    echo ""
    echo "[+] Challenge is now running!"
    echo "[+] Connect with: nc localhost 1337"
    exit 0
fi

echo "[*] Starting with Docker Compose..."
$COMPOSE_CMD up -d --build

echo ""
echo "[+] Challenge is now running!"
echo "[+] Connect with: nc localhost 1337"
echo ""
echo "To stop: $COMPOSE_CMD down"
echo "To view logs: $COMPOSE_CMD logs -f"
