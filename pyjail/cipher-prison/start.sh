#!/bin/bash

# Cipher-Prison CTF Challenge Launcher
# Usage: ./start.sh [port]

PORT=${1:-1337}

echo "🔐 Starting Cipher-Prison CTF Challenge..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Stop any existing container
echo "📋 Stopping existing containers..."
sudo docker-compose down 2>/dev/null || true

# Start the challenge
echo "🚀 Building and starting container..."
if ! sudo docker-compose up -d --build; then
    echo "❌ Failed to start container"
    exit 1
fi

# Wait for container to be ready
echo "⏳ Waiting for container to be ready..."
sleep 3

# Test connection
if nc -z localhost $PORT 2>/dev/null; then
    echo "✅ Challenge is now running!"
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "🎯 Challenge Access:"
    echo "   nc localhost $PORT"
    echo ""
    echo "🔧 Management Commands:"
    echo "   sudo docker-compose logs -f    # View live logs"
    echo "   sudo docker-compose down       # Stop challenge"
    echo "   sudo docker-compose restart    # Restart challenge"
    echo ""
    echo "🧪 Quick Test:"
    echo "   echo 'print(1+1)' | nc localhost $PORT"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
else
    echo "❌ Container started but port $PORT is not accessible"
    echo "📋 Container status:"
    sudo docker-compose ps
    echo ""
    echo "📋 Container logs:"
    sudo docker-compose logs
    exit 1
fi
