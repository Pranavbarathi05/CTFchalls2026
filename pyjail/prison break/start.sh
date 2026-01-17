#!/bin/bash

# Prison Break CTF Challenge Launcher
# Usage: ./start.sh [port]

PORT=${1:-9999}

echo "🔒 Starting Prison Break CTF Challenge..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Stop any existing container
echo "📋 Stopping existing containers..."
sudo docker stop prison-break 2>/dev/null || true
sudo docker rm prison-break 2>/dev/null || true

# Build the challenge
echo "🔨 Building container..."
if ! sudo docker build -t prison-break .; then
    echo "❌ Failed to build container"
    exit 1
fi

# Start the challenge
echo "🚀 Starting container..."
if ! sudo docker run -d --name prison-break -p $PORT:9999 prison-break; then
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
    echo "   sudo docker logs prison-break        # View logs"
    echo "   sudo docker stop prison-break       # Stop challenge"
    echo "   sudo docker restart prison-break    # Restart challenge"
    echo ""
    echo "🧪 Quick Test:"
    echo "   echo 'dir()' | nc localhost $PORT"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
else
    echo "❌ Container started but port $PORT is not accessible"
    echo "📋 Container status:"
    sudo docker ps -a | grep prison-break
    echo ""
    echo "📋 Container logs:"
    sudo docker logs prison-break
    exit 1
fi