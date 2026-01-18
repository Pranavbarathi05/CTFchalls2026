#!/bin/bash

echo "Starting Missing Tools Challenge..."

# Build and start the Docker container
docker-compose up -d

echo "Waiting for SSH service to start..."
sleep 10

echo "Challenge is ready!"
echo "Connect with: ssh ctf@localhost -p 2222"
echo "Password: ctf"
echo ""
echo "To stop the challenge: docker-compose down"