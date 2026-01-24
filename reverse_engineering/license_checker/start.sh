#!/bin/bash

# Start the license checker as a network service
while true; do
    ./license_checker | nc -l -p 8002
done
