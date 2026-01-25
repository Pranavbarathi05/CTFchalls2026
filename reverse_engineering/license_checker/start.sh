#!/bin/bash

# Start the license checker as a network service
while true; do
    ./license_checker | nc -l 8002
done
