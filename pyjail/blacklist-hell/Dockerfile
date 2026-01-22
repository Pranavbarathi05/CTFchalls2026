FROM python:3.11-slim

# Install socat (simpler and more reliable than xinetd)
RUN apt-get update && \
    apt-get install -y socat && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create challenge directory
RUN mkdir /challenge

# Copy challenge files
COPY challenge/jail.py /challenge/jail.py
COPY challenge/flag.txt /flag.txt

# Set permissions
RUN chmod 555 /challenge/jail.py && \
    chmod 444 /flag.txt && \
    chown root:root /flag.txt

# Create the ctf user
RUN useradd -m -s /bin/bash ctf

# Expose the challenge port
EXPOSE 1338

# Start with socat - forks for each connection, 180s timeout
CMD ["socat", "-T180", "TCP-LISTEN:1338,reuseaddr,fork", "EXEC:python3 /challenge/jail.py,stderr"]
