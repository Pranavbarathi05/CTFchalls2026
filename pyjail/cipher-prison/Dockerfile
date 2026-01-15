FROM python:3.11-slim

# Install xinetd
RUN apt-get update && \
    apt-get install -y xinetd && \
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

# Copy xinetd configuration
COPY xinetd.conf /etc/xinetd.d/pyjail

# Create the ctf user (matching xinetd config)
RUN useradd -m -s /bin/bash ctf

# Expose the challenge port
EXPOSE 1337

# Start xinetd in foreground
CMD ["xinetd", "-dontfork"]
