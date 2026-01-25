FROM python:2.7-slim

# Fix Debian Buster EOL repository issues
RUN echo "deb http://archive.debian.org/debian/ buster main" > /etc/apt/sources.list && \
    echo "deb http://archive.debian.org/debian-security buster/updates main" >> /etc/apt/sources.list

# Install socat for serving the jail
RUN apt-get update && \
    apt-get install -y socat && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create challenge directory  
RUN mkdir /challenge
COPY jail.py /challenge/jail.py
COPY flag.txt /challenge/flag.txt
RUN chmod 555 /challenge/jail.py
RUN chmod 444 /challenge/flag.txt

# Create user for security
RUN useradd -m ctf

EXPOSE 9999

# Use socat to serve the jail (fork for each connection)
CMD ["socat", "-T120", "TCP-LISTEN:9999,reuseaddr,fork", "EXEC:python /challenge/jail.py,stderr"]