FROM python:3.11-slim

WORKDIR /app

# Install socat for TCP handling
RUN apt-get update && \
    apt-get install -y socat && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

COPY dystopian_arithmetic.py .
COPY flag.txt .

EXPOSE 8018

CMD ["socat", "TCP-LISTEN:8018,reuseaddr,fork", "EXEC:python3 -u dystopian_arithmetic.py,pty,stderr"]
