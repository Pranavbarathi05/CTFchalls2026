FROM python:3.11-slim

WORKDIR /app

# Install socat for TCP handling
RUN apt-get update && \
    apt-get install -y socat && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

COPY challenge.py .
COPY namo.txt .

# Run as non-root user
RUN useradd -m -u 1000 ctfuser && \
    chown -R ctfuser:ctfuser /app

USER ctfuser

CMD ["python3", "-u", "challenge.py"]
