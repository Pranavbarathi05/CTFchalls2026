FROM python:3.9-slim

WORKDIR /app

# Install socat for TCP handling
RUN apt-get update && \
    apt-get install -y socat && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

COPY tree_traversal.py /app/
COPY solve.py /app/
COPY flag.txt /app/

# Run as non-root user
RUN useradd -m -u 1000 ctfuser && \
    chown -R ctfuser:ctfuser /app

USER ctfuser

EXPOSE 8005

CMD ["socat", "TCP-LISTEN:8005,reuseaddr,fork", "EXEC:python3 -u tree_traversal.py,pty,stderr"]