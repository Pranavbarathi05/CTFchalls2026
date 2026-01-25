FROM python:3.9-slim

WORKDIR /app

# Install socat for TCP handling
RUN apt-get update && \
    apt-get install -y socat && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

COPY regex_master.py /app/
COPY solve.py /app/
COPY flag.txt /app/

# Run as non-root user
RUN useradd -m -u 1000 ctfuser && \
    chown -R ctfuser:ctfuser /app

USER ctfuser

EXPOSE 8006

CMD ["socat", "TCP-LISTEN:8006,reuseaddr,fork", "EXEC:python3 -u regex_master.py,pty,stderr"]