# Build stage
FROM gcc:9 AS builder

WORKDIR /build
COPY license_checker.c /build/
RUN gcc -o license_checker license_checker.c

# Runtime stage
FROM debian:bullseye-slim

RUN apt-get update && apt-get install -y socat && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -u 1000 ctfuser

WORKDIR /app

# Copy compiled binary from builder stage
COPY --from=builder /build/license_checker /app/
COPY flag.txt /app/
COPY start.sh /app/

RUN chmod +x start.sh && \
    chown -R ctfuser:ctfuser /app

USER ctfuser

EXPOSE 8002

CMD ["./start.sh"]