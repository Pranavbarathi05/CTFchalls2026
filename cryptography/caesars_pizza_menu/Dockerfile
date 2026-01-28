FROM python:3.9-slim

WORKDIR /app

# Create non-root user
RUN useradd -m -u 1000 ctfuser

COPY generate_menu.py /app/
COPY flag.txt /app/
COPY server.py /app/

# Generate menu during build
RUN python3 generate_menu.py

RUN chown -R ctfuser:ctfuser /app

USER ctfuser

EXPOSE 8001

CMD ["python3", "server.py"]