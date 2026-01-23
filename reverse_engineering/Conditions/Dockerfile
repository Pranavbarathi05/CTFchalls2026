FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy challenge files
COPY . .

# For safety: don't run as root
RUN useradd -m ctfuser
USER ctfuser

EXPOSE 42552

# Run using gunicorn (production style)
CMD ["gunicorn", "-w", "2", "-b", "0.0.0.0:42552", "server:app"]
