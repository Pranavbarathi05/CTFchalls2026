FROM python:3.11-slim

WORKDIR /app

# Create non-root user
RUN useradd -m -u 1000 ctfuser

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .
COPY templates templates

RUN chown -R ctfuser:ctfuser /app

USER ctfuser

EXPOSE 8015

CMD ["python", "app.py"]
