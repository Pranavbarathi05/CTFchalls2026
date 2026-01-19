FROM python:3.9-slim

WORKDIR /app

COPY tree_traversal.py /app/
COPY solve.py /app/
COPY flag.txt /app/

EXPOSE 8005

CMD ["python3", "tree_traversal.py"]