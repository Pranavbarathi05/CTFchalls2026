FROM python:3.9-slim

WORKDIR /app

COPY pathfinding.py /app/
COPY solve.py /app/
COPY flag.txt /app/

EXPOSE 8004

CMD ["python3", "pathfinding.py", "interactive"]