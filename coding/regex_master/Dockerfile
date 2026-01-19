FROM python:3.9-slim

WORKDIR /app

COPY regex_master.py /app/
COPY solve.py /app/
COPY flag.txt /app/

EXPOSE 8006

CMD ["python3", "regex_master.py"]