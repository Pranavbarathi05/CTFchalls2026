FROM python:3.9-slim

WORKDIR /app

COPY generate_menu.py /app/
COPY solve.py /app/
COPY flag.txt /app/
COPY server.py /app/

RUN python3 generate_menu.py

COPY encrypted_menu.txt /app/

EXPOSE 8001

CMD ["python3", "server.py"]