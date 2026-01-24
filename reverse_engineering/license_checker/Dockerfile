FROM gcc:9

WORKDIR /app

RUN apt-get update && apt-get install -y netcat && rm -rf /var/lib/apt/lists/*

COPY license_checker.c /app/
COPY solve.py /app/
COPY flag.txt /app/
COPY start.sh /app/

RUN gcc -o license_checker license_checker.c && chmod +x start.sh

EXPOSE 8002

CMD ["./start.sh"]