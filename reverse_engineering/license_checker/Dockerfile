FROM gcc:9

WORKDIR /app

COPY license_checker.c /app/
COPY solve.py /app/
COPY flag.txt /app/

RUN gcc -o license_checker license_checker.c

EXPOSE 8002

CMD ["./license_checker"]