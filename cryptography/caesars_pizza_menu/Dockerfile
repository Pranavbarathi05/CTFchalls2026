FROM python:3.9-slim

WORKDIR /app

COPY generate_menu.py /app/
COPY solve.py /app/
COPY flag.txt /app/

RUN python3 generate_menu.py

COPY encrypted_menu.txt /app/

EXPOSE 8001

CMD ["python3", "-c", "print('=== Caesar\\'s Pizza Menu Challenge ==='); print(); print('Welcome to Caesar\\'s Pizza Palace!'); print('We have an encrypted menu that contains our secret VIP item.'); print('Can you decrypt it to find the flag?'); print(); exec(open('encrypted_menu.txt').read()); print(); print('Hint: Caesar liked to shift letters in his messages...'); print('The encrypted menu is in the file: encrypted_menu.txt')"]