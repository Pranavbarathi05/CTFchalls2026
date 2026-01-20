#!/usr/bin/env python3
import random
import time

FLAG = "DSCCTF{truth_1s_0nly_4_m4tt3r_0f_c0ns3nsus_2026}"
TIMEOUT = 7  # seconds per question
ROUNDS = 5

def transform(n):
    """
    The Truth Engine.
    Rule (hidden):
    - If the result contains an even number of set bits → +1
    - Else → -1
    """
    return n + 1 if bin(n).count("1") % 2 == 0 else n - 1


def main():
    print("=== Ministry of Truth Arithmetic Terminal ===\n")
    print("In our society, truth is not discovered.")
    print("It is declared.\n")

    print("For example, we declare that:")
    print("2 + 2 = 5\n")

    print("Do you accept this truth? (yes/no)")
    answer = input("> ").strip().lower()
    if answer != "yes":
        print("\nDissent detected. Session terminated.")
        return

    print("\nGood.")
    print("You will now be tested.")
    print(f"{ROUNDS} questions. {TIMEOUT} seconds each.")
    print("Answer according to the declared truth.\n")

    for i in range(1, ROUNDS + 1):
        a = random.randint(1, 10)
        b = random.randint(1, 10)
        op = random.choice(["+", "-", "*"])

        expr = f"{a} {op} {b}"
        real = eval(expr)
        expected = transform(real)

        print(f"[{i}/{ROUNDS}] What is {expr}?")
        start = time.time()

        try:
            user = input("> ").strip()
            if time.time() - start > TIMEOUT:
                print("\nToo slow. Truth waits for no one.")
                return

            if int(user) != expected:
                print("\nIncorrect. You are thinking objectively.")
                return

            print("Accepted.\n")
        except Exception:
            print("\nInvalid response.")
            return

    print("=== TEST COMPLETE ===")
    print("You have aligned with the truth.")
    print("\nFLAG:")
    print(FLAG)


if __name__ == "__main__":
    main()
