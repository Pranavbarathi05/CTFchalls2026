#!/usr/bin/env python3
import sys

FLAG = "dscctf{m1c34l_sc0fi3ld_fr0m_pr1s0n_br34k}"

SAFE_BUILTINS = {
    # constants
    "True": True,
    "False": False,
    "None": None,

    # functions allowed
    "abs": abs,
    "bin": bin,
    "dir": dir,
    "help": help,
    "str": str,
    "int": int,
    "len": len,
    "print": print,
}

class Sandbox:
    def execute(self, code):
        exec(code, {"__builtins__": SAFE_BUILTINS, "FLAG": FLAG})
        sys.stdout.flush()

sandbox = Sandbox()

print("Find the flag.")
sys.stdout.flush()

while True:
    try:
        sys.stdout.write(">>> ")
        sys.stdout.flush()
        code = input()
        sandbox.execute(code)
    except Exception:
        print("You have encountered an error.")
        sys.stdout.flush()
