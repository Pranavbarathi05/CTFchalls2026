#!/usr/bin/env python3

import sys

# Preserve print function before it gets deleted
_real_print = print

def flag_function():
    """Hidden flag function"""
    flag = "dscctf{m1c34l_sc0fi3ld_fr0m_pr1s0n_br34k}"
    return flag

class Sandbox(object):
    def execute(self, code_string):
        # Create restricted globals with access to our flag
        restricted_globals = {
            '__builtins__': {
                'ArithmeticError': ArithmeticError,
                'AssertionError': AssertionError, 
                'AttributeError': AttributeError,
                'Exception': Exception,
                'False': False,
                'None': None,
                'True': True,
                'basestring': str,
                'bytearray': bytearray,
                'bytes': bytes,
                'complex': complex,
                'dict': dict,
                'str': str,
                'abs': abs,
                'bin': bin,
                'dir': dir,
                'help': help,
                'len': len,
                'range': range
            },
            # Add the flag function to the restricted environment
            'FLAG_HOLDER': flag_function,
            'flag_function': flag_function
        }
        
        # Capture output and ensure it gets printed
        import io
        from contextlib import redirect_stdout
        
        output_capture = io.StringIO()
        try:
            with redirect_stdout(output_capture):
                result = eval(code_string, restricted_globals)
                if result is not None:
                    _real_print(repr(result))
        except:
            try:
                exec(code_string, restricted_globals)
            except Exception as e:
                _real_print(f"Error: {e}")
        
        # Print any captured output
        output = output_capture.getvalue()
        if output.strip():
            _real_print(output.strip())
        
        sys.stdout.flush()

sandbox = Sandbox()

# Python 3 compatible input
try:
    _input = raw_input  # Python 2
except NameError:
    _input = input      # Python 3

_real_print("???? Welcome to Prison Break!")
_real_print("Find the flag hidden in the global scope...")
_real_print("Type 'help()' if you get stuck.")
_real_print("")
sys.stdout.flush()

# Add flag to global scope for discovery
FLAG_HOLDER = flag_function

while True:
    try:
        sys.stdout.write(">>> ")
        sys.stdout.flush()
        code = _input()
        if code.strip() in ['quit', 'exit']:
            _real_print("Goodbye!")
            break
        sandbox.execute(code)

    except EOFError:
        _real_print("\nConnection closed.")
        break
    except Exception as e:
        _real_print("You have encountered an error.")
        sys.stdout.flush()
