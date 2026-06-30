"""Sample generated code — improper input validation leading to code execution (CWE-20)."""


def compute(expr):
    # Vulnerable: unvalidated request input passed straight to eval().
    return eval(expr)
