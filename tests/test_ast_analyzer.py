"""Tests for the Tree-sitter AST CWE detector."""
from __future__ import annotations

from adf.layer2_ast_cwe.ast_analyzer import ASTAnalyzer

analyzer = ASTAnalyzer()


def cwes(code: str) -> set[str]:
    return {f.cwe_id for f in analyzer.analyze(code)}


def test_sql_injection_via_concatenation():
    code = 'cursor.execute("SELECT * FROM users WHERE name = \'" + name + "\'")'
    assert "CWE-89" in cwes(code)


def test_sql_injection_via_fstring():
    code = 'db.execute(f"SELECT * FROM users WHERE id = {user_id}")'
    assert "CWE-89" in cwes(code)


def test_sql_injection_via_tainted_variable():
    code = (
        'query = "SELECT * FROM users WHERE n = \'" + name + "\'"\n'
        "cursor.execute(query)\n"
    )
    assert "CWE-89" in cwes(code)


def test_parameterised_query_is_safe():
    code = 'cursor.execute("SELECT * FROM users WHERE name = ?", (name,))'
    assert "CWE-89" not in cwes(code)


def test_code_injection_eval():
    assert "CWE-94" in cwes("result = eval(user_supplied)")


def test_command_injection_os_system():
    assert "CWE-78" in cwes('os.system("ping " + host)')


def test_xss_unescaped_render():
    code = 'return render_template_string("<h1>" + username + "</h1>")'
    assert "CWE-79" in cwes(code)


def test_hardcoded_password_assignment():
    assert "CWE-798" in cwes('password = "hunter2pass"')


def test_hardcoded_secret_kwarg():
    assert "CWE-798" in cwes('connect(host="db", api_key="sk-livesecret123")')


def test_improper_input_validation():
    code = "value = int(request.args.get('n'))"
    assert "CWE-20" in cwes(code)


def test_clean_code_has_no_findings():
    code = "def add(a, b):\n    return a + b\n"
    assert cwes(code) == set()


def test_findings_carry_line_numbers():
    code = "x = 1\npassword = 'realsecret123'\n"
    findings = analyzer.analyze(code)
    cred = [f for f in findings if f.cwe_id == "CWE-798"]
    assert cred and cred[0].line == 2
