"""Narrow process-remediation policy; never executes a proposed command."""
import ast
import textwrap

# Only these non-interpreter operations can be introduced by a code proposal.
# Arbitrary command endpoints require an application-specific authorization design.
ALLOWED_PROGRAMS = {'ping', 'printf', 'echo', 'whoami', 'hostname'}


def safe_process_edit(text):
    try: tree = ast.parse(textwrap.dedent(text))
    except (SyntaxError, ValueError): return False
    calls = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and node.id == 'subprocess':
            # Checked below: every access must occur as subprocess.run(...).
            continue
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == 'subprocess':
            if node.attr != 'run': return False
            calls.append(node)
    if not calls: return False
    parents = {child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}
    for reference in calls:
        call = parents.get(reference)
        if not isinstance(call, ast.Call) or call.func is not reference or len(call.args) != 1: return False
        argv = call.args[0]
        if not isinstance(argv, (ast.List, ast.Tuple)) or not argv.elts: return False
        first = argv.elts[0]
        if not isinstance(first, ast.Constant) or first.value not in ALLOWED_PROGRAMS: return False
        if any(isinstance(x, ast.Starred) for x in argv.elts): return False
        kwargs = {k.arg: k.value for k in call.keywords}
        if None in kwargs or set(kwargs) - {'shell', 'timeout', 'check', 'capture_output', 'text'}: return False
        if not isinstance(kwargs.get('shell'), ast.Constant) or kwargs['shell'].value is not False: return False
        timeout = kwargs.get('timeout')
        if not isinstance(timeout, ast.Constant) or type(timeout.value) not in {int, float} or not 0 < timeout.value <= 60: return False
        if any(not isinstance(v, ast.Constant) for v in kwargs.values()): return False
    # Reject aliasing the module or function, even alongside an approved call.
    return all(isinstance(parents.get(n), ast.Attribute) and parents[n] in calls
               for n in ast.walk(tree) if isinstance(n, ast.Name) and n.id == 'subprocess')
