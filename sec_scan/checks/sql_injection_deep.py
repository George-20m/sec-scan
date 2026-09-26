"""
sql_injection_deep.py — Python-only, tree-based taint tracking for SQL
injection. This is the upgrade over sql_injection.py's line-by-line
regex approach: instead of reading text, it parses the file into a
real syntax tree (via tree-sitter) and tracks which variables were
built unsafely, following that variable across lines within the same
function — which is exactly the gap the line-based check can't see:

    query = "SELECT ... " + username   # tainted here
    cursor.execute(query)               # caught here, two lines later

LIMITATIONS (same honesty policy as the line-based check):
  - Python only. Other languages still rely on sql_injection.py.
  - Taint tracking stays within one function — it does not follow a
    value if it's passed as an argument into another function.
  - If a tainted variable is reassigned safely, taint is cleared —
    but only for simple `name = ...` reassignment, not more complex
    patterns (tuple unpacking, augmented assignment with +=, etc.).
"""

import re
import tree_sitter_python as tspython
from tree_sitter import Language, Parser

EXTENSIONS = {".py"}

_PY_LANGUAGE = Language(tspython.language())
_parser = Parser(_PY_LANGUAGE)

SINK_NAMES = {"execute", "executemany", "query", "raw"}
SAFE_PLACEHOLDER = re.compile(r'\?|%s|@\w+|:\w+')


def _node_text(node, source):
    return source[node.start_byte:node.end_byte]


def _is_unsafe_string(node):
    # An f-string counts as unsafe if it actually interpolates a value.
    if node.type == "string":
        return any(c.type == "interpolation" for c in node.children)
    return False


def _contains_concat(node):
    # Walks a binary_operator chain looking for a '+' anywhere in it.
    if node.type == "binary_operator":
        for c in node.children:
            if c.type == "+":
                return True
        return any(_contains_concat(c) for c in node.children)
    return False


def _expr_is_unsafe(node):
    if node.type == "string":
        return _is_unsafe_string(node)
    if node.type == "binary_operator":
        return _contains_concat(node)
    return False


def _get_call_name(call_node):
    func = call_node.child_by_field_name("function")
    if func is None:
        return None
    if func.type == "attribute":
        attr = func.child_by_field_name("attribute")
        return attr.text.decode() if attr else None
    if func.type == "identifier":
        return func.text.decode()
    return None


def _build_finding(file_path, call_node, source, arg_src, tracked):
    row = call_node.start_point[0] + 1
    line_text = source.splitlines()[call_node.start_point[0]].decode(errors="ignore")
    if tracked:
        message = (
            f"Variable '{arg_src}' was built from unsafe string "
            f"concatenation/interpolation earlier, then passed into a "
            f"SQL execution call."
        )
    else:
        message = "Query built via unsafe string concatenation/interpolation directly in this call."
    return {
        "check_id": "SQL-INJECTION-DEEP",
        "severity": "HIGH",
        "file": file_path,
        "line": row,
        "message": message,
        "snippet": line_text.strip(),
    }


def _check_call(call_node, tainted, source, file_path, findings):
    name = _get_call_name(call_node)
    if not name or name.lower() not in SINK_NAMES:
        return

    args_node = call_node.child_by_field_name("arguments")
    if not args_node:
        return

    for arg in args_node.children:
        if arg.type in ("(", ")", ","):
            continue

        arg_src = _node_text(arg, source).decode(errors="ignore")
        if SAFE_PLACEHOLDER.search(arg_src):
            continue

        if arg.type == "identifier" and arg_src in tainted:
            findings.append(_build_finding(file_path, call_node, source, arg_src, True))
        elif _expr_is_unsafe(arg):
            findings.append(_build_finding(file_path, call_node, source, arg_src, False))


def _scan_scope(func_node, source, file_path, findings):
    # tainted = names of variables currently known to hold an unsafely
    # built string, within THIS function's scope only.
    tainted = set()

    def walk(node):
        # Nested function = new scope, tracked separately.
        if node.type == "function_definition" and node is not func_node:
            _scan_scope(node, source, file_path, findings)
            return

        if node.type == "assignment":
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            if left is not None and right is not None and left.type == "identifier":
                name = _node_text(left, source).decode()
                if _expr_is_unsafe(right):
                    tainted.add(name)
                else:
                    # Reassigned to something safe — taint no longer applies.
                    tainted.discard(name)

        if node.type == "call":
            _check_call(node, tainted, source, file_path, findings)

        for child in node.children:
            walk(child)

    walk(func_node)


def run(file_path, content):
    source = content.encode()
    tree = _parser.parse(source)
    findings = []
    _scan_scope(tree.root_node, source, file_path, findings)
    return findings