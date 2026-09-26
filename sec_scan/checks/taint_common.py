"""
taint_common.py - shared taint-tracking engine used by every
language-specific deep SQL injection check (sql_injection_deep_*.py).

Each language file only supplies a LanguageConfig describing how ITS
grammar spells out "assignment", "string concatenation", "string
interpolation", and "a call to a sink function" - the actual
algorithm (track tainted variables per function scope, follow them
to a sink) lives here once, instead of being copy-pasted per file.
"""

from dataclasses import dataclass


@dataclass
class LanguageConfig:
    scope_types: set          # node types that start a new taint scope (functions/methods)
    assign_types: set         # node types representing "name = value"
    identifier_types: set     # node types that count as a plain variable name
    binary_types: set         # node types representing a binary operation
    concat_ops: set           # token types, within a binary node, that mean concatenation
    string_types: set         # node types representing a string literal
    interpolation_types: set  # child node types inside a string that mean "interpolated"
    call_types: set           # node types representing a call (or call-like sink, e.g. `new SqlCommand(...)`)
    sink_names: set           # lowercase function/method names that execute SQL
    get_call_name: callable   # (call_node) -> str or None
    get_call_args: callable   # (call_node) -> list of argument expression nodes


def node_text(node, source):
    return source[node.start_byte:node.end_byte]


def unwrap_single(node):
    # Some grammars wrap a single value in a list node (e.g. Go's
    # `expression_list` for `x := y`). If it only holds one child,
    # unwrap to that child so the rest of the logic sees the real value.
    if node is not None and node.type == "expression_list" and node.child_count == 1:
        return node.children[0]
    return node


def get_assign_parts(node):
    left = node.child_by_field_name("left") or node.child_by_field_name("name")
    right = node.child_by_field_name("right") or node.child_by_field_name("value")
    if left is not None and right is not None:
        return unwrap_single(left), unwrap_single(right)

    # Positional fallback for grammars that don't expose named fields
    # for this node (e.g. C#'s variable_declarator): find the '=' or
    # ':=' token and take what's directly before/after it.
    children = node.children
    for i, c in enumerate(children):
        if c.type in ("=", ":="):
            name_node = children[0] if i > 0 else None
            value_node = children[i + 1] if i + 1 < len(children) else None
            return unwrap_single(name_node), unwrap_single(value_node)
    return None, None


def contains_concat(node, cfg):
    if node.type in cfg.binary_types:
        for c in node.children:
            if c.type in cfg.concat_ops:
                return True
        return any(contains_concat(c, cfg) for c in node.children)
    return False


def is_interpolated_string(node, cfg):
    if node.type in cfg.string_types:
        return any(c.type in cfg.interpolation_types for c in node.children)
    return False


def expr_is_unsafe(node, cfg):
    if node is None:
        return False
    if node.type in cfg.string_types:
        return is_interpolated_string(node, cfg)
    if node.type in cfg.binary_types:
        return contains_concat(node, cfg)
    return False


def build_finding(file_path, call_node, source, arg_src, tracked):
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


def check_call(call_node, tainted, source, file_path, findings, cfg):
    name = cfg.get_call_name(call_node)
    if not name or name.lower() not in cfg.sink_names:
        return

    for arg in cfg.get_call_args(call_node):
        arg_src = node_text(arg, source).decode(errors="ignore")

        if arg.type in cfg.identifier_types and arg_src in tainted:
            findings.append(build_finding(file_path, call_node, source, arg_src, True))
        elif expr_is_unsafe(arg, cfg):
            findings.append(build_finding(file_path, call_node, source, arg_src, False))


def scan_scope(func_node, source, file_path, findings, cfg):
    tainted = set()

    def walk(node):
        if node.type in cfg.scope_types and node is not func_node:
            scan_scope(node, source, file_path, findings, cfg)
            return

        if node.type in cfg.assign_types:
            left, right = get_assign_parts(node)
            if left is not None and right is not None and left.type in cfg.identifier_types:
                name = node_text(left, source).decode(errors="ignore")
                if expr_is_unsafe(right, cfg):
                    tainted.add(name)
                else:
                    tainted.discard(name)

        if node.type in cfg.call_types:
            check_call(node, tainted, source, file_path, findings, cfg)

        for child in node.children:
            walk(child)

    walk(func_node)


def run_taint_check(parser, source, file_path, cfg):
    tree = parser.parse(source)
    findings = []
    scan_scope(tree.root_node, source, file_path, findings, cfg)
    return findings