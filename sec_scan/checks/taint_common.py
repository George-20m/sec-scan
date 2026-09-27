"""
taint_common.py - shared taint-tracking engine used by every
language-specific deep SQL injection check (sql_injection_deep_*.py).

v2 additions over the original:
  - format_call_names: recognizes format-string calls (String.format,
    fmt.Sprintf) as an unsafe-construction pattern, not just
    concatenation/interpolation.
  - get_function_name / get_function_params: enables single-file,
    one-level-deep cross-function taint tracking. If a tainted
    variable is passed into a function defined elsewhere in the SAME
    file, that function's matching parameter is treated as tainted
    for that call, and its body is analyzed too. This does NOT
    follow taint across files, through recursion cycles, or through
    callbacks/higher-order functions - those remain out of scope.
    It also does NOT track a helper function's RETURN value - if a
    helper builds and returns a tainted string, the caller executing
    that return value is not caught. Only "pass taint in, callee
    executes it directly" is covered, not "callee returns taint,
    caller executes it."
"""

from dataclasses import dataclass, field


@dataclass
class LanguageConfig:
    scope_types: set
    assign_types: set
    identifier_types: set
    binary_types: set
    concat_ops: set
    string_types: set
    interpolation_types: set
    call_types: set
    sink_names: set
    get_call_name: callable
    get_call_args: callable
    format_call_names: set = field(default_factory=set)
    get_function_name: callable = None
    get_function_params: callable = None


def node_text(node, source):
    return source[node.start_byte:node.end_byte]


def unwrap_single(node):
    if node is not None and node.type == "expression_list" and node.child_count == 1:
        return node.children[0]
    return node


def get_assign_parts(node):
    left = node.child_by_field_name("left") or node.child_by_field_name("name")
    right = node.child_by_field_name("right") or node.child_by_field_name("value")
    if left is not None and right is not None:
        return unwrap_single(left), unwrap_single(right)

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


def is_format_call(node, cfg):
    if not cfg.format_call_names or node.type not in cfg.call_types:
        return False
    name = cfg.get_call_name(node)
    if not name or name.lower() not in cfg.format_call_names:
        return False
    args = cfg.get_call_args(node)
    return len(args) > 1  # format string + at least one substitution


def expr_is_unsafe(node, cfg):
    if node is None:
        return False
    if node.type in cfg.string_types:
        return is_interpolated_string(node, cfg)
    if node.type in cfg.binary_types:
        return contains_concat(node, cfg)
    if node.type in cfg.call_types:
        return is_format_call(node, cfg)
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


def collect_local_functions(root_node, cfg):
    """Maps function name -> (param_names, body_node) for every
    scope in the file, so calls to them can be followed one level
    deep. Returns {} if the language config doesn't support this
    (get_function_name is None)."""
    registry = {}
    if cfg.get_function_name is None:
        return registry

    def walk(node):
        if node.type in cfg.scope_types:
            name = cfg.get_function_name(node)
            if name:
                params = cfg.get_function_params(node) if cfg.get_function_params else []
                registry[name] = (params, node)
        for c in node.children:
            walk(c)

    walk(root_node)
    return registry


def scan_scope(func_node, source, file_path, findings, cfg,
               local_functions=None, seed_tainted=None, visiting=None):
    tainted = set(seed_tainted) if seed_tainted else set()
    if visiting is None:
        visiting = set()

    def walk(node):
        if node.type in cfg.scope_types and node is not func_node:
            scan_scope(node, source, file_path, findings, cfg, local_functions, None, visiting)
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

            # Cross-function propagation: if this call passes a
            # tainted (or directly unsafe) value into a function
            # defined elsewhere in this same file, analyze that
            # function's body with the matching parameter seeded as
            # tainted too.
            if local_functions:
                name = cfg.get_call_name(node)
                if name and name in local_functions and name not in visiting:
                    params, body = local_functions[name]
                    call_args = cfg.get_call_args(node)
                    seed = set()
                    for i, arg in enumerate(call_args):
                        if i >= len(params):
                            break
                        arg_src = node_text(arg, source).decode(errors="ignore")
                        is_tainted_arg = (arg.type in cfg.identifier_types and arg_src in tainted)
                        if is_tainted_arg or expr_is_unsafe(arg, cfg):
                            seed.add(params[i])
                    if seed:
                        visiting.add(name)
                        scan_scope(body, source, file_path, findings, cfg,
                                   local_functions, seed, visiting)
                        visiting.discard(name)

        for child in node.children:
            walk(child)

    walk(func_node)


def run_taint_check(parser, source, file_path, cfg):
    tree = parser.parse(source)
    findings = []
    local_functions = collect_local_functions(tree.root_node, cfg)
    scan_scope(tree.root_node, source, file_path, findings, cfg, local_functions)
    return findings