"""
taint_common.py - shared taint-tracking engine used by every
language-specific deep SQL injection check (sql_injection_deep_*.py).

v2 additions:
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

v3 additions:
  - is_unqualified_call: gates cross-function propagation to calls
    that are genuinely bare (no receiver/object), so a call like
    obj.query(x) can no longer be mistaken for a same-named local
    function query(x) just because get_call_name() returns "query"
    for both. If a language config doesn't set this, propagation
    behaves as before (no gating).
  - Simple identifier-to-identifier alias tracking: if `a = b` and
    `b` is already a tainted plain identifier, `a` becomes tainted
    too. This is intentionally narrow - it does not cover object
    properties, array/index access, or anything routed through a
    function call or return value.
  - format_min_args: minimum argument count for a format-style call
    to count as unsafe. Defaults to 2 (format string + >=1
    substitution), matching the original String.format/Sprintf
    behavior where the format string is itself a positional
    argument. Languages where the format string is the receiver
    instead of an argument (Python's "...".format(x)) set this to 1.
"""

from dataclasses import dataclass, field
import re


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
    format_min_args: int = 2
    get_function_name: callable = None
    get_function_params: callable = None
    is_unqualified_call: callable = None
    source_patterns: tuple = ()
    property_patterns: tuple = ()
    return_types: set = field(default_factory=set)
    branch_types: set = field(default_factory=set)


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
    return len(args) >= cfg.format_min_args


def is_source(node, source, cfg):
    text = node_text(node, source).decode(errors="ignore")
    return any(re.search(pattern, text) for pattern in cfg.source_patterns)


def track_key(node, source, cfg):
    """Return a stable name for a local variable or a simple instance field."""
    if node is None:
        return None
    text = node_text(node, source).decode(errors="ignore")
    if node.type in cfg.identifier_types:
        return text
    if any(re.fullmatch(pattern, text) for pattern in cfg.property_patterns):
        return text
    return None


def expr_is_construction(node, cfg):
    if node is None:
        return False
    if node.type in cfg.string_types:
        return is_interpolated_string(node, cfg)
    if node.type in cfg.binary_types:
        return contains_concat(node, cfg)
    if node.type in cfg.call_types:
        return is_format_call(node, cfg)
    return False


def expr_is_untrusted(node, untrusted, source, cfg):
    """Whether an expression contains external input or a value derived from it."""
    if node is None:
        return False
    key = track_key(node, source, cfg)
    if key is not None and key in untrusted:
        return True
    if is_source(node, source, cfg):
        return True
    return any(expr_is_untrusted(child, untrusted, source, cfg)
               for child in node.children)


def expr_is_unsafe_sql(node, untrusted, source, cfg):
    return (expr_is_construction(node, cfg)
            and expr_is_untrusted(node, untrusted, source, cfg))


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


def check_call(call_node, unsafe_sql, untrusted, source, file_path, findings, cfg):
    name = cfg.get_call_name(call_node)
    if not name or name.lower() not in cfg.sink_names:
        return

    # All currently supported SQL APIs take the query text as their first
    # argument. Later arguments are parameter values, never executable SQL.
    for arg in cfg.get_call_args(call_node)[:1]:
        arg_src = node_text(arg, source).decode(errors="ignore")

        key = track_key(arg, source, cfg)
        if key is not None and key in unsafe_sql:
            findings.append(build_finding(file_path, call_node, source, arg_src, True))
        elif expr_is_unsafe_sql(arg, untrusted, source, cfg):
            findings.append(build_finding(file_path, call_node, source, arg_src, False))
        elif expr_is_untrusted(arg, untrusted, source, cfg):
            findings.append(build_finding(file_path, call_node, source, arg_src, True))


def _return_parameter_indexes(func_node, source, cfg):
    """Return parameter positions that can build SQL returned by this function."""
    if not cfg.return_types or not cfg.get_function_params:
        return set()
    params = cfg.get_function_params(func_node)
    indexes = set()
    origins = {param: {param} for param in params}
    unsafe_origins = {}

    def expression_origins(node):
        key = track_key(node, source, cfg)
        if key is not None and key in origins:
            return origins[key]
        result = set()
        for child in node.children:
            result.update(expression_origins(child))
        return result

    def walk(node, in_branch=False):
        if node.type in cfg.scope_types and node is not func_node:
            return
        if node.type in cfg.assign_types:
            left, right = get_assign_parts(node)
            key = track_key(left, source, cfg)
            if key is not None and right is not None:
                value_origins = expression_origins(right)
                if value_origins:
                    origins[key] = value_origins
                elif not in_branch:
                    origins.pop(key, None)
                if expr_is_construction(right, cfg) and value_origins:
                    unsafe_origins[key] = value_origins
                elif not in_branch:
                    unsafe_origins.pop(key, None)
        if node.type in cfg.return_types:
            values = node.named_children
            if values:
                value = values[0]
                key = track_key(value, source, cfg)
                value_origins = unsafe_origins.get(key, set()) if key else set()
                if expr_is_construction(value, cfg):
                    value_origins = expression_origins(value)
                for index, param in enumerate(params):
                    if param in value_origins:
                        indexes.add(index)
        for child in node.children:
            walk(child, in_branch or node.type in cfg.branch_types)

    walk(func_node)
    return indexes


def collect_local_functions(root_node, source, cfg):
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
                registry[name] = (params, node,
                                  _return_parameter_indexes(node, source, cfg))
        for c in node.children:
            walk(c)

    walk(root_node)
    return registry


def scan_scope(func_node, source, file_path, findings, cfg,
               local_functions=None, seed_untrusted=None,
               seed_unsafe_sql=None, visiting=None):
    untrusted = set(seed_untrusted) if seed_untrusted else set()
    unsafe_sql = set(seed_unsafe_sql) if seed_unsafe_sql else set()
    if visiting is None:
        visiting = set()

    def walk(node, in_branch=False):
        if node.type in cfg.scope_types and node is not func_node:
            scan_scope(node, source, file_path, findings, cfg, local_functions,
                       None, None, visiting)
            return

        if node.type in cfg.assign_types:
            left, right = get_assign_parts(node)
            name = track_key(left, source, cfg)
            if name is not None and right is not None:
                returns_unsafe = False
                if right.type in cfg.call_types and local_functions:
                    call_name = cfg.get_call_name(right)
                    is_bare = (cfg.is_unqualified_call is None
                               or cfg.is_unqualified_call(right))
                    if call_name and is_bare and call_name in local_functions:
                        _, _, return_indexes = local_functions[call_name]
                        call_args = cfg.get_call_args(right)
                        returns_unsafe = any(
                            index < len(call_args)
                            and expr_is_untrusted(call_args[index], untrusted, source, cfg)
                            for index in return_indexes
                        )

                if returns_unsafe or expr_is_unsafe_sql(right, untrusted, source, cfg):
                    unsafe_sql.add(name)
                elif not in_branch:
                    unsafe_sql.discard(name)

                if expr_is_untrusted(right, untrusted, source, cfg):
                    untrusted.add(name)
                elif not in_branch:
                    untrusted.discard(name)

        if node.type in cfg.call_types:
            check_call(node, unsafe_sql, untrusted, source, file_path, findings, cfg)

            # Cross-function propagation: if this call passes a
            # tainted (or directly unsafe) value into a function
            # defined elsewhere in this same file, analyze that
            # function's body with the matching parameter seeded as
            # tainted too. Gated by is_unqualified_call so a
            # receiver-qualified call (obj.query(x)) can't be
            # mistaken for a same-named local function.
            if local_functions:
                name = cfg.get_call_name(node)
                is_bare = cfg.is_unqualified_call is None or cfg.is_unqualified_call(node)
                if name and is_bare and name in local_functions and name not in visiting:
                    params, body, _ = local_functions[name]
                    call_args = cfg.get_call_args(node)
                    seed_untrusted_params = set()
                    seed_unsafe_params = set()
                    for i, arg in enumerate(call_args):
                        if i >= len(params):
                            break
                        arg_src = node_text(arg, source).decode(errors="ignore")
                        key = track_key(arg, source, cfg)
                        if key is not None and key in unsafe_sql:
                            seed_unsafe_params.add(params[i])
                        if (expr_is_untrusted(arg, untrusted, source, cfg)
                                or expr_is_unsafe_sql(arg, untrusted, source, cfg)):
                            seed_untrusted_params.add(params[i])
                    if seed_untrusted_params or seed_unsafe_params:
                        visiting.add(name)
                        scan_scope(body, source, file_path, findings, cfg,
                                   local_functions, seed_untrusted_params,
                                   seed_unsafe_params, visiting)
                        visiting.discard(name)

        for child in node.children:
            walk(child, in_branch or node.type in cfg.branch_types)

    walk(func_node)


def run_taint_check(parser, source, file_path, cfg):
    tree = parser.parse(source)
    findings = []
    local_functions = collect_local_functions(tree.root_node, source, cfg)
    scan_scope(tree.root_node, source, file_path, findings, cfg, local_functions)
    return findings
