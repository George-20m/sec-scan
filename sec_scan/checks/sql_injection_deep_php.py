"""
sql_injection_deep_php.py - PHP deep SQL injection check.

Note: call_types here is member_call_expression only (e.g.
$pdo->query(...)), which is always receiver-qualified. That means
cross-function local-helper tracking has no unambiguous "bare call"
path to use for this language as currently scoped, so
is_unqualified_call always returns False here, disabling that
propagation for PHP rather than leaving it matching on ambiguous
receiver-qualified calls. Supporting bare function_call_expression
calls would be a separate addition (add it to call_types, teach
_get_call_name/_get_call_args to handle it).
"""

import tree_sitter_php as ts_php
from tree_sitter import Language, Parser

from .taint_common import LanguageConfig, run_taint_check

EXTENSIONS = {".php"}

_PARSER = Parser(Language(ts_php.language_php()))


def _get_call_name(call_node):
    if call_node.type != "member_call_expression":
        return None
    name = call_node.child_by_field_name("name")
    return name.text.decode() if name else None


def _get_call_args(call_node):
    args = call_node.child_by_field_name("arguments")
    if args is None:
        return []
    out = []
    for c in args.children:
        if c.type == "argument" and c.children:
            out.append(c.children[0])
    return out


def _get_function_name(func_node):
    name = func_node.child_by_field_name("name")
    return name.text.decode() if name else None


def _get_function_params(func_node):
    params_node = func_node.child_by_field_name("parameters")
    if params_node is None:
        return []
    out = []
    for c in params_node.children:
        if c.type == "simple_parameter":
            n = c.child_by_field_name("name")
            if n:
                out.append(n.text.decode())
    return out


def _is_unqualified_call(call_node):
    return False


CONFIG = LanguageConfig(
    scope_types={"function_definition", "method_declaration"},
    assign_types={"assignment_expression"},
    identifier_types={"variable_name"},
    binary_types={"binary_expression"},
    concat_ops={"."},
    string_types={"encapsed_string"},
    interpolation_types={"variable_name"},
    call_types={"member_call_expression"},
    sink_names={"query", "exec", "prepare"},
    get_call_name=_get_call_name,
    get_call_args=_get_call_args,
    get_function_name=_get_function_name,
    get_function_params=_get_function_params,
    is_unqualified_call=_is_unqualified_call,
    source_patterns=(r"\$_(?:GET|POST|REQUEST|COOKIE)\b",),
    property_patterns=(r"\$this->\w+",),
    return_types={"return_statement"},
    branch_types={"if_statement", "for_statement", "while_statement", "try_statement"},
)


def run(file_path, content):
    source = content.encode()
    return run_taint_check(_PARSER, source, file_path, CONFIG)
