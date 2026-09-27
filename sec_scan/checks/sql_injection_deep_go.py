"""
sql_injection_deep_go.py - Go deep SQL injection check.
No native string interpolation, so concatenation and fmt.Sprintf(...)
calls are the two unsafe-construction patterns tracked here. %s is
deliberately NOT a "safe placeholder" here - it's Sprintf's format
specifier, not a real SQL placeholder.
"""

import tree_sitter_go as ts_go
from tree_sitter import Language, Parser

from .taint_common import LanguageConfig, run_taint_check

EXTENSIONS = {".go"}

_PARSER = Parser(Language(ts_go.language()))


def _get_call_name(call_node):
    fn = call_node.child_by_field_name("function")
    if fn is None:
        return None
    if fn.type == "selector_expression":
        field = fn.child_by_field_name("field")
        return field.text.decode() if field else None
    if fn.type == "identifier":
        return fn.text.decode()
    return None


def _get_call_args(call_node):
    args = call_node.child_by_field_name("arguments")
    if args is None:
        return []
    return [c for c in args.children if c.type not in ("(", ")", ",")]


def _get_function_name(func_node):
    name = func_node.child_by_field_name("name")
    return name.text.decode() if name else None


def _get_function_params(func_node):
    params_node = func_node.child_by_field_name("parameters")
    if params_node is None:
        return []
    out = []
    for c in params_node.children:
        if c.type == "parameter_declaration":
            n = c.child_by_field_name("name")
            if n:
                out.append(n.text.decode())
    return out


CONFIG = LanguageConfig(
    scope_types={"function_declaration", "method_declaration"},
    assign_types={"short_var_declaration", "assignment_statement"},
    identifier_types={"identifier"},
    binary_types={"binary_expression"},
    concat_ops={"+"},
    string_types=set(),
    interpolation_types=set(),
    call_types={"call_expression"},
    sink_names={"query", "exec", "queryrow"},
    get_call_name=_get_call_name,
    get_call_args=_get_call_args,
    format_call_names={"sprintf"},
    get_function_name=_get_function_name,
    get_function_params=_get_function_params,
)


def run(file_path, content):
    source = content.encode()
    return run_taint_check(_PARSER, source, file_path, CONFIG)