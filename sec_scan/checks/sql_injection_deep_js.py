"""
sql_injection_deep_js.py - JS/TS deep SQL injection check.
"""

import tree_sitter_javascript as ts_js
import tree_sitter_typescript as ts_ts
from tree_sitter import Language, Parser

from .taint_common import LanguageConfig, run_taint_check

EXTENSIONS = {".js", ".ts"}

_JS_PARSER = Parser(Language(ts_js.language()))
_TS_PARSER = Parser(Language(ts_ts.language_typescript()))


def _get_call_name(call_node):
    fn = call_node.child_by_field_name("function")
    if fn is None:
        return None
    if fn.type == "member_expression":
        prop = fn.child_by_field_name("property")
        return prop.text.decode() if prop else None
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
    return [c.text.decode() for c in params_node.children if c.type == "identifier"]


CONFIG = LanguageConfig(
    scope_types={"function_declaration", "method_definition", "function_expression", "arrow_function"},
    assign_types={"variable_declarator", "assignment_expression"},
    identifier_types={"identifier"},
    binary_types={"binary_expression"},
    concat_ops={"+"},
    string_types={"template_string"},
    interpolation_types={"template_substitution"},
    call_types={"call_expression"},
    sink_names={"query", "execute", "raw"},
    get_call_name=_get_call_name,
    get_call_args=_get_call_args,
    get_function_name=_get_function_name,
    get_function_params=_get_function_params,
)


def run(file_path, content):
    source = content.encode()
    parser = _TS_PARSER if file_path.endswith(".ts") else _JS_PARSER
    return run_taint_check(parser, source, file_path, CONFIG)