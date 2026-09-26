"""
sql_injection_deep_ruby.py - Ruby deep SQL injection check.
"""

import re
import tree_sitter_ruby as ts_ruby
from tree_sitter import Language, Parser

from .taint_common import LanguageConfig, run_taint_check

EXTENSIONS = {".rb"}

_PARSER = Parser(Language(ts_ruby.language()))

SAFE_PLACEHOLDER = re.compile(r'\?|%s|@\w+|:\w+')


def _get_call_name(call_node):
    if call_node.type != "call":
        return None
    name = call_node.child_by_field_name("method")
    return name.text.decode() if name else None


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
    scope_types={"method"},
    assign_types={"assignment"},
    identifier_types={"identifier"},
    binary_types={"binary"},
    concat_ops={"+"},
    string_types={"string"},
    interpolation_types={"interpolation"},
    call_types={"call"},
    sink_names={"execute", "exec_query", "query"},
    get_call_name=_get_call_name,
    get_call_args=_get_call_args,
    get_function_name=_get_function_name,
    get_function_params=_get_function_params,
)


def run(file_path, content):
    source = content.encode()
    findings = run_taint_check(_PARSER, source, file_path, CONFIG)
    return [f for f in findings if not SAFE_PLACEHOLDER.search(f["snippet"])]