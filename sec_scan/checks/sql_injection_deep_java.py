"""
sql_injection_deep_java.py - Java deep SQL injection check.
Java has no native string interpolation, so only concatenation is
tracked as an unsafe-construction pattern here.
"""

import re
import tree_sitter_java as ts_java
from tree_sitter import Language, Parser

from .taint_common import LanguageConfig, run_taint_check

EXTENSIONS = {".java"}

_PARSER = Parser(Language(ts_java.language()))

SAFE_PLACEHOLDER = re.compile(r'\?|%s|@\w+|:\w+')


def _get_call_name(call_node):
    if call_node.type != "method_invocation":
        return None
    name = call_node.child_by_field_name("name")
    return name.text.decode() if name else None


def _get_call_args(call_node):
    args = call_node.child_by_field_name("arguments")
    if args is None:
        return []
    return [c for c in args.children if c.type not in ("(", ")", ",")]


CONFIG = LanguageConfig(
    scope_types={"method_declaration", "constructor_declaration"},
    assign_types={"variable_declarator", "assignment_expression"},
    identifier_types={"identifier"},
    binary_types={"binary_expression"},
    concat_ops={"+"},
    string_types=set(),        # no native interpolation in Java
    interpolation_types=set(),
    call_types={"method_invocation"},
    sink_names={"executequery", "executeupdate"},
    get_call_name=_get_call_name,
    get_call_args=_get_call_args,
)


def run(file_path, content):
    source = content.encode()
    findings = run_taint_check(_PARSER, source, file_path, CONFIG)
    return [f for f in findings if not SAFE_PLACEHOLDER.search(f["snippet"])]
