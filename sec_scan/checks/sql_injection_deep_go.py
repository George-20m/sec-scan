"""
sql_injection_deep_go.py - Go deep SQL injection check.
Go has no native string interpolation (no equivalent to f-strings/
template literals), so only concatenation is tracked here. Building
a query with fmt.Sprintf is a real and common pattern in Go that
this version does NOT catch - a known, documented gap, since
Sprintf's danger comes from its format string content, which needs
different handling than a binary concatenation expression.
"""

import re
import tree_sitter_go as ts_go
from tree_sitter import Language, Parser

from .taint_common import LanguageConfig, run_taint_check

EXTENSIONS = {".go"}

_PARSER = Parser(Language(ts_go.language()))

SAFE_PLACEHOLDER = re.compile(r'\?|%s|@\w+|:\w+')


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


CONFIG = LanguageConfig(
    scope_types={"function_declaration", "method_declaration"},
    assign_types={"short_var_declaration", "assignment_statement"},
    identifier_types={"identifier"},
    binary_types={"binary_expression"},
    concat_ops={"+"},
    string_types=set(),        # no native interpolation in Go
    interpolation_types=set(),
    call_types={"call_expression"},
    sink_names={"query", "exec", "queryrow"},
    get_call_name=_get_call_name,
    get_call_args=_get_call_args,
)


def run(file_path, content):
    source = content.encode()
    findings = run_taint_check(_PARSER, source, file_path, CONFIG)
    return [f for f in findings if not SAFE_PLACEHOLDER.search(f["snippet"])]