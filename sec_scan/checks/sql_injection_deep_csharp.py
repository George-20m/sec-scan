"""
sql_injection_deep_csharp.py - C# deep SQL injection check.

Special case worth noting: in ADO.NET, the dangerous moment is often
`new SqlCommand(query)` (the constructor), not `cmd.ExecuteReader()`
(which usually takes no arguments at all - the query was already
handed over earlier). So object_creation_expression for known
*Command classes is treated as a sink here, alongside the usual
Execute* method calls.
"""

import re
import tree_sitter_c_sharp as ts_cs
from tree_sitter import Language, Parser

from .taint_common import LanguageConfig, run_taint_check

EXTENSIONS = {".cs"}

_PARSER = Parser(Language(ts_cs.language()))

SAFE_PLACEHOLDER = re.compile(r'\?|%s|@\w+|:\w+')

COMMAND_CLASS_SUFFIX = "command"


def _get_call_name(call_node):
    if call_node.type == "object_creation_expression":
        type_node = call_node.child_by_field_name("type")
        return type_node.text.decode() if type_node else None
    if call_node.type == "invocation_expression":
        fn = call_node.child_by_field_name("function")
        if fn is None:
            return None
        if fn.type == "member_access_expression":
            name = fn.child_by_field_name("name")
            return name.text.decode() if name else None
        if fn.type == "identifier":
            return fn.text.decode()
    return None


def _get_call_args(call_node):
    args = call_node.child_by_field_name("arguments")
    if args is None:
        return []
    out = []
    for c in args.children:
        if c.type == "argument" and c.children:
            out.append(c.children[0])
    return out


class _SinkNameSet(set):
    # SqlCommand, OleDbCommand, NpgsqlCommand, MySqlCommand, etc. all
    # end in "Command" - match by suffix instead of an exhaustive list.
    def __contains__(self, item):
        if super().__contains__(item):
            return True
        return isinstance(item, str) and item.endswith(COMMAND_CLASS_SUFFIX)


CONFIG = LanguageConfig(
    scope_types={"method_declaration", "constructor_declaration"},
    assign_types={"variable_declarator", "assignment_expression"},
    identifier_types={"identifier"},
    binary_types={"binary_expression"},
    concat_ops={"+"},
    string_types={"interpolated_string_expression"},
    interpolation_types={"interpolation"},
    call_types={"invocation_expression", "object_creation_expression"},
    sink_names=_SinkNameSet({"executereader", "executenonquery", "executescalar"}),
    get_call_name=_get_call_name,
    get_call_args=_get_call_args,
)


def run(file_path, content):
    source = content.encode()
    findings = run_taint_check(_PARSER, source, file_path, CONFIG)
    return [f for f in findings if not SAFE_PLACEHOLDER.search(f["snippet"])]