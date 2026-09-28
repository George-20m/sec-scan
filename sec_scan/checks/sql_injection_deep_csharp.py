"""
sql_injection_deep_csharp.py - C# deep SQL injection check.
Treats `new SqlCommand(query)` (and similar *Command constructors)
as a sink in its own right, since the dangerous moment is often the
constructor call, not the later Execute*() call.
"""

import tree_sitter_c_sharp as ts_cs
from tree_sitter import Language, Parser

from .taint_common import LanguageConfig, run_taint_check

EXTENSIONS = {".cs"}

_PARSER = Parser(Language(ts_cs.language()))

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


def _get_function_name(func_node):
    name = func_node.child_by_field_name("name")
    return name.text.decode() if name else None


def _get_function_params(func_node):
    params_node = func_node.child_by_field_name("parameters")
    if params_node is None:
        return []
    out = []
    for c in params_node.children:
        if c.type == "parameter":
            n = c.child_by_field_name("name")
            if n:
                out.append(n.text.decode())
    return out


def _is_unqualified_call(call_node):
    # object_creation_expression (constructors) never match a local
    # method by name, so treat as qualified. invocation_expression
    # is unqualified only when its function is a bare identifier,
    # not a member_access_expression (obj.Method()).
    if call_node.type != "invocation_expression":
        return False
    fn = call_node.child_by_field_name("function")
    return fn is not None and fn.type == "identifier"


class _SinkNameSet(set):
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
    get_function_name=_get_function_name,
    get_function_params=_get_function_params,
    is_unqualified_call=_is_unqualified_call,
)


def run(file_path, content):
    source = content.encode()
    return run_taint_check(_PARSER, source, file_path, CONFIG)