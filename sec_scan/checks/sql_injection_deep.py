"""
sql_injection_deep.py - Python deep SQL injection check, now built on
the same shared taint_common.py engine as every other language, so it
gets the same cross-function propagation, format-call detection, and
is no longer filtered by the unsound SAFE_PLACEHOLDER regex.

format_min_args=1 because Python's "...".format(x) puts the format
string in the receiver (not in the argument list the way Java's
String.format("...", x) or Go's fmt.Sprintf("...", x) do), so the
generic ">=2 args" rule used by those languages would never match
Python's call shape. Requiring only ">=1 arg" here is intentionally
a looser bar than the other languages - any 1-arg call named
"format" gets treated as a possible format-string build. That can
over-flag an unrelated .format() call with unsafe data passed to a
SQL sink afterward, but errs toward catching real injection over
staying silent, same trade-off already accepted elsewhere in this
tool.
"""

import tree_sitter_python as ts_python
from tree_sitter import Language, Parser

from .taint_common import LanguageConfig, run_taint_check

EXTENSIONS = {".py"}

_PARSER = Parser(Language(ts_python.language()))


def _get_call_name(call_node):
    fn = call_node.child_by_field_name("function")
    if fn is None:
        return None
    if fn.type == "attribute":
        attr = fn.child_by_field_name("attribute")
        return attr.text.decode() if attr else None
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


def _is_unqualified_call(call_node):
    # attribute = obj.method() or "...".format() (qualified);
    # identifier = method() (bare, matches a local function).
    fn = call_node.child_by_field_name("function")
    return fn is not None and fn.type == "identifier"


CONFIG = LanguageConfig(
    scope_types={"function_definition"},
    assign_types={"assignment"},
    identifier_types={"identifier"},
    binary_types={"binary_operator"},
    concat_ops={"+"},
    string_types={"string"},
    interpolation_types={"interpolation"},
    call_types={"call"},
    sink_names={"execute", "executemany", "query", "raw"},
    get_call_name=_get_call_name,
    get_call_args=_get_call_args,
    format_call_names={"format"},
    format_min_args=1,
    get_function_name=_get_function_name,
    get_function_params=_get_function_params,
    is_unqualified_call=_is_unqualified_call,
)


def run(file_path, content):
    source = content.encode()
    return run_taint_check(_PARSER, source, file_path, CONFIG)