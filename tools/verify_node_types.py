"""
verify_node_types.py — cross-checks every tree-sitter node type and
field name our checks/*.py files assume exists against the REAL
node-types.json shipped by each grammar's own source repo. This
catches a guessed field name that silently returns None instead of
erroring, for every language, in one pass, instead of one
hand-written example at a time.

Run once to fetch the grammars' node-types.json files (they don't
ship in the compiled pip packages, only in each grammar's source
repo), then run the verifier against your checks/ folder.

Usage:
    python tools/fetch_node_types.py     # one-time / after upgrading
                                          # a tree-sitter-* dependency
    python tools/verify_node_types.py
"""

import json
import os
import re

NODE_TYPES_DIR = os.path.join(os.path.dirname(__file__), "node_types")
CHECKS_DIR = os.path.join(os.path.dirname(__file__), "..", "sec_scan", "checks")

LANGUAGES = {
    "python": "sql_injection_deep.py",
    "javascript": "sql_injection_deep_js.py",
    "typescript": "sql_injection_deep_js.py",
    "java": "sql_injection_deep_java.py",
    "go": "sql_injection_deep_go.py",
    "php": "sql_injection_deep_php.py",
    "c-sharp": "sql_injection_deep_csharp.py",
    "ruby": "sql_injection_deep_ruby.py",
}

TYPE_KWARGS_TO_CHECK = {
    "scope_types", "assign_types", "identifier_types", "binary_types",
    "string_types", "interpolation_types", "call_types",
}


def load_all_type_names(node_types_json):
    """Every node type name the grammar knows about, named or not,
    at any position (top-level type, or a subtype inside a
    supertype's list)."""
    names = set()
    for entry in node_types_json:
        names.add(entry["type"])
        for subtype in entry.get("subtypes", []):
            names.add(subtype["type"])
    return names


def load_all_field_names(node_types_json):
    """Every field name declared on any node type in the grammar."""
    fields = set()
    for entry in node_types_json:
        for field_name in entry.get("fields", {}):
            fields.add(field_name)
    return fields


def extract_type_set_literals(source):
    """Pulls every set-of-strings literal assigned to a config
    kwarg we care about, e.g. scope_types={"a", "b"}. Returns
    {kwarg_name: {string, ...}}."""
    result = {}
    pattern = re.compile(r'(\w+)\s*=\s*\{([^}]*)\}', re.DOTALL)
    for kwarg, body in pattern.findall(source):
        strings = re.findall(r'"([^"]+)"', body)
        if strings:
            result.setdefault(kwarg, set()).update(strings)
    return result


def extract_field_name_literals(source):
    """Every literal passed to child_by_field_name(...)."""
    return set(re.findall(r'child_by_field_name\("([^"]+)"\)', source))


def main():
    any_problem = False

    for lang, check_file in LANGUAGES.items():
        json_path = os.path.join(NODE_TYPES_DIR, f"{lang}.json")
        check_path = os.path.join(CHECKS_DIR, check_file)

        if not os.path.exists(json_path):
            print(f"=== {lang} ===\n  SKIPPED - run fetch_node_types.py first "
                  f"({json_path} not found)")
            continue

        with open(json_path) as f:
            grammar = json.load(f)
        with open(check_path) as f:
            source = f.read()

        all_types = load_all_type_names(grammar)
        all_fields = load_all_field_names(grammar)

        type_literals = extract_type_set_literals(source)
        field_literals = extract_field_name_literals(source)

        print(f"\n=== {lang} ({check_file}) ===")

        problems_here = False
        for kwarg, values in type_literals.items():
            if kwarg not in TYPE_KWARGS_TO_CHECK:
                continue
            unknown = {v for v in values if v not in all_types}
            if unknown:
                problems_here = True
                any_problem = True
                print(f"  [TYPE MISMATCH] {kwarg}: {sorted(unknown)} "
                      f"not found in grammar's node types")

        unknown_fields = {f for f in field_literals if f not in all_fields}
        if unknown_fields:
            problems_here = True
            any_problem = True
            print(f"  [FIELD MISMATCH] child_by_field_name(...) uses "
                  f"unknown field(s): {sorted(unknown_fields)}")

        if not problems_here:
            print("  OK - every referenced node type and field name "
                  "exists in the real grammar")

    print()
    if any_problem:
        print("RESULT: mismatches found (see above)")
        raise SystemExit(1)
    print("RESULT: all language configs check out clean against their real grammars")


if __name__ == "__main__":
    main()