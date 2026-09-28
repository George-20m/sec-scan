import re

EXTENSIONS = {".py", ".js", ".ts", ".php", ".java", ".cs", ".rb", ".go"}

SINK_PATTERN = re.compile(
    r"\b(execute|executemany|executeQuery|executeUpdate|"
    r"ExecuteReader|ExecuteNonQuery|ExecuteScalar|"
    r"createStatement|query|raw)\s*\(",
    re.IGNORECASE,
)

DANGER_PATTERNS = [
    re.compile(r'["\']\s*\+\s*\w'),
    re.compile(r'\w\s*\+\s*["\']'),
    re.compile(r'f["\'].*\{.*\}'),
    re.compile(r'\.format\('),
    re.compile(r'\$\{'),
    re.compile(r'\$"'),
]


def run(file_path, content):
    findings = []

    for lineno, line in enumerate(content.splitlines(), start=1):
        if not SINK_PATTERN.search(line):
            continue

        if any(p.search(line) for p in DANGER_PATTERNS):
            findings.append({
                "check_id": "SQL-INJECTION",
                "severity": "HIGH",
                "file": file_path,
                "line": lineno,
                "message": (
                    "Query looks like it's built with string "
                    "concatenation/interpolation instead of parameters. "
                    "Possible SQL injection."
                ),
                "snippet": line,
            })

    return findings