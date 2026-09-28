"""
run_functional_checks.py — actually executes every language's deep
check against real source samples. verify_node_types.py proves every
referenced name exists in the grammar; this proves the logic built on
those names behaves correctly end to end.
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from sec_scan.checks import sql_injection_deep as py_check
from sec_scan.checks import sql_injection_deep_js as js_check
from sec_scan.checks import sql_injection_deep_java as java_check
from sec_scan.checks import sql_injection_deep_go as go_check
from sec_scan.checks import sql_injection_deep_csharp as cs_check
from sec_scan.checks import sql_injection_deep_php as php_check
from sec_scan.checks import sql_injection_deep_ruby as rb_check

CASES = {
    "python": {
        "module": py_check,
        "ext": ".py",
        "unsafe": '''
def find_user(name):
    query = "SELECT * FROM users WHERE name = '" + name + "'"
    cursor.execute(query)
''',
        "safe": '''
def find_user(name):
    query = "SELECT * FROM users WHERE name = %s"
    cursor.execute(query, (name,))
''',
        "mixed": '''
def find_user(name):
    query = "SELECT * FROM users WHERE role = %s AND name = '" + name + "'"
    cursor.execute(query)
''',
        "format": '''
def find_user(name):
    query = "SELECT * FROM users WHERE name = '{}'".format(name)
    cursor.execute(query)
''',
        "helper": '''
def run_query(sql):
    cursor.execute(sql)

def find_user(name):
    sql = "SELECT * FROM users WHERE name = '" + name + "'"
    run_query(sql)
''',
        "false_positive_check": '''
def find_user(name):
    query = "SELECT * FROM users WHERE name = %s"
    cursor.execute(query, (name,))

def other_thing():
    x = "a" + "b"
    return x
''',
    },
    "javascript": {
        "module": js_check,
        "ext": ".js",
        "unsafe": '''
function findUser(name) {
    const query = "SELECT * FROM users WHERE name = '" + name + "'";
    db.query(query);
}
''',
        "safe": '''
function findUser(name) {
    const query = "SELECT * FROM users WHERE name = ?";
    db.query(query, [name]);
}
''',
        "mixed": '''
function findUser(name) {
    const query = `SELECT * FROM users WHERE role = ? AND name = '${name}'`;
    db.query(query);
}
''',
        "helper": '''
function runQuery(sql) {
    db.query(sql);
}
function findUser(name) {
    const sql = "SELECT * FROM users WHERE name = '" + name + "'";
    runQuery(sql);
}
''',
        "no_false_match": '''
class SafeService {
    run(value) {
        return value;
    }
}
function findUser(name) {
    const sql = "SELECT * FROM users WHERE name = '" + name + "'";
    safeService.run(sql);
}
''',
    },
    "java": {
        "module": java_check,
        "ext": ".java",
        "unsafe": '''
class U {
    void findUser(String name) {
        String sql = "SELECT * FROM users WHERE name = '" + name + "'";
        statement.executeQuery(sql);
    }
}
''',
        "safe": '''
class U {
    void findUser(String name) {
        String sql = "SELECT * FROM users WHERE name = ?";
        statement.executeQuery(sql);
    }
}
''',
        "mixed": '''
class U {
    void findUser(String name) {
        String sql = "SELECT * FROM users WHERE role = ? AND name = '" + name + "'";
        statement.executeQuery(sql);
    }
}
''',
        "format": '''
class U {
    void findUser(String name) {
        String sql = String.format("SELECT * FROM users WHERE name = '%s'", name);
        statement.executeQuery(sql);
    }
}
''',
        "helper": '''
class U {
    void runQuery(String sql) {
        statement.executeQuery(sql);
    }
    void findUser(String name) {
        String sql = "SELECT * FROM users WHERE name = '" + name + "'";
        runQuery(sql);
    }
}
''',
    },
    "go": {
        "module": go_check,
        "ext": ".go",
        "unsafe": '''
package main
func findUser(name string) {
    query := "SELECT * FROM users WHERE name = '" + name + "'"
    db.Query(query)
}
''',
        "safe": '''
package main
func findUser(name string) {
    query := "SELECT * FROM users WHERE name = ?"
    db.Query(query, name)
}
''',
        "mixed": '''
package main
func findUser(name string) {
    query := "SELECT * FROM users WHERE role = ? AND name = '" + name + "'"
    db.Query(query)
}
''',
        "format": '''
package main
func findUser(name string) {
    query := fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", name)
    db.Query(query)
}
''',
        "helper": '''
package main
func runQuery(sql string) {
    db.Query(sql)
}
func findUser(name string) {
    sql := "SELECT * FROM users WHERE name = '" + name + "'"
    runQuery(sql)
}
''',
    },
    "csharp": {
        "module": cs_check,
        "ext": ".cs",
        "unsafe": '''
class U {
    void FindUser(string name) {
        string sql = "SELECT * FROM users WHERE name = '" + name + "'";
        var cmd = new SqlCommand(sql, conn);
    }
}
''',
        "safe": '''
class U {
    void FindUser(string name) {
        string sql = "SELECT * FROM users WHERE name = @name";
        var cmd = new SqlCommand(sql, conn);
    }
}
''',
        "mixed": '''
class U {
    void FindUser(string name) {
        string sql = $"SELECT * FROM users WHERE role = @role AND name = '{name}'";
        var cmd = new SqlCommand(sql, conn);
    }
}
''',
        "helper": '''
class U {
    void RunQuery(string sql) {
        var cmd = new SqlCommand(sql, conn);
    }
    void FindUser(string name) {
        string sql = "SELECT * FROM users WHERE name = '" + name + "'";
        RunQuery(sql);
    }
}
''',
    },
    "php": {
        "module": php_check,
        "ext": ".php",
        "unsafe": '''<?php
function findUser($name) {
    $sql = "SELECT * FROM users WHERE name = '" . $name . "'";
    $this->db->query($sql);
}
''',
        "safe": '''<?php
function findUser($name) {
    $sql = "SELECT * FROM users WHERE name = ?";
    $this->db->query($sql, [$name]);
}
''',
        "mixed": '''<?php
function findUser($name) {
    $sql = "SELECT * FROM users WHERE role = ? AND name = '" . $name . "'";
    $this->db->query($sql);
}
''',
        "helper_should_NOT_propagate": '''<?php
function runQuery($sql) {
    $this->db->query($sql);
}
function findUser($name) {
    $sql = "SELECT * FROM users WHERE name = '" . $name . "'";
    runQuery($sql);
}
''',
    },
    "ruby": {
        "module": rb_check,
        "ext": ".rb",
        "unsafe": '''
def find_user(name)
  sql = "SELECT * FROM users WHERE name = '" + name + "'"
  db.execute(sql)
end
''',
        "safe": '''
def find_user(name)
  sql = "SELECT * FROM users WHERE name = ?"
  db.execute(sql, name)
end
''',
        "mixed": '''
def find_user(name)
  sql = "SELECT * FROM users WHERE role = ? AND name = '" + name + "'"
  db.execute(sql)
end
''',
        "helper": '''
def run_query(sql)
  db.execute(sql)
end

def find_user(name)
  sql = "SELECT * FROM users WHERE name = '" + name + "'"
  run_query(sql)
end
''',
    },
}

EXPECT_FINDING = {"unsafe", "mixed", "format", "helper"}
EXPECT_NO_FINDING = {"safe", "no_false_match", "false_positive_check",
                     "helper_should_NOT_propagate"}


def main():
    total = 0
    failed = 0
    for lang, spec in CASES.items():
        module = spec["module"]
        print(f"\n== {lang} ==")
        for case_name, code in spec.items():
            if case_name in ("module", "ext"):
                continue
            total += 1
            findings = module.run(f"test{spec['ext']}", code)
            got_finding = len(findings) > 0

            if case_name in EXPECT_FINDING:
                ok = got_finding
                expectation = "expected a finding"
            elif case_name in EXPECT_NO_FINDING:
                ok = not got_finding
                expectation = "expected NO finding"
            else:
                ok = None
                expectation = "no expectation set"

            status = "PASS" if ok else ("FAIL" if ok is False else "?")
            if ok is False:
                failed += 1
            print(f"  [{status}] {case_name:35s} ({expectation}, "
                  f"got {len(findings)} finding(s))")
            if ok is False:
                for f in findings:
                    print(f"         -> {f['message']} | {f['snippet']}")

    print(f"\n{total - failed}/{total} cases behaved as expected.")
    if failed:
        sys.exit(1)


if __name__ == "__main__":
    main()