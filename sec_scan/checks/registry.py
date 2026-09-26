import importlib
import os


def load_checks():
    checks_dir = os.path.dirname(__file__)
    modules = []

    for filename in sorted(os.listdir(checks_dir)):
        if not filename.endswith(".py"):
            continue
        if filename in ("__init__.py", "registry.py"):
            continue

        module_name = f"sec_scan.checks.{filename[:-3]}"
        module = importlib.import_module(module_name)

        if hasattr(module, "EXTENSIONS") and hasattr(module, "run"):
            modules.append(module)

    return modules