"""Parse dependency files (requirements.txt, package.json)."""

import json
import sys
import re


def parse_requirements_txt(filepath):
    """Parse a Python requirements.txt file."""
    deps = []
    with open(filepath, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # Match patterns like: Django==4.2.0, flask>=2.0
            match = re.match(r"^([a-zA-Z0-9_.-]+)==([a-zA-Z0-9_.*+-]+)", line)
            if match:
                name = match.group(1)
                version = match.group(2)
                deps.append({"name": name, "version": version, "ecosystem": "PyPI"})
    return deps


def parse_package_json(filepath):
    """Parse a Node.js package.json file."""
    deps = []
    with open(filepath, "r") as f:
        data = json.load(f)

    for section in ["dependencies", "devDependencies"]:
        if section in data:
            for name, version in data[section].items():
                # Strip version prefixes like ^, ~, >=
                clean_version = re.sub(r"^[^0-9]*", "", version)
                if clean_version:
                    deps.append({"name": name, "version": clean_version, "ecosystem": "npm"})
    return deps


def parse_file(filepath):
    """Auto-detect file type and parse."""
    if filepath.endswith(".json"):
        return parse_package_json(filepath)
    else:
        return parse_requirements_txt(filepath)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python parse_deps.py <filepath>")
        print("  e.g. python parse_deps.py samples/requirements.txt")
        sys.exit(1)

    filepath = sys.argv[1]
    deps = parse_file(filepath)

    print(f"\nParsed {len(deps)} dependencies from {filepath}:\n")
    for dep in deps:
        print(f"  {dep['name']} {dep['version']} ({dep['ecosystem']})")