import json
import sys
import re


def parse_requirements_txt(filepath):
    deps = []
    with open(filepath) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            match = re.match(r"^([a-zA-Z0-9_.-]+)==([a-zA-Z0-9_.*+-]+)", line)
            if match:
                deps.append({"name": match.group(1), "version": match.group(2), "ecosystem": "PyPI"})
    return deps


def parse_package_json(filepath):
    deps = []
    with open(filepath) as f:
        data = json.load(f)

    for section in ["dependencies", "devDependencies"]:
        for name, version in data.get(section, {}).items():
            clean = re.sub(r"^[^0-9]*", "", version)
            if clean:
                deps.append({"name": name, "version": clean, "ecosystem": "npm"})
    return deps


def parse_file(filepath):
    if filepath.endswith(".json"):
        return parse_package_json(filepath)
    return parse_requirements_txt(filepath)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python parse_deps.py <filepath>")
        sys.exit(1)

    deps = parse_file(sys.argv[1])
    print(f"\nParsed {len(deps)} deps from {sys.argv[1]}:\n")
    for d in deps:
        print(f"  {d['name']} {d['version']} ({d['ecosystem']})")