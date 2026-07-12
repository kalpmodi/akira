#!/usr/bin/env python3
"""Repository quality checks for skills/docs content."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

SESSION_SCHEMA = ROOT / "docs/schemas/session.schema.json"
SESSION_EXAMPLE = ROOT / "docs/schemas/examples/session.example.json"
INTERESTING_SCHEMA = ROOT / "docs/schemas/interesting.schema.json"
INTERESTING_EXAMPLES = sorted((ROOT / "docs/schemas/examples").glob("interesting_*.md"))

MARKDOWN_GLOBS = [
    "README.md",
    "INSTALL.md",
    "CONTRIBUTING.md",
    "CHANGELOG.md",
    "SECURITY.md",
    "FINDINGS.md",
    "docs/**/*.md",
    "skills/**/*.md",
    "platform-adapters/**/*.md",
]

LINK_RE = re.compile(r"\[([^\]]+)\]\(([^)]+)\)")
BASH_BLOCK_RE = re.compile(r"```bash\n(.*?)\n```", re.DOTALL)
FENCED_CODE_RE = re.compile(r"```.*?```", re.DOTALL)


def fail(msg: str) -> None:
    print(f"[FAIL] {msg}")
    sys.exit(1)


def load_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        fail(f"Invalid JSON in {path}: {exc}")


def validate_type(value, schema_type: str) -> bool:
    type_map = {
        "object": dict,
        "array": list,
        "string": str,
        "number": (int, float),
        "integer": int,
        "boolean": bool,
    }
    expected = type_map.get(schema_type)
    if expected is None:
        return True
    if schema_type == "number" and isinstance(value, bool):
        return False
    if schema_type == "integer" and isinstance(value, bool):
        return False
    return isinstance(value, expected)


def validate_simple_schema(data, schema: dict, path: str = "$") -> list[str]:
    errors: list[str] = []
    expected_type = schema.get("type")
    if expected_type and not validate_type(data, expected_type):
        return [f"{path}: expected {expected_type}, got {type(data).__name__}"]

    if isinstance(data, dict):
        for key in schema.get("required", []):
            if key not in data:
                errors.append(f"{path}: missing required key '{key}'")
        properties = schema.get("properties", {})
        for key, subschema in properties.items():
            if key in data:
                errors.extend(validate_simple_schema(data[key], subschema, f"{path}.{key}"))

    if isinstance(data, list) and "items" in schema:
        for idx, item in enumerate(data):
            errors.extend(validate_simple_schema(item, schema["items"], f"{path}[{idx}]"))

    return errors


def check_artifact_schemas() -> None:
    for required in (SESSION_SCHEMA, SESSION_EXAMPLE, INTERESTING_SCHEMA):
        if not required.exists():
            fail(f"Missing required schema file: {required}")

    schema = load_json(SESSION_SCHEMA)
    example = load_json(SESSION_EXAMPLE)
    errors = validate_simple_schema(example, schema)
    if errors:
        fail("session.json example failed schema validation:\n" + "\n".join(errors))

    interesting_rules = load_json(INTERESTING_SCHEMA)
    required_sections = interesting_rules.get("required_sections", [])
    if not INTERESTING_EXAMPLES:
        fail("No interesting_*.md examples found in docs/schemas/examples/")

    for example_md in INTERESTING_EXAMPLES:
        text = example_md.read_text(encoding="utf-8")
        for section in required_sections:
            if section not in text:
                fail(f"{example_md} missing required section: {section}")

    print("[OK] Artifact schemas and examples validated")


def check_command_blocks() -> None:
    bad_blocks: list[str] = []
    for skill_file in sorted((ROOT / "skills").glob("**/SKILL.md")):
        text = skill_file.read_text(encoding="utf-8")
        blocks = BASH_BLOCK_RE.findall(text)
        for index, block in enumerate(blocks, start=1):
            lines = [ln for ln in (line.strip() for line in block.splitlines()) if ln]
            if not lines:
                bad_blocks.append(f"{skill_file}: bash block #{index} is empty")
                continue
            if any(ln.startswith("$ ") for ln in lines):
                bad_blocks.append(f"{skill_file}: bash block #{index} uses shell prompt '$ '")
    if bad_blocks:
        fail("Command block lint failed:\n" + "\n".join(bad_blocks))
    print("[OK] Command block lint passed")


def is_external_or_anchor(link: str) -> bool:
    return (
        link.startswith("http://")
        or link.startswith("https://")
        or link.startswith("mailto:")
        or link.startswith("#")
    )


def check_links() -> None:
    markdown_files: set[Path] = set()
    for pattern in MARKDOWN_GLOBS:
        markdown_files.update(ROOT.glob(pattern))

    missing: list[str] = []
    for md in sorted(markdown_files):
        text = md.read_text(encoding="utf-8")
        text_for_links = FENCED_CODE_RE.sub("", text)
        for _, raw_link in LINK_RE.findall(text_for_links):
            link = raw_link.strip()
            if is_external_or_anchor(link):
                continue
            link = link.split("#", 1)[0]
            if not link:
                continue
            target = (md.parent / link).resolve()
            try:
                target.relative_to(ROOT.resolve())
            except ValueError:
                missing.append(f"{md}: path escapes repo root -> {raw_link}")
                continue
            if not target.exists():
                missing.append(f"{md}: missing link target -> {raw_link}")

    if missing:
        fail("Markdown link check failed:\n" + "\n".join(missing))
    print("[OK] Markdown link check passed")


def main() -> None:
    check_artifact_schemas()
    check_command_blocks()
    check_links()
    print("[DONE] Repository quality validation passed")


if __name__ == "__main__":
    main()
