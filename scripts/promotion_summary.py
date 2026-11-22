"""Markdown body for the pre-prod -> main promotion PR.

Usage: promotion_summary.py <base-version.json> <head-version.json> [<baseline.json>]

Compares the component versions of main (base) with pre-prod (head) and prints a table, so
reviewers see what ships without reading a raw diff. When the cycle baseline is given, also
explains which component bump decided the release number (see update-info.py).
"""

import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("update_info", ROOT / "update-info.py")
update_info = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(update_info)

LEVEL_LABEL = {"major": "**major**", "minor": "minor", "patch": "patch", None: ""}


def _components(data):
    return {k: v.get("version", "") for k, v in data.get("components", {}).items()}


def _link(name, data):
    url = data.get("components", {}).get(name, {}).get("url")
    return f"[{name}]({url})" if url else name


def _tick(value):
    return f"`{value}`" if value else "-"


def build_summary(base, head, baseline=None):
    old, new = _components(base), _components(head)
    rows = []
    for name in sorted(set(old) | set(new)):
        before, after = old.get(name), new.get(name)
        if before == after:
            continue
        if before is None:
            level, note = None, "new"
        elif after is None:
            level, note = None, "removed"
        else:
            level = update_info.classify_bump(before, after)
            note = LEVEL_LABEL[level]
        rows.append((name, before, after, note, level))

    lines = [
        f"## Release {head.get('release')} \"{head.get('release_name', '')}\"",
        "",
        f"Promotes pre-prod to production. Production currently runs "
        f"`{base.get('release')}`; this ships `{head.get('release')}` "
        f"({head.get('release_date', 'no date')}).",
        "",
    ]

    if baseline is not None:
        deciding = [
            (n, b, a)
            for n, b, a, _, lvl in rows
            if lvl == "major" and baseline.get("components", {}).get(n)
        ]
        if deciding:
            lines += [
                f"> The release number was raised to a major version by: "
                + ", ".join(f"**{n}** ({b} -> {a})" for n, b, a in deciding)
                + ".",
                "",
            ]

    if not rows:
        lines.append("No component version changes.")
    else:
        lines += [
            f"### Component changes ({len(rows)})",
            "",
            "| Component | From | To | Bump |",
            "| --- | --- | --- | --- |",
        ]
        for name, before, after, note, _ in rows:
            lines.append(f"| {_link(name, head)} | {_tick(before)} | {_tick(after)} | {note} |")
    return "\n".join(lines) + "\n"


def main(argv):
    if len(argv) not in (3, 4):
        print(__doc__, file=sys.stderr)
        return 2
    base, head = (json.loads(Path(p).read_text()) for p in argv[1:3])
    baseline = json.loads(Path(argv[3]).read_text()) if len(argv) == 4 else None
    sys.stdout.write(build_summary(base, head, baseline))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
