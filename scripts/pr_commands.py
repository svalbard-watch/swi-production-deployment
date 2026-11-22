#!/usr/bin/env python3
"""Slash commands that maintainers write in a promotion PR comment.

  /ignore <image> <CVE-id | all> <reason> [until YYYY-MM-DD]
      Acknowledge a finding (or every finding of an image) for this PR.
  /name <release name>
      Set release_name in info/version.json.
  /add-ref
  ```bibtex
  @misc{key, title = {...}, ...}
  ```
      Append the BibTeX entry to info/references.json (CSL-JSON, as exported by Zotero).

Used by .github/workflows/pr-commands.yml, which checks who commented and does the git and
GitHub work. This script only parses, validates and rewrites files. The comment text comes
in through the COMMENT_BODY environment variable and is never executed.

  pr_commands.py parse                         print {"command": ...} as JSON
  pr_commands.py ignore ACKS_JSON STACK_YML    add an acknowledgement (env ACK_USER)
  pr_commands.py name VERSION_JSON             set the release name
  pr_commands.py add-ref REFERENCES_JSON       add the BibTeX reference

Exit status: 0 done, 3 the command is invalid (the message on stdout is meant for the PR
comment), 1 anything else.
"""

import datetime
import json
import os
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from scan_images import list_images, repository  # noqa: E402

DEFAULT_ACK_DAYS = 14
MAX_ACK_DAYS = 90
MAX_NAME = 60
COMMANDS = ("/ignore", "/name", "/add-ref")
IGNORE = re.compile(
    r"^/ignore\s+(?P<image>\S+)\s+(?P<vuln>\S+)\s+(?P<reason>.+?)"
    r"(?:\s+until\s+(?P<until>\d{4}-\d{2}-\d{2}))?\s*$"
)
VULN_ID = re.compile(r"^(all|[A-Za-z0-9][A-Za-z0-9._-]{2,63})$")
FENCE = re.compile(r"```(?:bibtex|bib)?\s*\n(?P<code>.*?)```", re.DOTALL | re.IGNORECASE)


class CommandError(Exception):
    """The command is invalid; the message is shown to the maintainer."""


def first_command(body):
    """(command, rest of the first line) of the first line that starts with a known command."""
    for line in (body or "").replace("\r\n", "\n").split("\n"):
        line = line.strip()
        for command in COMMANDS:
            if line == command or line.startswith(command + " "):
                return command, line
    return None, ""


# ---- /ignore ---------------------------------------------------------------------------


def add_ack(acks, line, image_names, user, today):
    match = IGNORE.match(line)
    if not match:
        raise CommandError(
            "Usage: `/ignore <image> <CVE-id | all> <reason> until YYYY-MM-DD` "
            "(the `until` part is optional, default %d days, maximum %d)." % (DEFAULT_ACK_DAYS, MAX_ACK_DAYS)
        )
    image, vuln, reason = match["image"], match["vuln"], match["reason"].strip()
    if image not in image_names:
        raise CommandError(f"Unknown image `{image}`. Images in the stack: " + ", ".join(f"`{n}`" for n in image_names) + ".")
    if not VULN_ID.match(vuln):
        raise CommandError(f"`{vuln}` is not a vulnerability id (for example `CVE-2025-1234`) or `all`.")
    limit = today + datetime.timedelta(days=MAX_ACK_DAYS)
    if match["until"]:
        try:
            until = datetime.date.fromisoformat(match["until"])
        except ValueError:
            raise CommandError(f"`{match['until']}` is not a valid date.") from None
    else:
        until = today + datetime.timedelta(days=DEFAULT_ACK_DAYS)
    if until < today:
        raise CommandError("The `until` date is in the past.")
    if until > limit:
        raise CommandError(f"An acknowledgement lasts at most {MAX_ACK_DAYS} days (until {limit}).")
    entry = {"image": image, "vuln": vuln, "reason": reason, "until": until.isoformat(), "by": user}
    kept = [a for a in acks if not (a["image"] == image and a["vuln"] == vuln)]
    return kept + [entry], entry


# ---- /name -----------------------------------------------------------------------------


def set_release_name(version_path, line):
    name = line[len("/name"):].strip()
    if not name:
        raise CommandError("Usage: `/name <release name>`.")
    if len(name) > MAX_NAME or not name.isprintable():
        raise CommandError(f"The release name must be printable text of at most {MAX_NAME} characters.")
    raw = Path(version_path).read_bytes().decode("utf-8")
    newline = "\r\n" if "\r\n" in raw else "\n"
    data = json.loads(raw)
    old = data.get("release_name")
    data["release_name"] = name
    text = json.dumps(data, indent=2, ensure_ascii=False)
    tail = newline if raw.endswith("\n") else ""
    Path(version_path).write_bytes((text.replace("\n", newline) + tail).encode("utf-8"))
    return old, name


# ---- /add-ref --------------------------------------------------------------------------

BIB_TYPES = {
    "article": "article-journal",
    "inproceedings": "paper-conference",
    "conference": "paper-conference",
    "book": "book",
    "incollection": "chapter",
    "inbook": "chapter",
    "techreport": "report",
    "report": "report",
    "phdthesis": "thesis",
    "mastersthesis": "thesis",
    "dataset": "dataset",
    "software": "software",
}
MONTHS = {m: i for i, m in enumerate(
    ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"], 1)}


def parse_bibtex(text):
    """The single entry of a BibTeX snippet as (type, key, {field: value})."""
    head = re.search(r"@(\w+)\s*([{(])\s*([^,\s]+)\s*,", text)
    if not head:
        raise CommandError("No BibTeX entry found. Expected `@misc{key, title = {...}, ...}`.")
    entry_type, key = head[1].lower(), head[3]
    closer = "}" if head[2] == "{" else ")"
    fields, i, n = {}, head.end(), len(text)
    while i < n:
        m = re.compile(r"\s*([A-Za-z][\w-]*)\s*=\s*").match(text, i)
        if not m:
            skip = re.compile(r"[\s,]*").match(text, i)
            i = skip.end()
            if i >= n or text[i] == closer:
                break
            raise CommandError(f"Cannot read the BibTeX near `{text[i:i + 30]}`.")
        name, i = m[1].lower(), m.end()
        if i < n and text[i] == "{":
            depth, j = 0, i
            while j < n:
                depth += text[j] == "{"
                depth -= text[j] == "}"
                j += 1
                if depth == 0:
                    break
            if depth:
                raise CommandError(f"Unbalanced braces in the `{name}` field.")
            value, i = text[i + 1:j - 1], j
        elif i < n and text[i] == '"':
            j = text.find('"', i + 1)
            if j < 0:
                raise CommandError(f"Unterminated quote in the `{name}` field.")
            value, i = text[i + 1:j], j + 1
        else:
            m2 = re.compile(r"[^,}\s]+").match(text, i)
            value = m2[0] if m2 else ""
            i = m2.end() if m2 else i
        fields[name] = re.sub(r"\s+", " ", value.replace("{", "").replace("}", "")).strip()
        i = re.compile(r"\s*,?").match(text, i).end()
    return entry_type, key, fields


def _people(value):
    people = []
    for person in re.split(r"\s+and\s+", value):
        if "," in person:
            family, given = (p.strip() for p in person.split(",", 1))
            people.append({"family": family, "given": given})
        elif person.strip():
            people.append({"literal": person.strip()})
    return people


def _date(value):
    parts = [p for p in re.split(r"[-/ ]", value.lower()) if p]
    out = []
    for p in parts[:3]:
        out.append(MONTHS.get(p[:3], p) if not p.isdigit() else p)
    return {"date-parts": [[int(x) if str(x).isdigit() else x for x in out]]} if out else None


def bibtex_to_csl(text):
    entry_type, key, f = parse_bibtex(text)
    if not f.get("title"):
        raise CommandError("The BibTeX entry needs a `title`.")
    csl = {"id": key, "type": BIB_TYPES.get(entry_type, "document")}
    if f.get("note"):
        csl["note"] = f["note"]  # swi-frontend reads the tags from here
    if f.get("abstract"):
        csl["abstract"] = f["abstract"]
    for source in ("publisher", "organization", "institution"):
        if f.get(source):
            csl["publisher"] = f[source]
            break
    csl["title"] = f["title"]
    if f.get("url"):
        csl["URL"] = f["url"]
    if f.get("author"):
        csl["author"] = _people(f["author"])
    elif f.get("organization") or f.get("institution"):
        csl["author"] = [{"literal": f.get("organization") or f["institution"]}]
    for source in ("journal", "booktitle"):
        if f.get(source):
            csl["container-title"] = f[source]
            break
    if f.get("address"):
        csl["publisher-place"] = f["address"]
    issued = _date(f["date"]) if f.get("date") else _date(" ".join(x for x in (f.get("year"), f.get("month")) if x))
    if issued:
        csl["issued"] = issued
    if f.get("urldate"):
        accessed = _date(f["urldate"])
        if accessed:
            csl["accessed"] = accessed
    return csl


def add_reference(references_path, text):
    raw = Path(references_path).read_bytes().decode("utf-8")
    newline = "\r\n" if "\r\n" in raw else "\n"
    refs = json.loads(raw)
    csl = bibtex_to_csl(text)
    for ref in refs:
        if ref.get("id") == csl["id"] or (csl.get("URL") and ref.get("URL") == csl["URL"]):
            raise CommandError(f"A reference with this key or URL already exists (`{ref.get('id')}`).")
    refs.append(csl)
    out = json.dumps(refs, indent="\t", ensure_ascii=False)
    tail = newline if raw.endswith("\n") else ""
    Path(references_path).write_bytes((out.replace("\n", newline) + tail).encode("utf-8"))
    return csl


# ---- command line ----------------------------------------------------------------------


def main(argv):
    body = os.environ.get("COMMENT_BODY", "")
    command, line = first_command(body)
    try:
        if len(argv) == 2 and argv[1] == "parse":
            print(json.dumps({"command": command}))
            return 0
        if len(argv) == 4 and argv[1] == "ignore" and command == "/ignore":
            names = [repository(i).rsplit("/", 1)[-1] for i in list_images(Path(argv[3]).read_text(encoding="utf-8"))]
            acks = json.loads(Path(argv[2]).read_text(encoding="utf-8"))
            acks, entry = add_ack(acks, line, names, os.environ["ACK_USER"], datetime.date.today())
            Path(argv[2]).write_text(json.dumps(acks), encoding="utf-8")
            print(f"Acknowledged `{entry['vuln']}` for `{entry['image']}` until {entry['until']}: {entry['reason']}")
            return 0
        if len(argv) == 3 and argv[1] == "name" and command == "/name":
            old, new = set_release_name(argv[2], line)
            print(f"Release name set to **{new}** (was {old!r}).")
            return 0
        if len(argv) == 3 and argv[1] == "add-ref" and command == "/add-ref":
            after = body.replace("\r\n", "\n").split(line, 1)[-1]
            fenced = FENCE.search(after)
            csl = add_reference(argv[2], fenced["code"] if fenced else after)
            print(f"Reference `{csl['id']}` added: {csl['title']}")
            return 0
    except CommandError as error:
        print(str(error))
        return 3
    print(__doc__, file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
