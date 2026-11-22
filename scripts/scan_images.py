#!/usr/bin/env python3
"""Helpers for the scheduled scan of the images deployed by stack.yml.

Two subcommands, both used by .github/workflows/scan-deployed-images.yml:

  scan_images.py matrix COMPOSE EXCEPTIONS
      Print the GitHub Actions matrix (JSON) with one entry per image in the compose
      file. An image with a current entry in the exceptions file is scanned in
      "report" mode (findings are shown but never fail the run); every other image,
      and any image whose exception has expired, is scanned in "enforce" mode.

  scan_images.py summary TRIVY_JSON
      Print a Markdown summary of a Trivy JSON report and exit 0. The number of
      findings is written to stdout's last line as ``findings=<n>``.

  scan_images.py aggregate MATRIX_JSON REPORTS_DIR ACKS_JSON OUT_MARKDOWN
      Combine every image's report (REPORTS_DIR/<name>.json) into one verdict and write the
      PR comment to OUT_MARKDOWN. Prints ``verdict=pass|fail``. The gate fails when an
      enforced image has a fixable HIGH/CRITICAL finding that no acknowledgement covers, or
      when a report is missing (a scan that did not run must not read as a pass).

  scan_images.py acks COMMENT_FILE            print the acknowledgements stored in a comment
  scan_images.py set-acks COMMENT_FILE ACKS   store acknowledgements in a comment file

Acknowledgements (JSON list, kept in the PR comment by scripts/pr_commands.py): {"image":
"<short name>", "vuln": "<CVE id>" or "all", "reason": "...", "until": "YYYY-MM-DD", "by":
"<login>"}. An acknowledgement past its date no longer counts.

Exceptions file (JSON): a list of {"image": "<repository without tag>", "reason": "...",
"expires": "YYYY-MM-DD"}. An exception must say why and when it ends.
"""

import base64
import datetime
import json
import os
import re
import sys

IMAGE_LINE = re.compile(r"^\s*image:\s*(?P<image>[^\s#]+)\s*(?:#.*)?$")
MAX_ROWS = 40
GATE_MARKER = "<!-- swi-image-gate -->"
ACKS_MARKER = re.compile(r"<!-- swi-acks: ([A-Za-z0-9+/=]*) -->")


def list_images(compose_text):
    """Image references in a compose file, in order, without duplicates."""
    images = []
    for line in compose_text.splitlines():
        match = IMAGE_LINE.match(line)
        if not match:
            continue
        image = match["image"].strip("\"'")
        if "${" in image:
            raise ValueError(
                f"image '{image}' uses a variable; the scan needs literal references"
            )
        if image not in images:
            images.append(image)
    return images


def repository(image):
    """The image without its tag or digest: 'redis:8.10-alpine' -> 'redis'."""
    image = image.split("@", 1)[0]
    last = image.rsplit("/", 1)[-1]
    if ":" in last:
        image = image.rsplit(":", 1)[0]
    return image


def parse_exceptions(text):
    exceptions = json.loads(text) if text.strip() else []
    for entry in exceptions:
        for key in ("image", "reason", "expires"):
            if not entry.get(key):
                raise ValueError(f"exception {entry!r} needs a non-empty '{key}'")
        datetime.date.fromisoformat(entry["expires"])
    return exceptions


def build_matrix(images, exceptions, today):
    """One entry per image: its reference, a short name and the scan mode."""
    entries = []
    for image in images:
        mode, note = "enforce", ""
        for exception in exceptions:
            if exception["image"] != repository(image):
                continue
            if datetime.date.fromisoformat(exception["expires"]) >= today:
                mode = "report"
                note = f"exception until {exception['expires']}: {exception['reason']}"
            else:
                note = f"exception expired on {exception['expires']}"
        entries.append(
            {
                "image": image,
                "name": repository(image).rsplit("/", 1)[-1],
                "mode": mode,
                "note": note,
            }
        )
    return {"include": entries}


def collect_findings(report):
    """(severity, id, package, installed, fixed) for each vulnerability in a Trivy report."""
    findings = []
    for result in report.get("Results") or []:
        for vuln in result.get("Vulnerabilities") or []:
            findings.append(
                (
                    vuln.get("Severity", "?"),
                    vuln.get("VulnerabilityID", "?"),
                    vuln.get("PkgName", "?"),
                    vuln.get("InstalledVersion", "?"),
                    vuln.get("FixedVersion", "") or "-",
                )
            )
    order = {"CRITICAL": 0, "HIGH": 1}
    return sorted(findings, key=lambda f: (order.get(f[0], 2), f[2], f[1]))


def summarize(report):
    findings = collect_findings(report)
    if not findings:
        return "No fixable HIGH or CRITICAL findings.\n", 0
    lines = [
        f"**{len(findings)} fixable HIGH/CRITICAL findings**",
        "",
        "| Severity | Vulnerability | Package | Installed | Fixed in |",
        "|---|---|---|---|---|",
    ]
    for severity, vuln_id, package, installed, fixed in findings[:MAX_ROWS]:
        lines.append(f"| {severity} | {vuln_id} | {package} | {installed} | {fixed} |")
    if len(findings) > MAX_ROWS:
        lines.append(f"\n... and {len(findings) - MAX_ROWS} more.")
    return "\n".join(lines) + "\n", len(findings)


def active_acks(acks, today):
    return [a for a in acks if datetime.date.fromisoformat(a["until"]) >= today]


def covers(ack, name, vuln_id):
    return ack["image"] == name and ack["vuln"] in ("all", vuln_id)


def evaluate(entries, reports, acks, today):
    """Per image: status 'ok' | 'acknowledged' | 'report' | 'blocked' | 'error' plus findings.

    reports maps an image's short name to its Trivy report (absent when the scan made none).
    Returns (verdict, images); each finding is (severity, id, package, installed, fixed, ack_by).
    """
    live = active_acks(acks, today)
    images = []
    for entry in entries:
        name = entry["name"]
        report = reports.get(name)
        item = {**entry, "open": [], "acked": [], "status": "ok"}
        if report is None:
            item["status"] = "error"
            images.append(item)
            continue
        for finding in collect_findings(report):
            by = [a for a in live if covers(a, name, finding[1])]
            (item["acked"] if by else item["open"]).append((*finding, by[0]["by"] if by else ""))
        if item["open"]:
            item["status"] = "blocked" if entry["mode"] == "enforce" else "report"
        elif item["acked"]:
            item["status"] = "acknowledged"
        images.append(item)
    failed = any(i["status"] in ("blocked", "error") for i in images)
    return ("fail" if failed else "pass"), images


STATUS_LABEL = {
    "ok": "✅ clean",
    "acknowledged": "☑️ acknowledged",
    "report": "👀 exception (report only)",
    "blocked": "❌ blocked",
    "error": "⚠️ no report",
}


def encode_acks(acks):
    return base64.b64encode(json.dumps(acks, separators=(",", ":")).encode()).decode()


def decode_acks(comment_body):
    """Acknowledgements stored in a gate comment; [] when absent or unreadable."""
    match = ACKS_MARKER.search(comment_body or "")
    if not match:
        return []
    try:
        return json.loads(base64.b64decode(match[1]).decode())
    except ValueError:
        return []


def replace_acks(comment_body, acks):
    """The comment with its stored acknowledgements replaced; a bare gate comment if none."""
    marker = f"<!-- swi-acks: {encode_acks(acks)} -->"
    if ACKS_MARKER.search(comment_body or ""):
        return ACKS_MARKER.sub(lambda _: marker, comment_body)
    return f"{GATE_MARKER}\n## ⏳ Image security gate: running\n\n{marker}\n"


def render_comment(verdict, images, acks, today, run_url=""):
    blocked = sum(len(i["open"]) for i in images if i["status"] == "blocked")
    errors = [i["name"] for i in images if i["status"] == "error"]
    if verdict == "pass":
        banner = "## ✅ Image security gate: passed"
        sub = "Every image in `stack.yml` was scanned; no unacknowledged fixable HIGH/CRITICAL findings."
    else:
        banner = "## ❌ Image security gate: failed"
        parts = []
        if blocked:
            parts.append(f"**{blocked}** unacknowledged fixable HIGH/CRITICAL finding(s)")
        if errors:
            parts.append("no scan report for " + ", ".join(f"`{n}`" for n in errors))
        sub = "; ".join(parts) + "."
    lines = [
        GATE_MARKER,
        banner,
        "",
        sub,
        "",
        "| Image | Result | Critical | High | Acknowledged |",
        "|---|---|--:|--:|--:|",
    ]
    for item in images:
        crit = sum(1 for f in item["open"] if f[0] == "CRITICAL")
        high = sum(1 for f in item["open"] if f[0] == "HIGH")
        lines.append(
            f"| `{item['name']}` | {STATUS_LABEL[item['status']]} | {crit} | {high} | {len(item['acked'])} |"
        )
    example_date = today + datetime.timedelta(days=14)
    for item in images:
        if not item["open"] and not item["note"]:
            continue
        lines += ["", f"<details><summary><b>{item['name']}</b>: {len(item['open'])} open finding(s)</summary>", ""]
        if item["note"]:
            lines += [f"> {item['note']}", ""]
        if item["open"]:
            lines += ["| Severity | Vulnerability | Package | Installed | Fixed in |", "|---|---|---|---|---|"]
            for sev, vuln_id, pkg, inst, fixed, _ in item["open"][:MAX_ROWS]:
                lines.append(f"| {sev} | {vuln_id} | {pkg} | {inst} | {fixed} |")
            if len(item["open"]) > MAX_ROWS:
                lines.append(f"\n... and {len(item['open']) - MAX_ROWS} more.")
            lines += [
                "",
                "Acknowledge one finding, or the whole image (devops-team only), in a PR comment:",
                "",
                "```",
                f"/ignore {item['name']} {item['open'][0][1]} <reason> until {example_date}",
                f"/ignore {item['name']} all <reason> until {example_date}",
                "```",
            ]
        lines += ["", "</details>"]
    live = active_acks(acks, today)
    if live:
        lines += ["", "### Acknowledged", "", "| Image | Vulnerability | By | Until | Reason |", "|---|---|---|---|---|"]
        for a in live:
            reason = a["reason"].replace("|", "\\|")
            lines.append(f"| `{a['image']}` | {a['vuln']} | @{a['by']} | {a['until']} | {reason} |")
    if run_url:
        lines += ["", f"<sub>[Scan run]({run_url}). Acknowledgements are per PR and expire on their date.</sub>"]
    lines += ["", f"<!-- swi-acks: {encode_acks(acks)} -->"]
    return "\n".join(lines) + "\n"


def aggregate(matrix, reports_dir, acks, today, run_url=""):
    entries = matrix["include"]
    reports = {}
    for entry in entries:
        path = os.path.join(reports_dir, f"{entry['name']}.json")
        if os.path.exists(path):
            with open(path, encoding="utf-8") as handle:
                reports[entry["name"]] = json.load(handle)
    verdict, images = evaluate(entries, reports, acks, today)
    return verdict, render_comment(verdict, images, acks, today, run_url)


def main(argv):
    if len(argv) == 4 and argv[1] == "matrix":
        with open(argv[2], encoding="utf-8") as handle:
            images = list_images(handle.read())
        with open(argv[3], encoding="utf-8") as handle:
            exceptions = parse_exceptions(handle.read())
        matrix = build_matrix(images, exceptions, datetime.date.today())
        print(json.dumps(matrix, separators=(",", ":")))
        return 0
    if len(argv) == 3 and argv[1] == "summary":
        with open(argv[2], encoding="utf-8") as handle:
            text, count = summarize(json.load(handle))
        print(text)
        print(f"findings={count}")
        return 0
    if len(argv) == 3 and argv[1] == "acks":
        # Acknowledgements stored in a comment file ([] when the file is empty or missing).
        body = open(argv[2], encoding="utf-8").read() if os.path.exists(argv[2]) else ""
        print(json.dumps(decode_acks(body)))
        return 0
    if len(argv) == 4 and argv[1] == "set-acks":
        # set-acks COMMENT_FILE ACKS_JSON: rewrite the comment file with the new acknowledgements.
        body = open(argv[2], encoding="utf-8").read() if os.path.exists(argv[2]) else ""
        with open(argv[3], encoding="utf-8") as handle:
            acks = json.load(handle)
        with open(argv[2], "w", encoding="utf-8") as handle:
            handle.write(replace_acks(body, acks))
        return 0
    if len(argv) == 6 and argv[1] == "aggregate":
        with open(argv[2], encoding="utf-8") as handle:
            matrix = json.load(handle)
        with open(argv[4], encoding="utf-8") as handle:
            acks = json.load(handle)
        verdict, markdown = aggregate(
            matrix, argv[3], acks, datetime.date.today(), os.environ.get("RUN_URL", "")
        )
        with open(argv[5], "w", encoding="utf-8") as handle:
            handle.write(markdown)
        print(f"verdict={verdict}")
        return 0
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv))
    except (ValueError, OSError) as error:
        print(f"error: {error}", file=sys.stderr)
        sys.exit(1)
