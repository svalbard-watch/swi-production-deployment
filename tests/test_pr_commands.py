import datetime
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from pr_commands import (  # noqa: E402
    CommandError,
    add_ack,
    add_reference,
    bibtex_to_csl,
    first_command,
    set_release_name,
)

TODAY = datetime.date(2026, 11, 22)
NAMES = ["swi-mapproxy", "redis"]

BIB = """\
@misc{npi_geodata,
  title = {{Norwegian Polar Institute} Map Data},
  author = {Norwegian Polar Institute and Doe, Jane},
  year = {2024},
  month = jan,
  url = {https://geodata.npolar.no/},
  urldate = {2024-01-22},
  note = {map-layer, base},
  abstract = {Line one
     continues},
}
"""


class FirstCommandTest(unittest.TestCase):
    def test_finds_the_command_on_any_line(self):
        self.assertEqual(first_command("hello\n/name Fox\nbye")[0], "/name")

    def test_ignores_text_that_only_mentions_a_command(self):
        self.assertEqual(first_command("please do /name later")[0], None)
        self.assertEqual(first_command("/namex")[0], None)


class AckTest(unittest.TestCase):
    def test_adds_with_default_and_explicit_dates(self):
        acks, e = add_ack([], "/ignore redis CVE-2025-1234 waiting for upstream", NAMES, "alice", TODAY)
        self.assertEqual((e["until"], e["reason"], e["by"]), ("2026-12-06", "waiting for upstream", "alice"))
        acks, e = add_ack(acks, "/ignore redis all fine until 2026-12-31", NAMES, "bob", TODAY)
        self.assertEqual((e["until"], e["vuln"], e["reason"]), ("2026-12-31", "all", "fine"))
        self.assertEqual(len(acks), 2)

    def test_same_image_and_vuln_is_replaced(self):
        acks, _ = add_ack([], "/ignore redis all one", NAMES, "alice", TODAY)
        acks, _ = add_ack(acks, "/ignore redis all two", NAMES, "bob", TODAY)
        self.assertEqual([(a["reason"], a["by"]) for a in acks], [("two", "bob")])

    def test_rejects_bad_input(self):
        for line in (
            "/ignore redis",
            "/ignore nope all reason",
            "/ignore redis ! reason",
            "/ignore redis all reason until 2026-02-30",
            "/ignore redis all reason until 2026-11-01",
            "/ignore redis all reason until 2027-12-31",
        ):
            with self.assertRaises(CommandError, msg=line):
                add_ack([], line, NAMES, "alice", TODAY)


class NameTest(unittest.TestCase):
    def test_sets_name_and_keeps_the_rest(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp, "version.json")
            path.write_bytes(b'{\r\n  "release": "3.0.0",\r\n  "release_name": "Old"\r\n}\r\n')
            self.assertEqual(set_release_name(path, "/name Arctic Fox"), ("Old", "Arctic Fox"))
            raw = path.read_bytes()
            self.assertIn(b"\r\n", raw)
            self.assertEqual(json.loads(raw), {"release": "3.0.0", "release_name": "Arctic Fox"})

    def test_rejects_empty_and_long_names(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp, "version.json")
            path.write_text("{}")
            for line in ("/name", "/name " + "x" * 61):
                with self.assertRaises(CommandError):
                    set_release_name(path, line)


class ReferenceTest(unittest.TestCase):
    def test_bibtex_to_csl(self):
        csl = bibtex_to_csl(BIB)
        self.assertEqual(csl["id"], "npi_geodata")
        self.assertEqual(csl["type"], "document")
        self.assertEqual(csl["title"], "Norwegian Polar Institute Map Data")
        self.assertEqual(csl["author"], [{"literal": "Norwegian Polar Institute"}, {"family": "Doe", "given": "Jane"}])
        self.assertEqual(csl["issued"], {"date-parts": [[2024, 1]]})
        self.assertEqual(csl["accessed"], {"date-parts": [[2024, 1, 22]]})
        self.assertEqual(csl["note"], "map-layer, base")
        self.assertEqual(csl["abstract"], "Line one continues")
        self.assertEqual(csl["URL"], "https://geodata.npolar.no/")

    def test_requires_entry_and_title(self):
        for text in ("nothing", "@misc{k, year = {2024}}"):
            with self.assertRaises(CommandError):
                bibtex_to_csl(text)

    def test_appends_keeping_tabs_and_line_endings_and_rejects_duplicates(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp, "references.json")
            path.write_bytes(b'[\r\n\t{\r\n\t\t"id": "x",\r\n\t\t"URL": "https://a/"\r\n\t}\r\n]\r\n')
            add_reference(path, BIB)
            raw = path.read_bytes()
            self.assertIn(b'\r\n\t{\r\n\t\t"id": "npi_geodata"', raw)
            self.assertEqual([r["id"] for r in json.loads(raw)], ["x", "npi_geodata"])
            with self.assertRaises(CommandError):
                add_reference(path, BIB)
            with self.assertRaises(CommandError):
                add_reference(path, BIB.replace("npi_geodata", "other"))


if __name__ == "__main__":
    unittest.main()
