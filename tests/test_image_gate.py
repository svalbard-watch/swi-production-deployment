import datetime
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from scan_images import GATE_MARKER, decode_acks, evaluate, render_comment, replace_acks  # noqa: E402

TODAY = datetime.date(2026, 11, 22)


def report(*ids):
    return {
        "Results": [
            {
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": vuln_id,
                        "Severity": "HIGH",
                        "PkgName": "libc",
                        "InstalledVersion": "1",
                        "FixedVersion": "2",
                    }
                    for vuln_id in ids
                ]
            }
        ]
    }


def entry(name, mode="enforce", note=""):
    return {"image": f"ghcr.io/o/{name}:1", "name": name, "mode": mode, "note": note}


def ack(image, vuln, until="2026-12-01", by="alice"):
    return {"image": image, "vuln": vuln, "reason": "tracked upstream", "until": until, "by": by}


class EvaluateTest(unittest.TestCase):
    def test_clean_images_pass(self):
        verdict, images = evaluate([entry("a")], {"a": report()}, [], TODAY)
        self.assertEqual(verdict, "pass")
        self.assertEqual(images[0]["status"], "ok")

    def test_unacknowledged_finding_in_enforced_image_fails(self):
        verdict, images = evaluate([entry("a")], {"a": report("CVE-1")}, [], TODAY)
        self.assertEqual(verdict, "fail")
        self.assertEqual(images[0]["status"], "blocked")

    def test_ack_for_one_vulnerability_covers_only_that_one(self):
        verdict, images = evaluate(
            [entry("a")], {"a": report("CVE-1", "CVE-2")}, [ack("a", "CVE-1")], TODAY
        )
        self.assertEqual(verdict, "fail")
        self.assertEqual([f[1] for f in images[0]["open"]], ["CVE-2"])
        self.assertEqual(images[0]["acked"][0][5], "alice")

    def test_all_ack_covers_the_image_and_passes(self):
        verdict, images = evaluate(
            [entry("a")], {"a": report("CVE-1", "CVE-2")}, [ack("a", "all")], TODAY
        )
        self.assertEqual(verdict, "pass")
        self.assertEqual(images[0]["status"], "acknowledged")

    def test_ack_for_another_image_does_not_apply(self):
        verdict, _ = evaluate([entry("a")], {"a": report("CVE-1")}, [ack("b", "all")], TODAY)
        self.assertEqual(verdict, "fail")

    def test_expired_ack_is_ignored(self):
        verdict, _ = evaluate(
            [entry("a")], {"a": report("CVE-1")}, [ack("a", "all", until="2026-11-21")], TODAY
        )
        self.assertEqual(verdict, "fail")

    def test_report_mode_image_never_fails(self):
        verdict, images = evaluate([entry("a", mode="report")], {"a": report("CVE-1")}, [], TODAY)
        self.assertEqual(verdict, "pass")
        self.assertEqual(images[0]["status"], "report")

    def test_missing_report_fails_closed(self):
        verdict, images = evaluate([entry("a")], {}, [], TODAY)
        self.assertEqual(verdict, "fail")
        self.assertEqual(images[0]["status"], "error")


class CommentTest(unittest.TestCase):
    def test_comment_has_marker_commands_and_round_trips_acks(self):
        acks = [ack("a", "CVE-9")]
        verdict, images = evaluate([entry("a"), entry("b")], {"a": report("CVE-1"), "b": report()}, acks, TODAY)
        body = render_comment(verdict, images, acks, TODAY)
        self.assertTrue(body.startswith(GATE_MARKER))
        self.assertIn("failed", body)
        self.assertIn("/ignore a CVE-1 <reason> until 2026-12-06", body)
        self.assertIn("@alice", body)
        self.assertEqual(decode_acks(body), acks)

    def test_replace_acks_updates_a_comment_or_creates_a_bare_one(self):
        old = [ack("a", "CVE-1")]
        new = [ack("a", "all")]
        body = render_comment("pass", [], old, TODAY)
        self.assertEqual(decode_acks(replace_acks(body, new)), new)
        self.assertIn("Image security gate", replace_acks("", new))
        self.assertTrue(replace_acks("", new).startswith(GATE_MARKER))
        self.assertEqual(decode_acks(replace_acks("", new)), new)

    def test_decode_acks_is_lenient(self):
        self.assertEqual(decode_acks("no marker"), [])
        self.assertEqual(decode_acks("<!-- swi-acks: !!! -->"), [])


if __name__ == "__main__":
    unittest.main()
