import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from promotion_summary import build_summary  # noqa: E402


def version(release, **components):
    return {
        "release": release,
        "release_name": "Fox",
        "release_date": "2026-11-22",
        "components": {k: {"url": f"https://example.com/{k}", "version": v} for k, v in components.items()},
    }


class PromotionSummaryTest(unittest.TestCase):
    def test_table_lists_only_changed_components(self):
        base = version("2.0.9", a="1.0.0", b="2.0.0", c="3.0.0")
        head = version("2.1.0", a="1.1.0", b="2.0.0", c="3.0.1")
        out = build_summary(base, head)
        self.assertIn("| [a](https://example.com/a) | `1.0.0` | `1.1.0` | minor |", out)
        self.assertIn("| [c](https://example.com/c) | `3.0.0` | `3.0.1` | patch |", out)
        self.assertNotIn("| [b]", out)

    def test_new_component_and_major_explanation(self):
        base = version("2.0.9", a="0.0.1")
        head = version("3.0.0", a="1.0.1", f="2.11.0")
        baseline = version("2.0.9", a="0.0.1")
        out = build_summary(base, head, baseline)
        self.assertIn("**a** (0.0.1 -> 1.0.1)", out)
        self.assertIn("| [f](https://example.com/f) | - | `2.11.0` | new |", out)
        self.assertNotIn("raised to a major version by: **f**", out)

    def test_lists_the_maintainer_commands(self):
        base = version("2.0.9", a="1.0.0")
        out = build_summary(base, base)
        for command in ("/ignore", "/name", "/add-ref"):
            self.assertIn(command, out)
        self.assertNotIn("frozen", out)
        self.assertIn("frozen", build_summary(base, base, production=True))

    def test_no_changes(self):
        base = version("2.0.9", a="1.0.0")
        self.assertIn("No component version changes.", build_summary(base, base))


if __name__ == "__main__":
    unittest.main()
