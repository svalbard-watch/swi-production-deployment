import sys
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from lint_stack import lint, max_stack_name_length  # noqa: E402


class LintStackTest(unittest.TestCase):
    def test_clean_stack_has_no_problems(self):
        data = {
            "services": {
                "web": {
                    "image": "nginx:1",
                    "deploy": {"replicas": 1, "labels": ["traefik.enable=true"]},
                }
            },
            "networks": {"internal": {"driver": "overlay"}, "ext": {"external": True}},
        }
        self.assertEqual(lint(data), [])

    def test_every_compose_only_key_is_reported(self):
        data = {
            "name": "x",
            "services": {
                "web": {
                    "image": "nginx:1",
                    "restart": "always",
                    "depends_on": ["db"],
                    "pre_start": [{"command": ["true"]}],
                    "container_name": "web",
                    "labels": ["traefik.enable=true"],
                }
            },
            "networks": {"internal": {"driver": "bridge"}},
        }
        text = "\n".join(lint(data))
        for expected in (
            "top-level `name`",
            "services.web.restart",
            "services.web.depends_on",
            "services.web.pre_start",
            "services.web.container_name",
            "services.web.labels",
            "networks.internal.driver",
        ):
            self.assertIn(expected, text)

    def test_service_with_empty_spec_and_network_with_no_options(self):
        data = {"services": {"web": None}, "networks": {"internal": None}}
        self.assertEqual(lint(data), [])

    def test_stack_name_budget_comes_from_the_longest_service_name(self):
        data = {"services": {"redis": {}, "CRON_AAforecast_cache": {}}}
        self.assertEqual(max_stack_name_length(data), 63 - 1 - len("CRON_AAforecast_cache"))

    def test_repository_stack_name_budget_is_documented_correctly(self):
        with open(ROOT / "stack.yml", encoding="utf-8") as f:
            budget = max_stack_name_length(yaml.safe_load(f))
        with open(ROOT / "README.md", encoding="utf-8") as f:
            self.assertIn(f"at most {budget} characters", f.read())

    def test_repository_stack_file_is_clean(self):
        with open(ROOT / "stack.yml", encoding="utf-8") as f:
            self.assertEqual(lint(yaml.safe_load(f)), [])


if __name__ == "__main__":
    unittest.main()
