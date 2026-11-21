#!/usr/bin/env python3
"""Fail when a Docker Swarm stack file uses Compose-only features.

Usage: lint_stack.py STACK_FILE [STACK_FILE ...]

`docker stack deploy` silently ignores or rejects several keys that plain Docker Compose
accepts, so a file that "works with docker compose up" can behave differently in Swarm.
This catches the ones that matter for stack.yml:

  - top-level `name:` (the stack name comes from the deploy command)
  - `restart:` (use deploy.restart_policy; the Swarm default is already "any")
  - `depends_on:` (ignored; start order is not guaranteed in Swarm)
  - `pre_start:` / `post_start:` / `pre_stop:` lifecycle hooks (Compose only)
  - `container_name:`, `build:`, `profiles:`, `extends:` (not supported by stack deploy)
  - container-level `labels:` (Traefik's Swarm provider reads service labels, so they
    must be under deploy.labels)
  - bridge networks (a stack needs overlay networks)
"""

import sys

import yaml

SERVICE_KEYS = {
    "restart": "use deploy.restart_policy (the Swarm default is already condition: any)",
    "depends_on": "ignored by Swarm; make the service retry its upstream instead",
    "pre_start": "Compose-only lifecycle hook; run the step in the command or an init service",
    "post_start": "Compose-only lifecycle hook",
    "pre_stop": "Compose-only lifecycle hook",
    "container_name": "not supported by stack deploy",
    "build": "not supported by stack deploy; use a published image",
    "profiles": "not supported by stack deploy",
    "extends": "not supported by stack deploy",
    "labels": "container labels are not seen by Traefik's Swarm provider; use deploy.labels",
}


def lint(data):
    """Return a list of human-readable problems for a parsed stack file."""
    problems = []
    if not isinstance(data, dict):
        return ["not a YAML mapping"]
    if "name" in data:
        problems.append("top-level `name`: the stack name comes from the deploy command")
    for service, spec in (data.get("services") or {}).items():
        for key, hint in SERVICE_KEYS.items():
            if key in (spec or {}):
                problems.append(f"services.{service}.{key}: {hint}")
    for network, spec in (data.get("networks") or {}).items():
        spec = spec or {}
        if spec.get("driver") == "bridge":
            problems.append(f"networks.{network}.driver: bridge; a stack needs overlay")
    return problems


def main(paths):
    failed = False
    for path in paths:
        with open(path, encoding="utf-8") as f:
            problems = lint(yaml.safe_load(f))
        for problem in problems:
            print(f"{path}: {problem}")
        failed = failed or bool(problems)
    if not failed:
        print("OK: no Compose-only features found")
    return 1 if failed else 0


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(2)
    sys.exit(main(sys.argv[1:]))
