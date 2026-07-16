import unittest
from pathlib import Path
from textwrap import indent
from typing import Any

import yaml


ROOT = Path(__file__).resolve().parent.parent
WORKFLOWS = ROOT / ".github" / "workflows"
VERIFY_COMMAND = "./tools/verify.sh"
PROTOC_ACTION = "arduino/setup-protoc"
PROTOC_REF = "v3"
PROTOC_VERSION = "31.1"
BUF_ACTION = "bufbuild/buf-setup-action"
GITHUB_TOKEN_EXPRESSION = "${{ github.token }}"


def workflow_jobs(workflow: Path) -> list[tuple[str, list[dict[str, Any]]]]:
    document = yaml.safe_load(workflow.read_text())
    if not isinstance(document, dict):
        raise AssertionError(f"{workflow.relative_to(ROOT)} must be a YAML mapping")
    jobs = document.get("jobs")
    if not isinstance(jobs, dict):
        return []
    result: list[tuple[str, list[dict[str, Any]]]] = []
    for name, job in jobs.items():
        if not isinstance(name, str) or not isinstance(job, dict):
            continue
        steps = job.get("steps", [])
        if not isinstance(steps, list):
            continue
        result.append((name, [step for step in steps if isinstance(step, dict)]))
    return result


def action_name(step: dict[str, Any]) -> str | None:
    uses = step.get("uses")
    if not isinstance(uses, str):
        return None
    owner_name, separator, ref = uses.partition("@")
    if separator and owner_name and ref:
        return owner_name
    return None


def step_has_with_value(
    step: dict[str, Any], wanted_key: str, wanted_value: str
) -> bool:
    values = step.get("with")
    return isinstance(values, dict) and values.get(wanted_key) == wanted_value


def unauthenticated_buf_setup_steps(
    steps: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    return [
        step
        for step in steps
        if action_name(step) == BUF_ACTION
        and not step_has_with_value(
            step,
            "github_token",
            GITHUB_TOKEN_EXPRESSION,
        )
    ]


class WorkflowContractTest(unittest.TestCase):
    def test_every_buf_setup_action_uses_github_token(self) -> None:
        callers: list[str] = []
        workflow_paths = sorted(WORKFLOWS.glob("*.yml")) + sorted(
            WORKFLOWS.glob("*.yaml")
        )

        for workflow in workflow_paths:
            for job_name, steps in workflow_jobs(workflow):
                buf_steps = [step for step in steps if action_name(step) == BUF_ACTION]
                if buf_steps:
                    callers.append(f"{workflow.relative_to(ROOT)}:{job_name}")
                self.assertFalse(
                    unauthenticated_buf_setup_steps(steps),
                    f"{workflow.relative_to(ROOT)}:{job_name} must authenticate "
                    f"{BUF_ACTION} GitHub API requests",
                )

        self.assertTrue(callers, f"no workflow job uses {BUF_ACTION}")

    def test_buf_setup_step_shapes_and_authentication(self) -> None:
        cases = {
            "named authenticated": (
                f"- name: Set up Buf\n  uses: {BUF_ACTION}@v1\n"
                f"  with:\n    github_token: {GITHUB_TOKEN_EXPRESSION}\n",
                True,
            ),
            "named unauthenticated": (
                f"- name: Set up Buf\n  uses: {BUF_ACTION}@v1\n",
                False,
            ),
            "unnamed authenticated": (
                f"- uses: {BUF_ACTION}@v1\n"
                f"  with: {{github_token: '{GITHUB_TOKEN_EXPRESSION}'}}\n",
                True,
            ),
            "alternate ref": (f"- uses: {BUF_ACTION}@main\n", False),
            "quoted uses key and value": (
                f'- "uses": "{BUF_ACTION}@v2"\n',
                False,
            ),
        }
        for name, (yaml_steps, authenticated) in cases.items():
            with self.subTest(name=name):
                document = yaml.safe_load("steps:\n" + indent(yaml_steps, "  "))
                step = document["steps"][0]
                self.assertEqual(action_name(step), BUF_ACTION)
                self.assertEqual(
                    unauthenticated_buf_setup_steps([step]),
                    [] if authenticated else [step],
                )

    def test_token_on_adjacent_step_does_not_authenticate_buf(self) -> None:
        document = yaml.safe_load(
            "steps:\n"
            "  - name: Set up Buf without a token\n"
            f"    uses: {BUF_ACTION}@0123456789abcdef\n"
            "  - name: Neighboring action\n"
            "    uses: example/neighbor@v1\n"
            "    with:\n"
            f"      github_token: {GITHUB_TOKEN_EXPRESSION}\n"
        )
        steps = document["steps"]
        self.assertEqual(len(steps), 2)
        self.assertEqual(unauthenticated_buf_setup_steps(steps), [steps[0]])

    def test_verify_jobs_install_pinned_protoc_first(self) -> None:
        callers: list[str] = []
        workflow_paths = sorted(WORKFLOWS.glob("*.yml")) + sorted(
            WORKFLOWS.glob("*.yaml")
        )

        for workflow in workflow_paths:
            for job_name, steps in workflow_jobs(workflow):
                verify_steps = [
                    index
                    for index, step in enumerate(steps)
                    if VERIFY_COMMAND in str(step.get("run", ""))
                ]
                if not verify_steps:
                    continue

                caller = f"{workflow.relative_to(ROOT)}:{job_name}"
                callers.append(caller)
                setup_steps = [
                    index
                    for index, step in enumerate(steps)
                    if step.get("uses") == f"{PROTOC_ACTION}@{PROTOC_REF}"
                    and step_has_with_value(step, "version", PROTOC_VERSION)
                ]
                self.assertTrue(
                    setup_steps,
                    f"{caller} must install protoc {PROTOC_VERSION} with {PROTOC_ACTION}",
                )
                self.assertLess(
                    min(setup_steps),
                    min(verify_steps),
                    f"{caller} must install protoc before running {VERIFY_COMMAND}",
                )

        self.assertTrue(callers, f"no workflow job runs {VERIFY_COMMAND}")


if __name__ == "__main__":
    unittest.main()
