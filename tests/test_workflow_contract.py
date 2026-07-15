import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
WORKFLOWS = ROOT / ".github" / "workflows"
VERIFY_COMMAND = "./tools/verify.sh"
PROTOC_ACTION = "arduino/setup-protoc@v3"
PROTOC_VERSION = '"31.1"'
BUF_ACTION = "bufbuild/buf-setup-action@v1"
BUF_GITHUB_TOKEN = "github_token: ${{ github.token }}"


def workflow_jobs(workflow: Path) -> list[tuple[str, list[str]]]:
    lines = workflow.read_text().splitlines()
    jobs_start = next(
        (index for index, line in enumerate(lines) if line == "jobs:"),
        len(lines),
    )
    candidates = [
        (index, len(match.group(1)), match.group(2))
        for index, line in enumerate(lines[jobs_start + 1 :], jobs_start + 1)
        if (match := re.fullmatch(r"(\s+)([A-Za-z0-9_-]+):", line))
    ]
    job_indent = min((indent for _, indent, _ in candidates), default=0)
    job_starts = [
        (index, name)
        for index, indent, name in candidates
        if indent == job_indent
    ]
    return [
        (name, lines[start:end])
        for (start, name), (end, _) in zip(
            job_starts,
            job_starts[1:] + [(len(lines), "")],
        )
    ]


def job_steps(job: list[str]) -> list[list[str]]:
    steps_start = next(
        (index for index, line in enumerate(job) if re.fullmatch(r"\s+steps:", line)),
        len(job),
    )
    candidates = [
        (index, len(match.group(1)))
        for index, line in enumerate(job[steps_start + 1 :], steps_start + 1)
        if (match := re.match(r"^(\s+)-\s", line))
    ]
    step_indent = min((indent for _, indent in candidates), default=0)
    starts = [
        index
        for index, indent in candidates
        if indent == step_indent
    ]
    return [
        job[start:end]
        for start, end in zip(starts, starts[1:] + [len(job)])
    ]


class WorkflowContractTest(unittest.TestCase):
    def test_every_buf_setup_action_uses_github_token(self) -> None:
        callers: list[str] = []
        workflow_paths = sorted(WORKFLOWS.glob("*.yml")) + sorted(
            WORKFLOWS.glob("*.yaml")
        )

        for workflow in workflow_paths:
            for job_name, job in workflow_jobs(workflow):
                for step in job_steps(job):
                    rendered = "\n".join(step)
                    if f"uses: {BUF_ACTION}" not in rendered:
                        continue
                    caller = f"{workflow.relative_to(ROOT)}:{job_name}"
                    callers.append(caller)
                    self.assertIn(
                        BUF_GITHUB_TOKEN,
                        rendered,
                        f"{caller} must authenticate {BUF_ACTION} GitHub API requests",
                    )

        self.assertTrue(callers, f"no workflow job uses {BUF_ACTION}")

    def test_verify_jobs_install_pinned_protoc_first(self) -> None:
        callers: list[str] = []
        workflow_paths = sorted(WORKFLOWS.glob("*.yml")) + sorted(
            WORKFLOWS.glob("*.yaml")
        )

        for workflow in workflow_paths:
            for job_name, job in workflow_jobs(workflow):
                steps = job_steps(job)
                verify_steps = [
                    index
                    for index, step in enumerate(steps)
                    if VERIFY_COMMAND in "\n".join(step)
                ]
                if not verify_steps:
                    continue

                caller = f"{workflow.relative_to(ROOT)}:{job_name}"
                callers.append(caller)
                setup_steps = [
                    index
                    for index, step in enumerate(steps)
                    if f"uses: {PROTOC_ACTION}" in "\n".join(step)
                    and f"version: {PROTOC_VERSION}" in "\n".join(step)
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
