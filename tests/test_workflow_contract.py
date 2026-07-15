import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
WORKFLOWS = ROOT / ".github" / "workflows"
VERIFY_COMMAND = "./tools/verify.sh"
PROTOC_ACTION = "arduino/setup-protoc@v3"
PROTOC_VERSION = '"31.1"'
BUF_ACTION = "bufbuild/buf-setup-action"
GITHUB_TOKEN_EXPRESSION = "${{ github.token }}"


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
        if (match := re.match(r"^(\s+)-(?:\s|$)", line))
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


def mapping_entry(text: str) -> tuple[str, str] | None:
    match = re.fullmatch(r"([A-Za-z_][A-Za-z0-9_-]*):(?:\s*(.*))?", text)
    if not match:
        return None
    return match.group(1), match.group(2) or ""


def scalar_value(value: str) -> str:
    value = value.strip()
    if value.startswith("#"):
        return ""
    if value.startswith("'"):
        match = re.match(r"'((?:[^']|'')*)'", value)
        if match:
            return match.group(1).replace("''", "'")
    if value.startswith('"'):
        match = re.match(r'"((?:[^"\\]|\\.)*)"', value)
        if match:
            return match.group(1)
    return re.split(r"\s+#", value, maxsplit=1)[0].strip()


def step_mapping_entries(step: list[str]) -> list[tuple[str, str, int, int]]:
    if not step:
        return []
    start = re.match(r"^(\s*)-\s*(.*)$", step[0])
    if not start:
        return []
    field_indent = len(start.group(1)) + 2
    entries: list[tuple[str, str, int, int]] = []
    first = mapping_entry(start.group(2))
    if first:
        entries.append((*first, 0, field_indent))
    for index, line in enumerate(step[1:], 1):
        stripped = line.lstrip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(line) - len(stripped)
        if indent != field_indent:
            continue
        entry = mapping_entry(stripped)
        if entry:
            entries.append((*entry, index, indent))
    return entries


def action_name(step: list[str]) -> str | None:
    uses = next(
        (value for key, value, _, _ in step_mapping_entries(step) if key == "uses"),
        None,
    )
    if uses is None:
        return None
    action_ref = scalar_value(uses)
    owner_name, separator, ref = action_ref.partition("@")
    if separator and owner_name and ref:
        return owner_name
    return None


def step_has_with_value(step: list[str], wanted_key: str, wanted_value: str) -> bool:
    with_entry = next(
        (
            (value, index, indent)
            for key, value, index, indent in step_mapping_entries(step)
            if key == "with"
        ),
        None,
    )
    if with_entry is None:
        return False
    value, index, with_indent = with_entry
    inline_value = scalar_value(value)
    if inline_value:
        return (
            re.search(
                rf"(?:^\{{|,)\s*{re.escape(wanted_key)}\s*:",
                inline_value,
            )
            is not None
            and wanted_value in inline_value
        )

    children: list[tuple[int, str, str]] = []
    for line in step[index + 1 :]:
        stripped = line.lstrip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(line) - len(stripped)
        if indent <= with_indent:
            break
        entry = mapping_entry(stripped)
        if entry:
            children.append((indent, *entry))
    if not children:
        return False
    child_indent = min(indent for indent, _, _ in children)
    return any(
        indent == child_indent
        and key == wanted_key
        and scalar_value(child_value) == wanted_value
        for indent, key, child_value in children
    )


def unauthenticated_buf_setup_steps(steps: list[list[str]]) -> list[list[str]]:
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
            for job_name, job in workflow_jobs(workflow):
                steps = job_steps(job)
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
                [
                    "      - name: Set up Buf",
                    f"        uses: {BUF_ACTION}@v1",
                    "        with:",
                    f"          github_token: {GITHUB_TOKEN_EXPRESSION}",
                ],
                True,
            ),
            "named unauthenticated": (
                [
                    "      - name: Set up Buf",
                    f"        uses: {BUF_ACTION}@v1",
                ],
                False,
            ),
            "unnamed authenticated": (
                [
                    f"      - uses: {BUF_ACTION}@v1",
                    "        with:",
                    f"          github_token: {GITHUB_TOKEN_EXPRESSION}",
                ],
                True,
            ),
            "alternate ref": ([f"      - uses: {BUF_ACTION}@main"], False),
            "quoted uses": ([f'      - uses: "{BUF_ACTION}@v2"'], False),
        }
        for name, (step, authenticated) in cases.items():
            with self.subTest(name=name):
                self.assertEqual(action_name(step), BUF_ACTION)
                self.assertEqual(
                    unauthenticated_buf_setup_steps([step]),
                    [] if authenticated else [step],
                )

    def test_token_on_adjacent_step_does_not_authenticate_buf(self) -> None:
        job = [
            "  contract:",
            "    steps:",
            "      - name: Set up Buf without a token",
            f"        uses: {BUF_ACTION}@0123456789abcdef",
            "      - name: Neighboring action",
            "        uses: example/neighbor@v1",
            "        with:",
            f"          github_token: {GITHUB_TOKEN_EXPRESSION}",
        ]
        steps = job_steps(job)
        self.assertEqual(len(steps), 2)
        self.assertEqual(unauthenticated_buf_setup_steps(steps), [steps[0]])

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
