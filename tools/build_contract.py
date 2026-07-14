#!/usr/bin/env python3
"""Build the v1alpha1 source from the frozen Heddle 0.23 contract.

This is an extraction aid, not a compatibility generator. The checked-in
v1alpha1 files are authoritative; CI runs this tool only to verify the legacy
migration manifest remains exhaustive.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path


PACKAGE = "heddle.api.v1alpha1"

EXTRA_TYPES = r'''
message StateId { bytes value = 1; }
message ChangeId { bytes value = 1; }
message GitObjectId { GitObjectAlgorithm algorithm = 1; bytes digest = 2; }
message RepositoryRef {
  oneof reference {
    string hosted_id = 1;
    string canonical_path = 2;
  }
}
message AgentRunId { string value = 1; }
message TimelineOperationId { bytes value = 1; }
message AgentCommandId { string value = 1; }
message PermissionId { string value = 1; }

enum GitObjectAlgorithm {
  GIT_OBJECT_ALGORITHM_UNSPECIFIED = 0;
  GIT_OBJECT_ALGORITHM_SHA1 = 1;
  GIT_OBJECT_ALGORITHM_SHA256 = 2;
}
enum AgentRunStatus {
  AGENT_RUN_STATUS_UNSPECIFIED = 0;
  AGENT_RUN_STATUS_RUNNING = 1;
  AGENT_RUN_STATUS_PAUSED = 2;
  AGENT_RUN_STATUS_COMPLETED = 3;
  AGENT_RUN_STATUS_FAILED = 4;
  AGENT_RUN_STATUS_CANCELLED = 5;
}
enum AgentVisibility {
  AGENT_VISIBILITY_UNSPECIFIED = 0;
  AGENT_VISIBILITY_OWNER_AND_MAINTAINERS = 1;
  AGENT_VISIBILITY_REPOSITORY_MEMBERS = 2;
  AGENT_VISIBILITY_ORGANIZATION = 3;
}
enum StructuredRetention {
  STRUCTURED_RETENTION_UNSPECIFIED = 0;
  STRUCTURED_RETENTION_30_DAYS = 1;
  STRUCTURED_RETENTION_90_DAYS = 2;
  STRUCTURED_RETENTION_365_DAYS = 3;
  STRUCTURED_RETENTION_UNTIL_REPOSITORY_DELETION = 4;
}
enum RawDiagnosticRetention {
  RAW_DIAGNOSTIC_RETENTION_UNSPECIFIED = 0;
  RAW_DIAGNOSTIC_RETENTION_OFF = 1;
  RAW_DIAGNOSTIC_RETENTION_1_DAY = 2;
  RAW_DIAGNOSTIC_RETENTION_7_DAYS = 3;
  RAW_DIAGNOSTIC_RETENTION_30_DAYS = 4;
}
enum AgentControlKind {
  AGENT_CONTROL_KIND_UNSPECIFIED = 0;
  AGENT_CONTROL_KIND_PAUSE_AT_SAFE_BOUNDARY = 1;
  AGENT_CONTROL_KIND_RESUME = 2;
  AGENT_CONTROL_KIND_CANCEL_BEST_EFFORT = 3;
  AGENT_CONTROL_KIND_STEER = 4;
}
enum AgentCommandStatus {
  AGENT_COMMAND_STATUS_UNSPECIFIED = 0;
  AGENT_COMMAND_STATUS_QUEUED = 1;
  AGENT_COMMAND_STATUS_DELIVERED = 2;
  AGENT_COMMAND_STATUS_ACKNOWLEDGED = 3;
  AGENT_COMMAND_STATUS_COMPLETED = 4;
  AGENT_COMMAND_STATUS_REJECTED = 5;
  AGENT_COMMAND_STATUS_EXPIRED = 6;
}
enum PermissionDecisionKind {
  PERMISSION_DECISION_KIND_UNSPECIFIED = 0;
  PERMISSION_DECISION_KIND_ALLOW_ONCE = 1;
  PERMISSION_DECISION_KIND_DENY_ONCE = 2;
  PERMISSION_DECISION_KIND_REMEMBER_ALLOW = 3;
  PERMISSION_DECISION_KIND_REMEMBER_DENY = 4;
}
'''

RETAINED = {
    "AuthService": {
        "BeginWebAuthnRegistration", "RegisterPublicKey",
        "BeginWebAuthnAuthentication", "FinishWebAuthnAuthentication",
        "CreateDeviceAuthorization", "ApproveDeviceAuthorization",
        "ExchangeDeviceAuthorization", "WaitForDeviceAuthorization",
        "RotateCredential", "RevokeCredential", "CreateServiceAccount",
        "IssueServiceAccountCredential", "RevokeServiceAccount", "WhoAmI",
        "IntrospectCredential", "ListServiceAccounts", "ListScopeCapabilities",
        "LinkOAuthIdentity", "StoreProviderToken", "VerifySignupEmail",
        "GetInvitationSummary", "ListSessions", "RevokeSession", "MintBiscuit",
        "IssuePresenceToken", "MintAnonBiscuit",
    },
    "ContentService": {
        "GetRefs", "ListStates", "GetState", "GetBlame",
        "ListProvenanceSummaries", "GetTree", "GetBlob", "GetCompare",
        "GetDiff", "GetSemanticHotSpots", "ListActions", "ListContext",
        "GetContextHistory", "ListContextSuggestions", "SetContext",
        "ReviseContext", "SupersedeContext",
    },
    "DiscussionService": {
        "OpenDiscussion", "AppendTurn", "ResolveDiscussion", "ListByState",
        "ListBySymbol",
    },
    "FeedService": {
        "StreamFeed", "GetFeedSnapshot", "RecordInteraction", "UpdateFeedItem",
    },
    "HostedUserService": {
        "GetCurrentUserNamespace", "CreateNamespace", "UpdateNamespace",
        "SetNamespaceVisibility", "DeleteNamespace", "CreateRepository",
        "ListSpools", "UpdateRepository", "DeleteRepository", "GetSpool",
        "SetSpoolVisibility", "UpdateSpoolSettings", "CreateGrant", "ListGrants",
        "UpdateGrant", "DeleteGrant", "ResolveSubjects", "CreateInvitation",
        "ListInvitations", "RevokeInvitation", "ListMembers", "ListWorktrees",
        "GrantSupportAccess", "ListSupportAccessGrants", "RevokeSupportAccess",
        "ListBookmarks", "UpsertBookmark", "DeleteBookmark", "AttachChild",
        "DetachChild", "ListChildren", "ResolveMonorepo",
    },
    "ImportService": {"CreateImportJob", "StreamImportProgress"},
    "RepoEventService": {"SubscribeRepoEvents"},
    "ReviewService": {
        "StartReviewAnalysis", "GetReviewAnalysisStatus", "GetReviewAnalysisResult",
    },
    "SearchService": {"Search"},
    "SignalService": set(),
    "StateReviewService": {"GetReviewPayload", "SignState", "ListSignatures"},
    "RepoSyncService": {"ListRefs", "UpdateRef", "Push", "Pull"},
    "ThreadWorkflowService": {
        "ListThreads", "GetWorkspaceSummary", "StreamWorkspaceSummary",
    },
}

WORKFLOW_HOSTED_METHODS = {
    "ApproveThread", "RevokeApproval", "ListThreadApprovals",
    "CheckMergeEligibility", "CreateApprovalGroup", "ListApprovalGroups",
    "DeleteApprovalGroup", "AddApprovalGroupMember", "RemoveApprovalGroupMember",
    "CreateThreadPolicy", "ListThreadPolicies", "DeleteThreadPolicy",
    "AddPolicyGroupRequirement", "RemovePolicyGroupRequirement",
}
RETAINED["HostedUserService"].update(WORKFLOW_HOSTED_METHODS)

SERVICE_TARGET = {
    "IdentityService": ["DEPLOYMENT_TARGET_WEFT"],
    "RegistryService": ["DEPLOYMENT_TARGET_WEFT"],
    "RepositoryService": ["DEPLOYMENT_TARGET_WEFT"],
    "CollaborationService": ["DEPLOYMENT_TARGET_WEFT", "DEPLOYMENT_TARGET_HEDDLE_DAEMON"],
    "StateReviewService": ["DEPLOYMENT_TARGET_WEFT", "DEPLOYMENT_TARGET_HEDDLE_DAEMON"],
    "PullRequestReviewService": ["DEPLOYMENT_TARGET_WEFT"],
    "WorkflowService": ["DEPLOYMENT_TARGET_WEFT"],
    "SearchService": ["DEPLOYMENT_TARGET_WEFT"],
    "AttentionService": ["DEPLOYMENT_TARGET_WEFT"],
    "RepoSyncService": ["DEPLOYMENT_TARGET_WEFT"],
}


def take_named_block(text: str, kind: str, name: str) -> tuple[str, str]:
    match = re.search(rf"(?m)^{kind} {re.escape(name)}\s*\{{", text)
    if not match:
        return "", text
    depth = 0
    end = match.end()
    in_string = False
    in_line_comment = False
    in_block_comment = False
    escaped = False
    index = match.end() - 1
    while index < len(text):
        char = text[index]
        following = text[index + 1] if index + 1 < len(text) else ""
        if in_line_comment:
            in_line_comment = char != "\n"
        elif in_block_comment:
            if char == "*" and following == "/":
                in_block_comment = False
                index += 1
        elif in_string:
            if char == '"' and not escaped:
                in_string = False
            escaped = char == "\\" and not escaped
            if char != "\\":
                escaped = False
        elif char == "/" and following == "/":
            in_line_comment = True
            index += 1
        elif char == "/" and following == "*":
            in_block_comment = True
            index += 1
        elif char == '"':
            in_string = True
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                end = index + 1
                break
        index += 1
    return text[match.start():end], text[:match.start()] + text[end:]


def rpc_blocks(service: str) -> dict[str, str]:
    blocks: dict[str, str] = {}
    for match in re.finditer(r"(?m)^\s*rpc\s+(\w+)", service):
        start = match.start()
        brace = service.find("{", match.end())
        semi = service.find(";", match.end())
        if semi != -1 and (brace == -1 or semi < brace):
            end = semi + 1
        else:
            depth = 0
            end = brace
            for index in range(brace, len(service)):
                if service[index] == "{":
                    depth += 1
                elif service[index] == "}":
                    depth -= 1
                    if depth == 0:
                        end = index + 1
                        break
        blocks[match.group(1)] = service[start:end].strip()
    return blocks


def source_body(path: Path, service_names: list[str]) -> tuple[str, dict[str, str]]:
    text = path.read_text()
    services: dict[str, str] = {}
    for name in service_names:
        block, text = take_named_block(text, "service", name)
        services.update(rpc_blocks(block))
    text = re.sub(r"(?m)^syntax = .*?;\n", "", text)
    text = re.sub(r"(?m)^package .*?;\n", "", text)
    text = re.sub(r"(?m)^import .*?;\n", "", text)
    text = re.sub(r"(?m)^\s*reserved\s+[^;]+;\n", "", text)
    text = text.replace("heddle.v1.", f"{PACKAGE}.")
    text = text.replace("(heddle.v1.", f"({PACKAGE}.")
    text = re.sub(r"\s*\[\(heddle\.api\.v1alpha1\.idempotency_key\)\s*=\s*true\]", "", text)
    return text.strip(), services


def method_contract(block: str) -> str:
    effect_match = re.search(r"effect:\s*RPC_EFFECT_(\w+)", block)
    dedup_match = re.search(r"deduplication:\s*RPC_DEDUPLICATION_(\w+)", block)
    effect = effect_match.group(1) if effect_match else "READ_ONLY"
    dedup = dedup_match.group(1) if dedup_match else "NONE"
    block = re.sub(r"\n?\s*option \([^;]+;", "", block)
    retry = "RETRY_BEHAVIOR_SAFE" if effect == "READ_ONLY" else "RETRY_BEHAVIOR_CLIENT_OPERATION_ID"
    required = "true" if effect == "DURABLE_WRITE" else "false"
    tier = "SIGNING_TIER_PROOF_OF_POSSESSION"
    if effect == "READ_ONLY":
        tier = "SIGNING_TIER_NONE"
    if re.search(r"rpc\s+(Push|Pull)\b", block):
        tier = "SIGNING_TIER_STREAMING_PROOF_OF_POSSESSION"
        retry = "RETRY_BEHAVIOR_RESUMABLE_STREAM"
    option = (
        f"    option ({PACKAGE}.rpc_contract) = {{\n"
        "      signing_identity: STABLE_SIGNING_IDENTITY_AUTHENTICATED_PRINCIPAL\n"
        f"      signing_tier: {tier}\n"
        f"      effect: RPC_EFFECT_{effect}\n"
        f"      retry_behavior: {retry}\n"
        f"      client_operation_id_required: {required}\n"
        "    };"
    )
    if block.endswith(";"):
        return block[:-1] + " {\n" + option + "\n  }"
    return block[:-1].rstrip() + "\n" + option + "\n  }"


def service(name: str, methods: list[str], all_methods: dict[str, str]) -> str:
    rendered = [
        f"service {name} {{",
        f"  option ({PACKAGE}.service_contract) = {{",
    ]
    rendered.extend(f"    deployment_targets: {target}" for target in SERVICE_TARGET[name])
    rendered.extend(["    maturity: SERVICE_MATURITY_SHIPPED", "  };"])
    for method in methods:
        rendered.append("  " + method_contract(all_methods[method]).replace("\n", "\n  "))
    rendered.append("}")
    return "\n".join(rendered)


def header(imports: list[str]) -> str:
    lines = ["syntax = \"proto3\";", "", f"package {PACKAGE};", ""]
    lines.extend(f'import "{item}";' for item in imports)
    return "\n".join(lines) + "\n\n"


def renumber_fields(text: str) -> str:
    stack: list[tuple[str, int]] = []
    counters: list[int] = []
    out: list[str] = []
    field = re.compile(r"^(\s*)(?:(optional|required|repeated)\s+)?([.\w<> ,]+)\s+(\w+)\s*=\s*\d+([^;]*;)(.*)$")
    for line in text.splitlines():
        stripped = line.strip()
        if re.match(r"^(message|enum|oneof)\s+\w+\s*\{", stripped):
            kind = stripped.split()[0]
            stack.append((kind, line.count("{") - line.count("}")))
            if kind == "message":
                counters.append(0)
        elif stack:
            kind, depth = stack[-1]
            stack[-1] = (kind, depth + line.count("{") - line.count("}"))
        in_message = any(kind == "message" for kind, _ in stack)
        in_enum = any(kind == "enum" for kind, _ in stack[stack.index(next(x for x in stack if x[0] == "message")) + 1:]) if in_message else False
        match = field.match(line)
        if match and in_message and not in_enum and not stripped.startswith(("option ", "reserved ")):
            counters[-1] += 1
            prefix = (match.group(2) + " ") if match.group(2) else ""
            line = f"{match.group(1)}{prefix}{match.group(3)} {match.group(4)} = {counters[-1]}{match.group(5)}{match.group(6)}"
        out.append(line)
        while stack and stack[-1][1] <= 0:
            kind, _ = stack.pop()
            if kind == "message":
                counters.pop()
    return "\n".join(out).strip() + "\n"


def add_operation_ids(text: str, durable_requests: set[str]) -> str:
    for name in sorted(durable_requests):
        block, _ = take_named_block(text, "message", name)
        if not block or re.search(r"\bclient_operation_id\s*=", block):
            continue
        replacement = block[:-1].rstrip() + "\n  string client_operation_id = 999;\n}"
        text = text.replace(block, replacement, 1)
    return text


def request_name(block: str) -> str:
    match = re.search(r"rpc\s+\w+\s*\(\s*(?:stream\s+)?([\w.]+)", block)
    return match.group(1).split(".")[-1] if match else ""


def production_callsite(service_name: str, method: str) -> str:
    if service_name == "RepoSyncService":
        return "HeddleCo/heddle:crates/client/src/grpc_hosted/sync.rs"
    if service_name == "StateReviewService":
        return "HeddleCo/heddle:crates/cli/src/cli/commands/review.rs"
    if service_name == "DiscussionService":
        return "HeddleCo/tapestry:src/lib/server/api.ts"
    if service_name == "ReviewService":
        return "HeddleCo/tapestry:src/lib/server/review-api.ts"
    if service_name == "RepoEventService":
        return "HeddleCo/tapestry:src/routes/app/events/+server.ts"
    if service_name == "FeedService" and method == "RecordInteraction":
        return "HeddleCo/tapestry:src/routes/app/feed/interaction.json/+server.ts"
    return "HeddleCo/tapestry:src/lib/server/api.ts"


def make_sync_directional(text: str) -> str:
    for name in ("PushMessage", "PullMessage"):
        block, text = take_named_block(text, "message", name)
        if not block:
            raise ValueError(f"missing legacy stream envelope {name}")
    for name in ("PushRequest", "PullRequest"):
        block, _ = take_named_block(text, "message", name)
        replacement = re.sub(r"(?m)^\s*string client_operation_id\s*=\s*\d+;\n", "", block)
        text = text.replace(block, replacement, 1)
    text = text.replace("rpc Push(stream PushMessage) returns (stream PushMessage)", "rpc Push(stream PushClientFrame) returns (stream PushServerFrame)")
    text = text.replace("rpc Pull(stream PullMessage) returns (stream PullMessage)", "rpc Pull(stream PullClientFrame) returns (stream PullServerFrame)")
    frames = r'''
message StreamOpeningProof {
  string stream_id = 1;
  string route = 2;
  RepositoryRef repository = 3;
  string resume_cursor = 4;
  bytes capability_context = 5;
  bytes nonce = 6;
  bytes signature = 7;
}
message PushClientFrame {
  oneof frame {
    StreamOpeningProof open = 1;
    PushRequest request = 2;
    PackChunk pack = 3;
    RedactionTransfer redaction = 4;
    StateVisibilityTransfer state_visibility = 5;
    GitLaneTransfer git_lane = 6;
  }
  string client_operation_id = 7;
}
message PushServerFrame {
  oneof frame {
    PushReady ready = 1;
    PushComplete complete = 2;
  }
}
message PullClientFrame {
  oneof frame {
    StreamOpeningProof open = 1;
    PullRequest request = 2;
    WantObjects want = 3;
  }
}
message PullServerFrame {
  oneof frame {
    PullReady ready = 1;
    PackChunk pack = 2;
    PullComplete complete = 3;
    RedactionTransfer redaction = 4;
    StateVisibilityTransfer state_visibility = 5;
    GitLaneTransfer git_lane = 6;
  }
}
'''
    service_at = text.index("service RepoSyncService")
    return text[:service_at] + frames + "\n" + text[service_at:]


def type_identifiers(text: str) -> str:
    qualifiers = r"(?P<qualifier>(?:optional|repeated)\s+)?"
    tag = r"(?P<tag>\s*=\s*\d+[^;]*;)"
    text = re.sub(
        rf"(?m)^(?P<indent>\s*){qualifiers}(?:bytes|string)\s+(?P<name>(?:(?:\w+_)?state(?:_ids?)?|child_head|exclude_states)){tag}",
        lambda m: f"{m['indent']}{m['qualifier'] or ''}StateId {m['name']}{m['tag']}",
        text,
    )
    text = re.sub(
        rf"(?m)^(?P<indent>\s*){qualifiers}(?:bytes|string)\s+(?P<name>\w*change_ids?){tag}",
        lambda m: f"{m['indent']}{m['qualifier'] or ''}ChangeId {m['name']}{m['tag']}",
        text,
    )
    text = re.sub(
        rf"(?m)^(?P<indent>\s*){qualifiers}string\s+(?P<name>(?:repo|repository)_paths?){tag}",
        lambda m: f"{m['indent']}{m['qualifier'] or ''}RepositoryRef {m['name']}{m['tag']}",
        text,
    )
    text = re.sub(
        rf"(?m)^(?P<indent>\s*){qualifiers}(?:bytes|string)\s+(?P<name>(?:git_)?(?:target|peeled|expected_target|commit)_oid){tag}",
        lambda m: f"{m['indent']}{m['qualifier'] or ''}GitObjectId {m['name']}{m['tag']}",
        text,
    )
    # `thread_state` is the thread lifecycle label, not a content-addressed
    # repository state. Its neighboring `thread_state_typed` enum is the typed
    # lifecycle representation.
    text = re.sub(
        r"(?m)^(?P<indent>\s*)(?P<qualifier>optional\s+)?StateId\s+thread_state(?P<tag>\s*=\s*\d+[^;]*;)",
        lambda m: f"{m['indent']}{m['qualifier'] or ''}string thread_state{m['tag']}",
        text,
    )
    return text


def normalize_enum_unspecified(text: str) -> str:
    """Give every zero enum value the contract-wide UNSPECIFIED spelling."""
    for enum_name in re.findall(r"(?m)^enum\s+(\w+)\s*\{", text):
        block, _ = take_named_block(text, "enum", enum_name)
        zero = re.search(r"(?m)^\s*(\w+)\s*=\s*0\s*;", block)
        if zero and not zero.group(1).endswith("_UNSPECIFIED"):
            prefix = re.sub(r"(?<!^)(?=[A-Z])", "_", enum_name).upper()
            updated = block[:zero.start(1)] + f"{prefix}_UNSPECIFIED" + block[zero.end(1):]
            text = text.replace(block, updated, 1)
    return text


def top_level_definitions(text: str) -> dict[str, str]:
    definitions: dict[str, str] = {}
    for kind, name in re.findall(r"(?m)^(message|enum)\s+(\w+)\s*\{", text):
        block, _ = take_named_block(text, kind, name)
        definitions[name] = block
    return definitions


def prune_unreachable(output: Path, generated_filenames: list[str]) -> None:
    all_paths = sorted(output.glob("*.proto"))
    texts = {path.name: path.read_text() for path in all_paths}
    definitions: dict[str, tuple[str, str]] = {}
    for filename in generated_filenames:
        for name, block in top_level_definitions(texts[filename]).items():
            definitions[name] = (filename, block)

    roots: set[str] = set()
    for text in texts.values():
        for request, response in re.findall(
            r"rpc\s+\w+\s*\(\s*(?:stream\s+)?(\w+)\s*\)\s*returns\s*\(\s*(?:stream\s+)?(\w+)",
            text,
        ):
            roots.update((request, response))
    # Static Agent and error definitions may reference generated shared types.
    for filename, text in texts.items():
        if filename not in generated_filenames:
            roots.update(name for name in definitions if re.search(rf"\b{re.escape(name)}\b", text))

    reachable: set[str] = set()
    pending = [name for name in roots if name in definitions]
    while pending:
        name = pending.pop()
        if name in reachable:
            continue
        reachable.add(name)
        block = definitions[name][1]
        pending.extend(
            candidate
            for candidate in definitions
            if candidate not in reachable and re.search(rf"\b{re.escape(candidate)}\b", block)
        )

    for filename in generated_filenames:
        text = texts[filename]
        for name, (owner, block) in definitions.items():
            if owner == filename and name not in reachable:
                text = text.replace(block, "", 1)
        output.joinpath(filename).write_text(re.sub(r"\n{3,}", "\n\n", text))


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit("usage: build_contract.py LEGACY_PROTO_DIR OUTPUT_DIR")
    legacy = Path(sys.argv[1])
    output = Path(sys.argv[2])
    output.mkdir(parents=True, exist_ok=True)

    specs = {
        "identity.proto": (["auth.proto"], ["AuthService"]),
        "registry.proto": (["hosted.proto", "policies.proto", "support.proto"], ["HostedUserService"]),
        "repository.proto": (["content.proto", "import.proto", "repo_events.proto"], ["ContentService", "ImportService", "RepoEventService"]),
        "collaboration.proto": (["discussion.proto"], ["DiscussionService"]),
        "state_review.proto": (["state_review.proto", "signals.proto"], ["StateReviewService", "SignalService"]),
        "pull_request_review.proto": (["review.proto"], ["ReviewService"]),
        "workflow.proto": (["threads.proto"], ["ThreadWorkflowService"]),
        "search.proto": (["search.proto"], ["SearchService"]),
        "attention.proto": (["feed.proto"], ["FeedService"]),
        "repo_sync.proto": (["sync.proto"], ["RepoSyncService"]),
    }
    source_text: dict[str, str] = {}
    method_sources: dict[str, dict[str, str]] = {}
    for filename, (sources, services) in specs.items():
        bodies: list[str] = []
        methods: dict[str, str] = {}
        for source in sources:
            owned = [name for name in services if f"service {name}" in (legacy / source).read_text()]
            body, found = source_body(legacy / source, owned)
            bodies.append(body)
            methods.update(found)
        source_text[filename] = "\n\n".join(bodies)
        method_sources[filename] = methods

    common, _ = source_body(legacy / "common.proto", [])
    (output / "types.proto").write_text(
        renumber_fields(normalize_enum_unspecified(type_identifiers(header([]) + common + "\n\n" + EXTRA_TYPES)))
    )

    service_map: dict[str, tuple[str, list[tuple[str, str]]]] = {
        "identity.proto": ("IdentityService", [("AuthService", m) for m in sorted(RETAINED["AuthService"])]),
        "registry.proto": ("RegistryService", [("HostedUserService", m) for m in sorted(RETAINED["HostedUserService"] - WORKFLOW_HOSTED_METHODS)]),
        "repository.proto": ("RepositoryService", [(s, m) for s in ("ContentService", "ImportService", "RepoEventService") for m in sorted(RETAINED[s])]),
        "collaboration.proto": ("CollaborationService", [("DiscussionService", m) for m in sorted(RETAINED["DiscussionService"])]),
        "state_review.proto": ("StateReviewService", [(s, m) for s in ("StateReviewService", "SignalService") for m in sorted(RETAINED[s])]),
        "pull_request_review.proto": ("PullRequestReviewService", [("ReviewService", m) for m in sorted(RETAINED["ReviewService"])]),
        "workflow.proto": ("WorkflowService", [("ThreadWorkflowService", m) for m in sorted(RETAINED["ThreadWorkflowService"])]),
        "search.proto": ("SearchService", [("SearchService", m) for m in sorted(RETAINED["SearchService"])]),
        "attention.proto": ("AttentionService", [("FeedService", m) for m in sorted(RETAINED["FeedService"])]),
        "repo_sync.proto": ("RepoSyncService", [("RepoSyncService", m) for m in sorted(RETAINED["RepoSyncService"])]),
    }
    # Workflow policy messages originate in registry.proto, but their methods
    # belong to the neutral WorkflowService.
    hosted_text = (legacy / "hosted.proto").read_text()
    hosted_service, _ = take_named_block(hosted_text, "service", "HostedUserService")
    hosted_methods = rpc_blocks(hosted_service)
    workflow_name, workflow_methods = service_map["workflow.proto"]
    workflow_methods.extend(("HostedUserService", m) for m in sorted(WORKFLOW_HOSTED_METHODS))
    method_sources["workflow.proto"].update(hosted_methods)

    base_imports = [
        "heddle/api/v1alpha1/contract.proto",
        "heddle/api/v1alpha1/types.proto",
        "google/protobuf/duration.proto",
        "google/protobuf/timestamp.proto",
    ]
    extra_imports = {
        "collaboration.proto": [
            "heddle/api/v1alpha1/repository.proto",
            "heddle/api/v1alpha1/state_review.proto",
        ],
        "repository.proto": ["heddle/api/v1alpha1/registry.proto"],
        "repo_sync.proto": ["heddle/api/v1alpha1/workflow.proto"],
        "workflow.proto": ["heddle/api/v1alpha1/registry.proto"],
    }
    durable_requests: set[str] = set()
    manifest: list[dict[str, str]] = []
    retained_lookup = {(s, m) for s, methods in RETAINED.items() for m in methods}
    for filename, (new_service, selected) in service_map.items():
        blocks = method_sources[filename]
        selected_blocks: dict[str, str] = {}
        for old_service, method in selected:
            block = blocks[method]
            selected_blocks[method] = block
            if "RPC_EFFECT_DURABLE_WRITE" in block:
                durable_requests.add(request_name(block))
            manifest.append({
                "old_rpc": f"heddle.v1.{old_service}/{method}",
                "classification": "renamed",
                "production_callsite": production_callsite(old_service, method),
                "new_rpc": f"{PACKAGE}.{new_service}/{method}",
            })
        rendered_service = service(new_service, [m for _, m in selected], selected_blocks)
        text = header(base_imports + extra_imports.get(filename, [])) + source_text[filename] + "\n\n" + rendered_service + "\n"
        text = add_operation_ids(text, durable_requests)
        if filename == "repo_sync.proto":
            text = make_sync_directional(text)
        text = type_identifiers(text)
        (output / filename).write_text(renumber_fields(normalize_enum_unspecified(text)))

    prune_unreachable(output, ["types.proto", *service_map.keys()])

    # Every legacy method is classified, including deliberate removals.
    for source in sorted(legacy.glob("*.proto")):
        text = source.read_text()
        for match in re.finditer(r"service\s+(\w+)\s*\{", text):
            name = match.group(1)
            block, _ = take_named_block(text, "service", name)
            for method in rpc_blocks(block):
                if (name, method) not in retained_lookup:
                    manifest.append({
                        "old_rpc": f"heddle.v1.{name}/{method}",
                        "classification": "dropped",
                        "reason": "no reachable production caller in the coordinated cutover inventory",
                    })
    manifest.sort(key=lambda item: item["old_rpc"])
    (output.parent.parent.parent.parent / "migration-manifest.json").write_text(
        json.dumps({"legacy_package": "heddle.v1", "methods": manifest}, indent=2) + "\n"
    )


if __name__ == "__main__":
    main()
