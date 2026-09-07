import json
import logging
import os
import re
from pathlib import Path
from typing import Mapping

import grpc
import yaml
from pyvelociraptor import api_pb2, api_pb2_grpc
from velociraptor_env import load_environment

load_environment()

stub = None
DEFAULT_ORG_ID = os.environ.get("VELOCIRAPTOR_ORG_ID", "").strip()
DEBUG_VQL = os.environ.get("VELOCIRAPTOR_DEBUG_VQL", "").strip().lower() in {
    "1",
    "true",
    "yes",
    "on",
}
VALID_PARAMETER_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
VALID_FIELD_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.]*$")
VALID_ARTIFACT_RE = re.compile(r"^[A-Za-z0-9_.:/-]+$")
ScalarParameter = str | int | float | bool | None
ParameterValue = ScalarParameter | list[ScalarParameter]
SCALAR_PARAMETER_TYPES = (str, int, float, bool)
logger = logging.getLogger(__name__)


def vql_literal(value: ParameterValue) -> str:
    if isinstance(value, list):
        return "[" + ", ".join(vql_literal(item) for item in value) + "]"
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "TRUE" if value else "FALSE"
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return str(value)

    escaped = str(value).replace("\\", "\\\\").replace("'", "\\'")
    return f"'{escaped}'"


def normalize_parameter_value(value) -> ParameterValue:
    if value is None or isinstance(value, SCALAR_PARAMETER_TYPES):
        return value
    if isinstance(value, list):
        normalized_items = []
        for item in value:
            if isinstance(item, list):
                raise ValueError(
                    "Parameter lists must contain scalar values only."
                )
            normalized_items.append(normalize_parameter_value(item))
        return normalized_items
    raise ValueError(
        "Parameter values must be JSON scalars or lists of scalar values."
    )


def normalize_fields(fields: str) -> str:
    cleaned = fields.strip()
    if not cleaned:
        raise ValueError("Fields must not be empty.")
    if cleaned == "*":
        return cleaned

    result = []
    for field in cleaned.split(","):
        candidate = field.strip()
        if not candidate or not VALID_FIELD_RE.fullmatch(candidate):
            raise ValueError(
                "Invalid field selection. Use '*' or a comma-separated list of field "
                "names such as 'Pid, Name, CommandLine'."
            )
        result.append(candidate)

    return ", ".join(result)


def normalize_artifact_name(artifact: str) -> str:
    cleaned = artifact.strip()
    if not cleaned or not VALID_ARTIFACT_RE.fullmatch(cleaned):
        raise ValueError(f"Invalid artifact name: {artifact!r}")
    return cleaned


def normalize_env_dict(parameters: Mapping[str, ParameterValue] | None = None) -> str:
    if parameters is None:
        return ""
    if not isinstance(parameters, Mapping):
        raise TypeError("parameters must be a mapping or None")

    items = []
    for key, value in parameters.items():
        encoded_key = vql_identifier(key)
        normalized_value = normalize_parameter_value(value)
        items.append(f"{encoded_key}={vql_literal(normalized_value)}")

    return ",".join(items)


def normalize_parameter_dict(
    parameters: Mapping[str, ParameterValue] | None = None,
) -> dict[str, ParameterValue]:
    if parameters is None:
        return {}
    if not isinstance(parameters, Mapping):
        raise TypeError("parameters must be a mapping or None")

    normalized = {}
    for key, value in parameters.items():
        vql_identifier(key)
        normalized[key] = normalize_parameter_value(value)
    return normalized


def vql_identifier(value: str) -> str:
    """Encode one VQL identifier without allowing syntax to escape it."""
    if not isinstance(value, str) or not value:
        raise ValueError("VQL identifier must be a non-empty string.")
    if VALID_PARAMETER_NAME_RE.fullmatch(value):
        return value
    if "`" in value or any(ord(character) < 32 for character in value):
        raise ValueError("VQL identifier contains unsupported characters.")
    return f"`{value}`"


def _artifact_spec_key(artifact: str) -> str:
    escaped = artifact.replace("`", "\\`")
    return f"`{escaped}`"


def hunt_spec_vql(
    artifact: str,
    parameters: Mapping[str, ParameterValue] | None = None,
) -> str:
    normalized_artifact = normalize_artifact_name(artifact)
    normalized_parameters = normalize_parameter_dict(parameters)
    if not normalized_parameters:
        return ""

    env_items = []
    for key, value in sorted(normalized_parameters.items()):
        env_items.append(f"{vql_identifier(key)}={vql_literal(value)}")
    return (
        "dict("
        f"{_artifact_spec_key(normalized_artifact)}=dict("
        + ",".join(env_items)
        + "))"
    )


def _compiled_arg_env_map(compiled_arg: dict) -> dict[str, ParameterValue]:
    env_values = {}
    for item in compiled_arg.get("env") or []:
        if not isinstance(item, dict):
            continue
        key = item.get("key")
        if not key:
            continue
        env_values[str(key)] = item.get("value")
    return env_values


def _parameter_values_equal(actual, expected: ParameterValue) -> bool:
    if actual == expected:
        return True
    if str(actual) == str(expected):
        return True
    if isinstance(expected, bool):
        return str(actual).strip().lower() in {
            "true" if expected else "false",
            "y" if expected else "n",
            "1" if expected else "0",
        }
    if isinstance(expected, list):
        try:
            parsed = json.loads(str(actual))
        except json.JSONDecodeError:
            parsed = None
        return parsed == expected
    return False


def _compiled_arg_mentions_artifact(compiled_arg: dict, artifact: str) -> bool:
    haystack_parts = []
    for item in compiled_arg.get("artifacts") or []:
        if isinstance(item, dict):
            haystack_parts.append(str(item.get("name") or ""))
        else:
            haystack_parts.append(str(item))
    for query in compiled_arg.get("Query") or []:
        if not isinstance(query, dict):
            continue
        haystack_parts.append(str(query.get("Name") or ""))
        haystack_parts.append(str(query.get("VQL") or ""))
    haystack = "\n".join(haystack_parts)
    artifact_token = artifact.replace(".", "_")
    return artifact in haystack or artifact_token in haystack


def validate_hunt_parameters(
    hunt_info: dict,
    artifact: str,
    parameters: Mapping[str, ParameterValue] | None = None,
) -> dict:
    normalized_artifact = normalize_artifact_name(artifact)
    normalized_parameters = normalize_parameter_dict(parameters)
    if not normalized_parameters:
        return {"validated": False, "reason": "no_parameters_requested"}

    start_request = hunt_info.get("start_request")
    if not isinstance(start_request, dict):
        request = hunt_info.get("Request")
        if isinstance(request, dict):
            start_request = request.get("start_request")
    if not isinstance(start_request, dict):
        raise RuntimeError("Parameterized hunt has no start_request to validate.")

    compiled_args = start_request.get("compiled_collector_args")
    if not isinstance(compiled_args, list) or not compiled_args:
        raise RuntimeError(
            "Parameterized hunt has no compiled_collector_args to validate."
        )

    artifact_candidates = [
        compiled_arg
        for compiled_arg in compiled_args
        if isinstance(compiled_arg, dict)
        and _compiled_arg_mentions_artifact(compiled_arg, normalized_artifact)
    ]
    candidates = artifact_candidates or [
        compiled_arg
        for compiled_arg in compiled_args
        if isinstance(compiled_arg, dict)
    ]

    for compiled_arg in candidates:
        if not isinstance(compiled_arg, dict):
            continue
        env_map = _compiled_arg_env_map(compiled_arg)
        missing_or_mismatched = []
        for key, expected in normalized_parameters.items():
            if key not in env_map:
                missing_or_mismatched.append(key)
                continue
            if not _parameter_values_equal(env_map[key], expected):
                missing_or_mismatched.append(key)
        if not missing_or_mismatched:
            return {
                "validated": True,
                "parameters": normalized_parameters,
                "compiled_env": env_map,
            }

    expected_env = ", ".join(
        f"{key}={value}" for key, value in sorted(normalized_parameters.items())
    )
    raise RuntimeError(
        "Refusing to start parameterized hunt because Velociraptor did not "
        f"compile the requested env for {normalized_artifact}: {expected_env}"
    )

def resolve_config_path(config_path: str | None = None) -> Path:
    explicit_path = config_path or os.environ.get("VELOCIRAPTOR_API_CONFIG")
    if explicit_path:
        resolved = Path(explicit_path).expanduser()
        if resolved.is_file():
            return resolved
        raise FileNotFoundError(
            f"Velociraptor API config not found: {resolved}. "
            "Set VELOCIRAPTOR_API_CONFIG to a valid file path."
        )

    candidates = [
        Path("api_client.yaml"),
        Path.home() / ".config" / "api_client.yaml",
    ]
    for candidate in candidates:
        resolved = candidate.expanduser()
        if resolved.is_file():
            return resolved

    raise FileNotFoundError(
        "Velociraptor API config not found. Checked ./api_client.yaml and "
        "~/.config/api_client.yaml. Set VELOCIRAPTOR_API_CONFIG to override."
    )


def init_stub(config_path: str | None = None):
    global stub
    resolved_path = resolve_config_path(config_path)
    config = yaml.safe_load(resolved_path.read_text())
    creds = grpc.ssl_channel_credentials(
        root_certificates=config["ca_certificate"].encode("utf-8"),
        private_key=config["client_private_key"].encode("utf-8"),
        certificate_chain=config["client_cert"].encode("utf-8")
    )
    channel_opts = (('grpc.ssl_target_name_override', "VelociraptorServer"),)
    channel = grpc.secure_channel(config["api_connection_string"], creds, options=channel_opts)
    stub = api_pb2_grpc.APIStub(channel)


def resolve_org_id(org_id: str | None = None) -> str | None:
    resolved = (org_id or DEFAULT_ORG_ID).strip()
    return resolved or None


def run_vql_query(
    vql: str,
    org_id: str | None = None,
    *,
    root_org: bool = False,
):
    if stub is None:
        raise RuntimeError("Stub not initialized. Call init_stub() first.")
    request = api_pb2.VQLCollectorArgs(Query=[api_pb2.VQLRequest(VQL=vql)])
    resolved_org_id = None if root_org else resolve_org_id(org_id)
    if resolved_org_id:
        request.org_id = resolved_org_id
    results = []
    if DEBUG_VQL:
        logger.debug("VQL request: %s", request)
    
    for resp in stub.Query(request):
        if hasattr(resp, "error") and resp.error:
            raise RuntimeError(f"Velociraptor API error: {resp.error}")
        if hasattr(resp, "log") and "VQL Error:" in resp.log:
            raise RuntimeError("Velociraptor rejected the VQL query.")
        if hasattr(resp, "Response") and resp.Response:
            results.extend(json.loads(resp.Response))
    return results


def run_vql_query_bounded(
    vql: str,
    *,
    max_rows: int,
    org_id: str | None = None,
    root_org: bool = False,
) -> list[dict]:
    """Read no more than ``max_rows`` from a root or selected-org VQL stream."""
    if stub is None:
        raise RuntimeError("Stub not initialized. Call init_stub() first.")
    if not isinstance(max_rows, int) or isinstance(max_rows, bool) or max_rows < 1:
        raise ValueError("max_rows must be a positive integer")
    request = api_pb2.VQLCollectorArgs(Query=[api_pb2.VQLRequest(VQL=vql)])
    resolved_org_id = None if root_org else resolve_org_id(org_id)
    if resolved_org_id:
        request.org_id = resolved_org_id

    results: list[dict] = []
    responses = stub.Query(request)
    try:
        for resp in responses:
            if hasattr(resp, "error") and resp.error:
                raise RuntimeError(f"Velociraptor API error: {resp.error}")
            if hasattr(resp, "log") and "VQL Error:" in resp.log:
                raise RuntimeError("Velociraptor rejected the VQL query.")
            if not (hasattr(resp, "Response") and resp.Response):
                continue
            decoded = json.loads(resp.Response)
            remaining = max_rows - len(results)
            results.extend(decoded[:remaining])
            if len(results) >= max_rows:
                break
    finally:
        cancel = getattr(responses, "cancel", None)
        if len(results) >= max_rows and callable(cancel):
            cancel()
    return results


def find_client_info(hostname: str, org_id: str | None = None, search_all_orgs: bool = False) -> dict:
    hostname_pattern = f"^{re.escape(hostname)}$"
    resolved_org_id = resolve_org_id(org_id)

    select_clause = (
        "SELECT client_id,"
        "timestamp(epoch=first_seen_at) as FirstSeen,"
        "timestamp(epoch=last_seen_at) as LastSeen,"
        "os_info.hostname as Hostname,"
        "os_info.fqdn as Fqdn,"
        "os_info.system as OSType,"
        "os_info.release as OS,"
        "os_info.machine as Machine,"
        "agent_information.version as AgentVersion "
    )
    where_clause = (
        f"WHERE os_info.hostname =~ {vql_literal(hostname_pattern)} "
        f"OR os_info.fqdn =~ {vql_literal(hostname_pattern)}"
    )

    if search_all_orgs and not resolved_org_id:
        vql = (
            "SELECT OrgId, Name as OrgName, client_id, FirstSeen, LastSeen, Hostname, "
            "Fqdn, OSType, OS, Machine, AgentVersion "
            "FROM foreach( "
            "row={ SELECT OrgId, Name FROM orgs() }, "
            "query={ "
            "SELECT OrgId, OrgName, client_id, FirstSeen, LastSeen, Hostname, "
            "Fqdn, OSType, OS, Machine, AgentVersion "
            "FROM query( "
            "query={ "
            f"{select_clause} FROM clients() {where_clause} "
            "ORDER BY LastSeen DESC LIMIT 1 "
            "}, "
            "org_id=OrgId "
            ") "
            "} "
            ") ORDER BY LastSeen DESC LIMIT 1"
        )
    else:
        vql = (
            f"{select_clause} "
            f"FROM clients() {where_clause} "
            "ORDER BY LastSeen DESC LIMIT 1"
        )

    result = run_vql_query(vql, org_id=resolved_org_id)
    if not result:
        return None
    row = result[0]
    if resolved_org_id and "OrgId" not in row:
        row["OrgId"] = resolved_org_id
    return row


def list_all_clients(
    search: str = ".",
    os_filter: str = ".",
    limit: int = 100,
    org_id: str | None = None,
) -> list[dict]:
    search_pattern = search or "."
    os_pattern = os_filter or "."
    vql = (
        "SELECT client_id,"
        "timestamp(epoch=first_seen_at) as FirstSeen,"
        "timestamp(epoch=last_seen_at) as LastSeen,"
        "os_info.hostname as Hostname,"
        "os_info.fqdn as Fqdn,"
        "os_info.system as OSType,"
        "os_info.release as OS,"
        "os_info.machine as Machine,"
        "agent_information.version as AgentVersion,"
        "last_ip as LastIP "
        "FROM clients() "
        f"WHERE (os_info.hostname =~ {vql_literal(search_pattern)} "
        f"OR os_info.fqdn =~ {vql_literal(search_pattern)} "
        f"OR client_id =~ {vql_literal(search_pattern)}) "
        f"AND os_info.system =~ {vql_literal(os_pattern)} "
        f"ORDER BY LastSeen DESC LIMIT {int(limit)}"
    )
    return run_vql_query(vql, org_id=org_id)


def list_windows_clients_strict() -> list[dict]:
    """Return every root-org client whose reported OS is exactly Windows."""
    vql = (
        "SELECT client_id, os_info.system AS system, "
        "os_info.hostname AS hostname, os_info.fqdn AS fqdn "
        "FROM clients() "
        "WHERE os_info.system =~ '(?i)^windows$' "
        "ORDER BY client_id"
    )
    return run_vql_query(vql, root_org=True)


def client_id_exists(client_id: str) -> bool:
    """Check one exact client id in the root org without guessing a replacement."""
    rows = run_vql_query(
        "SELECT client_id FROM clients() "
        f"WHERE client_id = {vql_literal(client_id)} LIMIT 2",
        root_org=True,
    )
    return bool(rows)


def read_root_artifact_definitions() -> list[dict]:
    """Read the exact Windows artifact metadata used for atomic registration."""
    name_pattern = r"^Windows\."
    return run_vql_query(
        "SELECT name, type, description, parameters, raw "
        "FROM artifact_definitions() "
        f"WHERE name =~ {vql_literal(name_pattern)} "
        "ORDER BY name",
        root_org=True,
    )


def artifact_exists(artifact: str) -> bool:
    normalized = normalize_artifact_name(artifact)
    rows = run_vql_query(
        "SELECT name FROM artifact_definitions() "
        f"WHERE name = {vql_literal(normalized)} LIMIT 2",
        root_org=True,
    )
    return len(rows) == 1


def start_hunt(
    artifact: str,
    parameters: Mapping[str, ParameterValue] | None = None,
    description: str = "",
    os_filter: str = "",
    org_id: str | None = None,
) -> list[dict]:
    normalized_artifact = normalize_artifact_name(artifact)
    hunt_description = description or f"MCP Hunt: {normalized_artifact}"
    normalized_parameters = normalize_parameter_dict(parameters)
    spec_vql = hunt_spec_vql(normalized_artifact, normalized_parameters)
    create_paused = not bool(normalized_parameters)

    hunt_args = [
        f"description={vql_literal(hunt_description)}",
        f"artifacts={vql_literal(normalized_artifact)}",
    ]
    if spec_vql:
        hunt_args.append(f"spec={spec_vql}")
    if os_filter.strip():
        hunt_args.append(f"os={vql_literal(os_filter.strip())}")
    if create_paused:
        hunt_args.append("pause=TRUE")

    vql = (
        "SELECT hunt(" + ", ".join(hunt_args) + ") AS HuntResult FROM scope()"
    )
    rows = run_vql_query(vql, org_id=org_id)
    hunt_result = rows[0].get("HuntResult") if rows else None
    hunt_id = ""
    if isinstance(hunt_result, dict):
        request = hunt_result.get("Request")
        hunt_id = str(
            hunt_result.get("HuntId")
            or hunt_result.get("hunt_id")
            or (request.get("hunt_id") if isinstance(request, dict) else "")
            or ""
        )
    if not hunt_id:
        hunt_id = _find_hunt_id_by_description(hunt_description, org_id=org_id)
    if not hunt_id:
        raise RuntimeError("Velociraptor hunt() did not return a hunt id.")

    validation = {"validated": False, "reason": "no_parameters_requested"}
    if normalized_parameters:
        hunt_info = _get_hunt_info(hunt_id, org_id=org_id)
        try:
            validation = validate_hunt_parameters(
                hunt_info,
                normalized_artifact,
                normalized_parameters,
            )
        except Exception:
            run_vql_query(
                "SELECT hunt_update(hunt_id="
                f"{vql_literal(hunt_id)}, stop=TRUE) AS Result FROM scope()",
                org_id=org_id,
            )
            raise

    start_rows = [{"Result": hunt_id}]
    if create_paused:
        start_rows = run_vql_query(
            "SELECT hunt_update(hunt_id="
            f"{vql_literal(hunt_id)}, start=TRUE) AS Result FROM scope()",
            org_id=org_id,
        )
    return [
        {
            "hunt_id": hunt_id,
            "description": hunt_description,
            "artifacts": [normalized_artifact],
            "parameters": normalized_parameters,
            "parameter_validation": validation,
            "os_filter": os_filter,
            "state": "STARTED",
            "created_paused": create_paused,
            "start_result": start_rows[0].get("Result") if start_rows else None,
        }
    ]


def _find_hunt_id_by_description(
    description: str,
    org_id: str | None = None,
) -> str:
    rows = run_vql_query(
        "SELECT hunt_id, create_time, hunt_description "
        "FROM hunts() "
        f"WHERE hunt_description = {vql_literal(description)} "
        "ORDER BY create_time DESC LIMIT 1",
        org_id=org_id,
    )
    if not rows:
        return ""
    return str(rows[0].get("hunt_id") or "")


def _get_hunt_info(
    hunt_id: str,
    org_id: str | None = None,
) -> dict:
    rows = run_vql_query(
        "SELECT hunt_info(hunt_id="
        f"{vql_literal(hunt_id)}) AS Hunt FROM scope()",
        org_id=org_id,
    )
    if rows and isinstance(rows[0].get("Hunt"), dict):
        return rows[0]["Hunt"]

    rows = run_vql_query(
        "SELECT * FROM hunts(hunt_id="
        f"{vql_literal(hunt_id)}) LIMIT 1",
        org_id=org_id,
    )
    if rows:
        return rows[0]
    raise RuntimeError(f"Hunt {hunt_id} was not found after creation.")


def get_hunt_results(
    hunt_id: str,
    artifact: str,
    fields: str = "*",
    limit: int = 500,
    org_id: str | None = None,
) -> list[dict]:
    normalized_artifact = normalize_artifact_name(artifact)
    normalized_fields = normalize_fields(fields)
    vql = (
        f"SELECT {normalized_fields} "
        f"FROM hunt_results(hunt_id={vql_literal(hunt_id)}, "
        f"artifact={vql_literal(normalized_artifact)}) "
        f"LIMIT {int(limit)}"
    )
    return run_vql_query(vql, org_id=org_id)


def realtime_collection(
    client_id: str,
    artifact: str,
    parameters: Mapping[str, ParameterValue] | None = None,
    fields: str = "*",
    result_scope: str = "",
    org_id: str | None = None,
) -> list[dict]:
    normalized_artifact = normalize_artifact_name(artifact)
    normalized_result_artifact = normalize_artifact_name(f"{artifact}{result_scope}")
    normalized_fields = normalize_fields(fields)
    normalized_parameters = normalize_env_dict(parameters)
    vql = (
        f"LET collection <= collect_client(urgent='TRUE',client_id={vql_literal(client_id)}, "
        f"artifacts={vql_literal(normalized_artifact)}, env=dict({normalized_parameters})) "
        f"LET get_monitoring = SELECT * FROM watch_monitoring(artifact='System.Flow.Completion') WHERE FlowId = collection.flow_id LIMIT 1 "
        f"LET get_results = SELECT * FROM source(client_id=collection.request.client_id, flow_id=collection.flow_id,artifact={vql_literal(normalized_result_artifact)}) "
        f"SELECT {normalized_fields} FROM foreach(row=get_monitoring, query=get_results) "
    )

    return run_vql_query(vql, org_id=org_id)

def start_collection(
    client_id: str,
    artifact: str,
    parameters: Mapping[str, ParameterValue] | None = None,
    timeout: int | None = None,
    max_bytes: int | None = None,
    org_id: str | None = None,
    *,
    root_org: bool = False,
) -> list[dict]:
    normalized_artifact = normalize_artifact_name(artifact)
    normalized_parameters = normalize_env_dict(parameters)
    resource_args = ""
    if timeout is not None:
        if not isinstance(timeout, int) or isinstance(timeout, bool) or timeout < 1:
            raise ValueError("timeout must be a positive integer")
        resource_args += f", timeout={timeout}"
    if max_bytes is not None:
        if not isinstance(max_bytes, int) or isinstance(max_bytes, bool) or max_bytes < 1:
            raise ValueError("max_bytes must be a positive integer")
        resource_args += f", max_bytes={max_bytes}"
    vql = (
        f"LET collection <= collect_client(urgent='TRUE',client_id={vql_literal(client_id)}, "
        f"artifacts={vql_literal(normalized_artifact)}, env=dict({normalized_parameters}){resource_args}) "
        "SELECT flow_id, request.artifacts as artifacts, request.timeout as timeout, "
        "request.max_upload_bytes as max_upload_bytes, request.specs[0] as specs "
        "FROM foreach(row=collection) "
    )

    return run_vql_query(vql, org_id=org_id, root_org=root_org)


def get_flow_status(client_id: str, flow_id: str, artifact: str, org_id: str | None = None) -> str:
    artifact_pattern = f"^Collection {re.escape(normalize_artifact_name(artifact))} is done after"
    vql = (
        f"SELECT * FROM flow_logs(client_id={vql_literal(client_id)}, flow_id={vql_literal(flow_id)}) "
        f"WHERE message =~ {vql_literal(artifact_pattern)} "
        "LIMIT 100"
    )

    results = run_vql_query(vql, org_id=org_id)

    if results and isinstance(results, list) and len(results) > 0:
        return "FINISHED"

    return "RUNNING"


def get_flow_details(
    client_id: str,
    flow_id: str,
    org_id: str | None = None,
    *,
    root_org: bool = False,
) -> dict | None:
    """Read the backend's current state for one exact client collection."""
    rows = run_vql_query(
        "SELECT session_id, state, status, create_time, start_time, active_time, "
        "total_collected_rows, total_logs, total_uploaded_files, "
        "total_uploaded_bytes, artifacts_with_results, request, request.artifacts AS artifacts "
        f"FROM flows(client_id={vql_literal(client_id)}) "
        f"WHERE session_id = {vql_literal(flow_id)} LIMIT 1",
        org_id=org_id,
        root_org=root_org,
    )
    return rows[0] if rows else None


def get_flow_results(
    client_id: str,
    flow_id: str,
    artifact: str,
    fields: str = "*",
    org_id: str | None = None,
) -> list[dict]:
    normalized_artifact = normalize_artifact_name(artifact)
    normalized_fields = normalize_fields(fields)
    vql = (
        f"SELECT {normalized_fields} FROM source(client_id={vql_literal(client_id)}, "
        f"flow_id={vql_literal(flow_id)},artifact={vql_literal(normalized_artifact)}) "
    )

    return run_vql_query(vql, org_id=org_id)


def get_flow_results_window(
    client_id: str,
    flow_id: str,
    artifact: str,
    *,
    source: str | None,
    start_row: int,
    count: int,
    org_id: str | None = None,
    root_org: bool = False,
) -> list[dict]:
    normalized_artifact = normalize_artifact_name(artifact)
    if not isinstance(start_row, int) or start_row < 0:
        raise ValueError("start_row must be a non-negative integer")
    if not isinstance(count, int) or count < 1:
        raise ValueError("count must be a positive integer")
    source_arg = ""
    if source is not None:
        cleaned_source = source.strip()
        if not cleaned_source or any(ord(character) < 32 for character in cleaned_source):
            raise ValueError("source contains unsupported characters")
        source_arg = f", source={vql_literal(cleaned_source)}"
    vql = (
        "SELECT * FROM source("
        f"client_id={vql_literal(client_id)}, flow_id={vql_literal(flow_id)}, "
        f"artifact={vql_literal(normalized_artifact)}{source_arg}, "
        f"start_row={start_row}, count={count})"
    )
    return run_vql_query(vql, org_id=org_id, root_org=root_org)


def get_flow_result_count(
    client_id: str,
    flow_id: str,
    artifact: str,
    *,
    source: str | None,
    org_id: str | None = None,
    root_org: bool = False,
) -> int:
    normalized_artifact = normalize_artifact_name(artifact)
    source_arg = ""
    if source is not None:
        cleaned_source = source.strip()
        if not cleaned_source or any(ord(character) < 32 for character in cleaned_source):
            raise ValueError("source contains unsupported characters")
        source_arg = f", source={vql_literal(cleaned_source)}"
    rows = run_vql_query(
        "SELECT count() AS Count FROM source("
        f"client_id={vql_literal(client_id)}, flow_id={vql_literal(flow_id)}, "
        f"artifact={vql_literal(normalized_artifact)}{source_arg})",
        org_id=org_id,
        root_org=root_org,
    )
    if not rows:
        return 0
    # VQL's count() is emitted as a running aggregate (1, 2, ...), so the
    # final row is the total for the selected result source.
    value = rows[-1].get("Count")
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise RuntimeError("Velociraptor returned an invalid flow result count")
    return value


def list_flow_uploads(
    client_id: str,
    flow_id: str,
    org_id: str | None = None,
    *,
    root_org: bool = False,
) -> list[dict]:
    return run_vql_query(
        "SELECT * FROM uploads("
        f"client_id={vql_literal(client_id)}, flow_id={vql_literal(flow_id)})",
        org_id=org_id,
        root_org=root_org,
    )


def read_vfs_buffer(
    components: list[str] | tuple[str, ...],
    *,
    offset: int,
    length: int,
) -> bytes:
    if stub is None:
        raise RuntimeError("Stub not initialized. Call init_stub() first.")
    if not components or any(not isinstance(item, str) for item in components):
        raise ValueError("components must be a non-empty sequence of strings")
    if offset < 0 or length < 1:
        raise ValueError("invalid VFS buffer window")
    response = stub.VFSGetBuffer(
        api_pb2.VFSFileBuffer(
            components=list(components),
            offset=offset,
            length=length,
        )
    )
    return bytes(response.data)


def cancel_flow_by_id(
    client_id: str,
    flow_id: str,
    org_id: str | None = None,
    *,
    root_org: bool = False,
) -> None:
    rows = run_vql_query(
        "SELECT cancel_flow("
        f"client_id={vql_literal(client_id)}, flow_id={vql_literal(flow_id)}) "
        "AS Result FROM scope()",
        org_id=org_id,
        root_org=root_org,
    )
    if not rows or rows[0].get("Result") is None:
        raise RuntimeError("Velociraptor cancel_flow returned no result")


def create_paused_hunt(
    artifact: str,
    parameters: Mapping[str, ParameterValue] | None,
    description: str,
    org_id: str | None = None,
    *,
    root_org: bool = False,
) -> str:
    normalized_artifact = normalize_artifact_name(artifact)
    normalized_parameters = normalize_parameter_dict(parameters)
    spec = hunt_spec_vql(normalized_artifact, normalized_parameters)
    args = [
        f"description={vql_literal(description)}",
        f"artifacts={vql_literal(normalized_artifact)}",
    ]
    if spec:
        args.append(f"spec={spec}")
    args.append("pause=TRUE")
    rows = run_vql_query(
        "SELECT hunt(" + ", ".join(args) + ") AS HuntResult FROM scope()",
        org_id=org_id,
        root_org=root_org,
    )
    result = rows[0].get("HuntResult") if rows else None
    hunt_id = ""
    if isinstance(result, dict):
        request = result.get("Request") if isinstance(result.get("Request"), dict) else {}
        hunt_id = str(
            result.get("HuntId")
            or result.get("hunt_id")
            or request.get("hunt_id")
            or ""
        )
    if not hunt_id:
        matches = run_vql_query(
            "SELECT hunt_id FROM hunts() "
            f"WHERE hunt_description = {vql_literal(description)} "
            "ORDER BY create_time DESC LIMIT 1",
            org_id=org_id,
            root_org=root_org,
        )
        hunt_id = str(matches[0].get("hunt_id") or "") if matches else ""
    if not hunt_id:
        raise RuntimeError("Velociraptor hunt() did not return a hunt id")
    return hunt_id


def add_hunt_flow(
    client_id: str,
    hunt_id: str,
    flow_id: str,
    org_id: str | None = None,
    *,
    root_org: bool = False,
) -> None:
    rows = run_vql_query(
        "SELECT hunt_add("
        f"client_id={vql_literal(client_id)}, hunt_id={vql_literal(hunt_id)}, "
        f"flow_id={vql_literal(flow_id)}) AS Result FROM scope()",
        org_id=org_id,
        root_org=root_org,
    )
    if not rows or str(rows[0].get("Result") or "") != client_id:
        raise RuntimeError("Velociraptor hunt_add did not confirm the client")


def get_hunt_details(
    hunt_id: str,
    org_id: str | None = None,
    *,
    root_org: bool = False,
) -> dict | None:
    rows = run_vql_query(
        "SELECT hunt_id, hunt_description, state, stats, artifacts, artifact_sources "
        f"FROM hunts(hunt_id={vql_literal(hunt_id)}) LIMIT 1",
        org_id=org_id,
        root_org=root_org,
    )
    return rows[0] if rows else None


def list_hunt_flows(
    hunt_id: str,
    org_id: str | None = None,
    *,
    root_org: bool = False,
) -> list[dict]:
    return run_vql_query(
        "SELECT HuntId, ClientId, FlowId, Flow.state AS FlowState "
        f"FROM hunt_flows(hunt_id={vql_literal(hunt_id)})",
        org_id=org_id,
        root_org=root_org,
    )


def stop_hunt_by_id(
    hunt_id: str,
    org_id: str | None = None,
    *,
    root_org: bool = False,
) -> None:
    rows = run_vql_query(
        "SELECT hunt_update("
        f"hunt_id={vql_literal(hunt_id)}, stop=TRUE) AS Result FROM scope()",
        org_id=org_id,
        root_org=root_org,
    )
    if not rows or str(rows[0].get("Result") or "") != hunt_id:
        raise RuntimeError("Velociraptor hunt_update did not confirm the hunt")


def list_orgs() -> list[dict]:
    return run_vql_query("SELECT OrgId, Name, Nonce FROM orgs()")
