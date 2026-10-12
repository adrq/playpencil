"""Validate the committed OpenAPI document: OAS 3.1 validity, structural
invariants of the /v1 contract, and schema behaviour on sample instances."""

import copy
import json
import sys

import jsonschema
import referencing
import referencing.jsonschema
from openapi_spec_validator import validate

PROBLEM_JSON = "application/problem+json"
RESERVED = "Reserved."
SCHEMA_PREFIX = "#/components/schemas/"

# (content type, body component) per operation and status; None = no body.
# "string" = an inline string schema.
JSON = "application/json"
BODY_MATRIX = {
    ("post", "/v1/sandboxes"): {
        "202": (JSON, "SandboxDocument"),
        "400": (PROBLEM_JSON, "Problem"),
        "401": None,
        "403": None,
        "409": (PROBLEM_JSON, "CreateConflictProblem"),
        "422": (PROBLEM_JSON, "InvalidInputProblem"),
    },
    ("get", "/v1/sandboxes"): {
        "200": (JSON, "SandboxList"),
        "400": (PROBLEM_JSON, "Problem"),
        "401": None,
        "403": None,
        "422": (PROBLEM_JSON, "InvalidInputProblem"),
    },
    ("get", "/v1/sandboxes/{id}"): {
        "200": (JSON, "SandboxDocument"),
        "401": None,
        "403": None,
        "404": (PROBLEM_JSON, "NotFoundProblem"),
    },
    ("patch", "/v1/sandboxes/{id}"): {
        "202": (JSON, "SandboxDocument"),
        "400": (PROBLEM_JSON, "Problem"),
        "401": None,
        "403": None,
        "404": (PROBLEM_JSON, "NotFoundProblem"),
        "409": (PROBLEM_JSON, "PatchConflictProblem"),
        "422": (PROBLEM_JSON, "InvalidInputProblem"),
        "500": (PROBLEM_JSON, "InternalProblem"),
    },
    ("get", "/v1/sandboxes/{id}/events"): {
        "200": ("text/event-stream", "string"),
        "400": (PROBLEM_JSON, "Problem"),
        "401": None,
        "403": None,
        "404": (PROBLEM_JSON, "NotFoundProblem"),
    },
    ("get", "/v1/streams"): {
        "101": None,
    },
    ("post", "/v1/sandboxes/{id}/processes"): {
        "201": (JSON, "ProcessRecord"),
        "400": (PROBLEM_JSON, "Problem"),
        "401": None,
        "403": None,
        "404": (PROBLEM_JSON, "NotFoundProblem"),
        "409": (PROBLEM_JSON, "ProcessConflictProblem"),
        "422": (PROBLEM_JSON, "InvalidInputProblem"),
    },
    ("get", "/v1/sandboxes/{id}/processes"): {
        "200": (JSON, "ProcessList"),
        "401": None,
        "403": None,
        "404": (PROBLEM_JSON, "NotFoundProblem"),
    },
    ("get", "/v1/sandboxes/{id}/processes/{pid}"): {
        "200": (JSON, "ProcessRecord"),
        "401": None,
        "403": None,
        "404": (PROBLEM_JSON, "NotFoundProblem"),
    },
    ("delete", "/v1/sandboxes/{id}/processes/{pid}"): {
        "202": None,
        "401": None,
        "403": None,
        "404": (PROBLEM_JSON, "NotFoundProblem"),
        "409": (PROBLEM_JSON, "ProcessConflictProblem"),
    },
    ("get", "/v1/capabilities"): {
        "200": (JSON, "CapabilitiesResponse"),
        "401": None,
        "403": None,
    },
    ("get", "/v1/health"): {
        "200": None,
        "401": None,
        "403": None,
        "503": None,
    },
}
STATUS_MATRIX = {op: set(responses) for op, responses in BODY_MATRIX.items()}
REQUEST_BODY_MATRIX = {
    ("post", "/v1/sandboxes"): "CreateSandboxRequest",
    ("patch", "/v1/sandboxes/{id}"): "PatchSandboxRequest",
    ("post", "/v1/sandboxes/{id}/processes"): "CommandSpecWrite",
}

TAGS = {"sandboxes", "events", "processes", "streams", "system"}

REQUEST_BODIES = ["CreateSandboxRequest", "PatchSandboxRequest", "CommandSpecWrite"]
EVENT_COMPONENTS = ["ChangedEvent", "NoticeEvent"]

NULLABLE = {
    ("Status", "state"),
    ("ConfigPatch", "main"),
    ("PatchConflictProblem", "current_state"),
    ("ProcessConflictProblem", "current_state"),
}
OPTIONAL_NON_NULLABLE = {
    ("CreateSandboxRequest", "desired_state"),
    ("ConfigCreate", "backend_options"),
    ("ConfigCreate", "mounts"),
    ("ConfigCreate", "env"),
    ("ConfigCreate", "main"),
    ("PatchSandboxRequest", "desired_state"),
    ("PatchSandboxRequest", "clear_reason"),
    ("PatchSandboxRequest", "config"),
    ("ConfigPatch", "network"),
    ("ConfigPatch", "mounts"),
    ("ConfigPatch", "env"),
    ("ConfigPatch", "backend"),
    ("ConfigPatch", "backend_options"),
    ("CommandSpecWrite", "uid"),
    ("CommandSpecWrite", "gid"),
}
REQUIRED_NON_NULLABLE = {
    ("PatchSandboxRequest", "if_version"),
    ("ConfigCreate", "backend"),
    ("ConfigCreate", "network"),
}
FREE_FORM_MAPS = {
    ("ConfigCreate", "env"),
    ("ConfigPatch", "env"),
    ("CommandSpecWrite", "env"),
    ("ConfigCreate", "backend_options"),
    ("ConfigPatch", "backend_options"),
}
NOTICE_CODES = {
    "deny",
    "pin_registered",
    "pin_expired",
    "host_addresses_changed",
    "resync",
    "flush_incomplete",
    "gap",
}

failures: list[str] = []


def fail(pointer: str, message: str) -> None:
    failures.append(f"{pointer}: {message}")


def ref_name(schema: dict) -> str | None:
    ref = schema.get("$ref")
    if ref and ref.startswith(SCHEMA_PREFIX):
        return ref[len(SCHEMA_PREFIX) :]
    return None


def resolve(spec: dict, schema: dict) -> dict:
    name = ref_name(schema)
    return spec["components"]["schemas"][name] if name else schema


def accepts_null(spec: dict, schema: dict) -> bool:
    """Whether a schema accepts `null`, decided by validating `null` against it."""
    text = json.dumps(schema).replace(
        '"' + SCHEMA_PREFIX, '"urn:openapi' + SCHEMA_PREFIX
    )
    validator = jsonschema.Draft202012Validator(
        json.loads(text), registry=openapi_registry(spec)
    )
    return validator.is_valid(None)


_registries: dict[int, referencing.Registry] = {}


def openapi_registry(spec: dict) -> referencing.Registry:
    """A registry resolving `urn:openapi#/...` references into the document."""
    if id(spec) not in _registries:
        resource = referencing.Resource.from_contents(
            spec, default_specification=referencing.jsonschema.DRAFT202012
        )
        _registries[id(spec)] = referencing.Registry().with_resource(
            "urn:openapi", resource
        )
    return _registries[id(spec)]


def object_parts(spec: dict, schema: dict) -> list[dict]:
    """The object schemas a schema is composed of (allOf members, oneOf/anyOf branches)."""
    schema = resolve(spec, schema)
    parts = [schema] if "properties" in schema else []
    for key in ("allOf", "oneOf", "anyOf"):
        for branch in schema.get(key, []):
            parts.extend(object_parts(spec, branch))
    return parts


def walk_properties(spec: dict, roots: list[str]):
    """Yield (owner, property, schema) for every property reachable from the
    roots, through references, inline objects, array items, additional
    properties and combinator branches. `owner` is the enclosing component."""
    seen: set[str] = set()
    stack = list(roots)
    while stack:
        name = stack.pop()
        if name in seen:
            continue
        seen.add(name)
        pending = [spec["components"]["schemas"][name]]
        while pending:
            schema = pending.pop()
            if not isinstance(schema, dict):
                continue
            target = ref_name(schema)
            if target:
                stack.append(target)
                continue
            for key in ("allOf", "oneOf", "anyOf"):
                pending.extend(schema.get(key, []))
            for key in ("items", "additionalProperties"):
                pending.append(schema.get(key))
            for prop, prop_schema in schema.get("properties", {}).items():
                yield name, prop, prop_schema
                pending.append(prop_schema)


def json_body(response: dict) -> dict | None:
    return response.get("content", {}).get("application/json", {}).get("schema")


def check_operations(spec: dict) -> None:
    found = {(m, p) for p, ops in spec["paths"].items() for m in ops}
    if found != set(STATUS_MATRIX):
        fail("/paths", f"operations {sorted(found)} != {sorted(STATUS_MATRIX)}")
    for (method, path), statuses in STATUS_MATRIX.items():
        op = spec["paths"].get(path, {}).get(method)
        if op is None:
            continue
        pointer = f"/paths{path}/{method}"
        responses = op["responses"]
        if set(responses) != statuses:
            fail(pointer, f"statuses {sorted(responses)} != {sorted(statuses)}")
        if len(op.get("tags", [])) != 1 or op["tags"][0] not in TAGS:
            fail(
                pointer, f"tags {op.get('tags')} must be exactly one of {sorted(TAGS)}"
            )
        for status, response in responses.items():
            check_error_response(pointer, path, status, response)
            check_body(
                pointer, status, response, BODY_MATRIX[(method, path)].get(status)
            )
        check_request_body(pointer, op, REQUEST_BODY_MATRIX.get((method, path)))


def check_body(
    pointer: str, status: str, response: dict, expected: tuple | None
) -> None:
    where = f"{pointer}/responses/{status}"
    content = response.get("content")
    if expected is None:
        if content is not None:
            fail(where, f"must have no body, has {sorted(content)}")
        return
    content_type, component = expected
    if content is None or set(content) != {content_type}:
        fail(where, f"content types {sorted(content or {})} != [{content_type}]")
        return
    schema = content[content_type]["schema"]
    if component == "string":
        if schema.get("type") != "string" or "$ref" in schema:
            fail(where, "body must be an inline string")
    elif ref_name(schema) != component:
        fail(where, f"body {ref_name(schema)} != {component}")


def check_request_body(pointer: str, op: dict, expected: str | None) -> None:
    body = op.get("requestBody")
    if expected is None:
        if body is not None:
            fail(f"{pointer}/requestBody", "must have no request body")
        return
    content = (body or {}).get("content", {})
    if (
        set(content) != {JSON}
        or ref_name(content[JSON]["schema"]) != expected
        or not body.get("required")
    ):
        fail(f"{pointer}/requestBody", f"must be a required {JSON} {expected}")


def check_error_response(pointer: str, path: str, status: str, response: dict) -> None:
    if not status.startswith(("4", "5")):
        return
    where = f"{pointer}/responses/{status}"
    content = response.get("content")
    if status in ("401", "403"):
        if content is not None or response.get("description") != RESERVED:
            fail(
                where,
                "reserved 401/403 must have no content and the reserved description",
            )
        return
    if path == "/v1/health" and status == "503":
        if content is not None:
            fail(where, "health 503 must have no body")
        return
    if content is None or set(content) != {PROBLEM_JSON}:
        fail(where, f"content types {sorted(content or {})} != [{PROBLEM_JSON}]")
        return
    schema = ref_name(content[PROBLEM_JSON]["schema"])
    if status == "400":
        if schema != "Problem":
            fail(where, f"bare 400 must reference Problem, not {schema}")
    elif schema is None or not schema.endswith("Problem") or schema == "Problem":
        fail(where, f"must reference a typed problem schema, not {schema}")


def check_lists(spec: dict) -> None:
    for path, item_schema, name in [
        ("/v1/sandboxes", "SandboxDocument", "SandboxList"),
        ("/v1/sandboxes/{id}/processes", "ProcessRecord", "ProcessList"),
    ]:
        pointer = f"/paths{path}/get/responses/200"
        body = json_body(spec["paths"][path]["get"]["responses"]["200"]) or {}
        if ref_name(body) != name:
            fail(pointer, f"body must reference {name}")
            continue
        schema = spec["components"]["schemas"][name]
        items = schema.get("properties", {}).get("items", {})
        if (
            schema.get("required") != ["items"]
            or items.get("type") != "array"
            or ref_name(items.get("items", {})) != item_schema
        ):
            fail(
                f"{SCHEMA_PREFIX}{name}",
                f"must be {{items: [{item_schema}]}} with items required",
            )


def check_env(spec: dict) -> None:
    response_roots = list(EVENT_COMPONENTS)
    for ops in spec["paths"].values():
        for op in ops.values():
            for response in op["responses"].values():
                body = json_body(response)
                if body and ref_name(body):
                    response_roots.append(ref_name(body))
    for owner, prop, schema in walk_properties(spec, response_roots):
        if prop == "env" and resolve(spec, schema).get("type") != "array":
            fail(
                f"{SCHEMA_PREFIX}{owner}/properties/env",
                "read-surface env must be a list of names",
            )
    for owner, prop, schema in walk_properties(spec, REQUEST_BODIES):
        if prop == "env" and resolve(spec, schema).get("type") != "object":
            fail(
                f"{SCHEMA_PREFIX}{owner}/properties/env",
                "request env must be an object",
            )


# Expected `required` members of every object schema reachable from a
# response or event body. Keys: component, `[tag=value]` for a tagged branch
# (`*` for the unknown-tag fallback), `[anyOfN]` for other branches, and
# `/allOfN` for inline allOf members.
RESPONSE_REQUIRED = {
    "Backend": {"backend_id", "dials", "isolation_tier", "provenance"},
    "CapabilitiesResponse": {"backends", "listeners"},
    "ChangedEvent": {"at", "document", "seq"},
    "CommandSpecRead": {"command", "cwd", "env"},
    "ConfigRead": {"backend", "network"},
    "CreateConflictProblem": {"existing_id", "type"},
    "DenyDetails[anyOf0]": {"cause", "name", "port", "protocol"},
    "DenyDetails[anyOf1]": {"cause", "ip", "port", "protocol"},
    "Dial": {"dial", "known_limitations", "level", "mechanism"},
    "FlushIncompleteDetails": {"phase", "waited_ms"},
    "GapDetails": {"from", "to"},
    "HostAddressesChangedDetails": {"addresses"},
    "InternalProblem": {"type"},
    "InvalidInputProblem": {"type"},
    "Mount": {"guest_path", "host_path", "read_only"},
    "NetworkRead[mode=none]": {"mode"},
    "NetworkRead[mode=allowlist]": {"entries", "mode"},
    "NetworkRead[mode=all]": {"entries", "mode"},
    "NetworkRead[mode=*]": {"mode"},
    "NotFoundProblem": {"type"},
    "NoticeEvent[code=deny]": {"at", "code", "details", "seq"},
    "NoticeEvent[code=pin_registered]": {"at", "code", "details", "seq"},
    "NoticeEvent[code=pin_expired]": {"at", "code", "details", "seq"},
    "NoticeEvent[code=host_addresses_changed]": {"at", "code", "details", "seq"},
    "NoticeEvent[code=resync]": {"at", "code", "seq"},
    "NoticeEvent[code=flush_incomplete]": {"at", "code", "details", "seq"},
    "NoticeEvent[code=gap]": {"at", "code", "details", "seq"},
    "NoticeEvent[code=*]": {"at", "code", "seq"},
    "PatchConflictProblem": {"type"},
    "PinExpiredDetails": {"addresses", "name"},
    "PinRegisteredDetails": {"addresses", "expires_at", "name", "ports"},
    "Problem": set(),
    "ProcessConflictProblem": {"type"},
    "ProcessList": {"items"},
    "ProcessRecord": {"boot", "command_spec", "id", "interrupt_requested", "state"},
    "ProcessState[kind=running]": {"kind"},
    "ProcessState[kind=exited]": {"code", "kind"},
    "ProcessState[kind=start_failed]": {"kind", "message"},
    "ProcessState[kind=lost]": {"kind", "teardown"},
    "ProcessState[kind=*]": {"kind"},
    "Provenance": {"backend_id", "build", "kernel", "os", "schema", "version"},
    "Reason": {"code", "id"},
    "SandboxDocument": {"config", "id", "name", "namespace", "status", "version"},
    "SandboxList": {"items"},
    "Status": {"created_at", "desired", "last_transition_at", "state"},
}
TAG_MEMBERS = ("code", "kind", "mode")


def keyed_object_parts(
    name: str, schema: dict, key: str | None = None
) -> list[tuple[str, dict]]:
    """Inline object schemas within a component, keyed as in RESPONSE_REQUIRED."""
    key = key or name
    parts = (
        [(key, schema)]
        if "properties" in schema or schema.get("type") == "object"
        else []
    )
    for keyword in ("oneOf", "anyOf"):
        for i, branch in enumerate(schema.get(keyword, [])):
            if ref_name(branch):
                continue
            label = f"{keyword}{i}"
            for tag in TAG_MEMBERS:
                tag_schema = branch.get("properties", {}).get(tag)
                if tag_schema is not None:
                    label = (
                        f"{tag}={tag_schema['enum'][0]}"
                        if "enum" in tag_schema
                        else f"{tag}=*"
                    )
            parts.extend(keyed_object_parts(name, branch, f"{key}[{label}]"))
    for i, branch in enumerate(schema.get("allOf", [])):
        if not ref_name(branch):
            parts.extend(keyed_object_parts(name, branch, f"{key}/allOf{i}"))
    return parts


def referenced_components(spec: dict, roots: set[str]) -> set[str]:
    seen: set[str] = set()
    stack = list(roots)
    while stack:
        name = stack.pop()
        if name in seen:
            continue
        seen.add(name)
        pending = [spec["components"]["schemas"][name]]
        while pending:
            node = pending.pop()
            if isinstance(node, dict):
                target = ref_name(node)
                if target:
                    stack.append(target)
                pending.extend(node.values())
            elif isinstance(node, list):
                pending.extend(node)
    return seen


def response_roots(spec: dict) -> set[str]:
    roots = set(EVENT_COMPONENTS)
    for ops in spec["paths"].values():
        for op in ops.values():
            for response in op["responses"].values():
                for media in response.get("content", {}).values():
                    if ref_name(media["schema"]):
                        roots.add(ref_name(media["schema"]))
    return roots


def check_response_required(spec: dict) -> None:
    schemas = spec["components"]["schemas"]
    found = {}
    for name in referenced_components(spec, response_roots(spec)):
        for key, part in keyed_object_parts(name, schemas[name]):
            found[key] = set(part.get("required", []))
    for key in sorted(set(found) | set(RESPONSE_REQUIRED)):
        if key not in found:
            fail(key, "expected response object schema is missing")
        elif key not in RESPONSE_REQUIRED:
            fail(
                key,
                f"response object schema has no expected `required` entry (has {sorted(found[key])})",
            )
        elif found[key] != RESPONSE_REQUIRED[key]:
            fail(
                key,
                f"required {sorted(found[key])} != {sorted(RESPONSE_REQUIRED[key])}",
            )


def check_nullability(spec: dict) -> None:
    schemas = spec["components"]["schemas"]
    for owner, component in schemas.items():
        for part in object_parts(spec, component):
            for prop, schema in part.get("properties", {}).items():
                if accepts_null(spec, schema) and (owner, prop) not in NULLABLE:
                    fail(
                        f"{SCHEMA_PREFIX}{owner}/properties/{prop}",
                        "must not be nullable",
                    )
    for owner, prop in NULLABLE:
        schema = schemas[owner]["properties"][prop]
        if not accepts_null(spec, schema):
            fail(f"{SCHEMA_PREFIX}{owner}/properties/{prop}", "must be nullable")
    for owner, prop in (
        OPTIONAL_NON_NULLABLE | REQUIRED_NON_NULLABLE | {("ConfigPatch", "main")}
    ):
        required = prop in schemas[owner].get("required", [])
        should = (owner, prop) in REQUIRED_NON_NULLABLE
        if required != should:
            fail(
                f"{SCHEMA_PREFIX}{owner}/properties/{prop}",
                f"required must be {should}",
            )
    none_entries = network_variants(spec, "NetworkWrite")["none"]["properties"][
        "entries"
    ]
    if accepts_null(spec, none_entries):
        fail(f"{SCHEMA_PREFIX}NetworkWrite/none/entries", "must not be nullable")


def check_defaults(spec: dict) -> None:
    schemas = spec["components"]["schemas"]
    expected = [
        ("CreateSandboxRequest", "desired_state", "running"),
        ("ConfigCreate", "mounts", []),
        ("ConfigCreate", "env", {}),
    ]
    for owner, prop, value in expected:
        if schemas[owner]["properties"][prop].get("default", object()) != value:
            fail(
                f"{SCHEMA_PREFIX}{owner}/properties/{prop}",
                f"default must be {value!r}",
            )
    if "default" in schemas["ConfigCreate"]["properties"]["main"]:
        fail(f"{SCHEMA_PREFIX}ConfigCreate/properties/main", "must have no default")
    for name in ("NetworkWrite", "NetworkRead"):
        for mode, variant in network_variants(spec, name).items():
            if "default" in variant["properties"].get("entries", {}):
                fail(f"{SCHEMA_PREFIX}{name}/{mode}/entries", "must have no default")


def network_variants(spec: dict, name: str) -> dict[str, dict]:
    variants = {}
    for branch in spec["components"]["schemas"][name]["oneOf"]:
        mode = branch["properties"]["mode"]
        if "enum" in mode:
            variants[mode["enum"][0]] = branch
    return variants


def check_network(spec: dict) -> None:
    for name in ("NetworkWrite", "NetworkRead"):
        pointer = f"{SCHEMA_PREFIX}{name}"
        variants = network_variants(spec, name)
        if set(variants) != {"none", "allowlist", "all"}:
            fail(pointer, f"modes {sorted(variants)} != ['all', 'allowlist', 'none']")
            continue
        none = variants["none"]
        entries = resolve(spec, none["properties"].get("entries", {}))
        if "entries" in none.get("required", []) or entries.get("maxItems") != 0:
            fail(f"{pointer}/none", "entries must be optional with maxItems 0")
        for mode in ("allowlist", "all"):
            if "entries" not in variants[mode].get("required", []):
                fail(f"{pointer}/{mode}", "entries must be required")
    write_branches = len(spec["components"]["schemas"]["NetworkWrite"]["oneOf"])
    read_branches = len(spec["components"]["schemas"]["NetworkRead"]["oneOf"])
    if write_branches != 3 or read_branches != 4:
        fail(
            SCHEMA_PREFIX + "NetworkRead",
            "NetworkWrite has 3 variants, NetworkRead 3 plus a fallback",
        )


def without_descriptions(spec: dict, schema):
    """A schema with references resolved and descriptions removed, for comparison."""
    if isinstance(schema, dict):
        if ref_name(schema):
            return without_descriptions(spec, resolve(spec, schema))
        return {
            k: without_descriptions(spec, v)
            for k, v in schema.items()
            if k != "description"
        }
    if isinstance(schema, list):
        return [without_descriptions(spec, v) for v in schema]
    return schema


def check_network_parity(spec: dict) -> None:
    write = network_variants(spec, "NetworkWrite")
    read = network_variants(spec, "NetworkRead")
    for mode in ("none", "allowlist", "all"):
        if mode not in write or mode not in read:
            continue
        pointer = f"{SCHEMA_PREFIX}NetworkRead/{mode}"
        if set(write[mode].get("required", [])) != set(read[mode].get("required", [])):
            fail(pointer, "required members must match NetworkWrite")
        write_props = without_descriptions(spec, write[mode]["properties"])
        read_props = without_descriptions(spec, read[mode]["properties"])
        if write_props != read_props:
            fail(pointer, f"members {read_props} must match NetworkWrite {write_props}")


def check_notices(spec: dict) -> None:
    pointer = f"{SCHEMA_PREFIX}Notice"
    codes = {}
    for branch in spec["components"]["schemas"]["NoticeEvent"]["oneOf"]:
        code = branch["properties"]["code"]
        if "enum" in code:
            codes[code["enum"][0]] = branch
    if set(codes) != NOTICE_CODES:
        fail(pointer, f"codes {sorted(codes)} != {sorted(NOTICE_CODES)}")
    for code, branch in codes.items():
        has_details = "details" in branch["properties"]
        if has_details != (code != "resync"):
            fail(
                f"{pointer}/{code}",
                "every code except resync has details; resync has none",
            )


def check_state_filter(spec: dict) -> None:
    params = spec["paths"]["/v1/sandboxes"]["get"]["parameters"]
    state = next((p for p in params if p["name"] == "state"), None)
    expected = ["null", "stopped", "running", "destroyed"]
    if (
        state is None
        or state.get("style") != "form"
        or state.get("explode") is not False
        or state["schema"].get("type") != "array"
        or state["schema"].get("items", {}).get("enum") != expected
    ):
        fail(
            "/paths/v1/sandboxes/get/parameters/state",
            f"must be a form, non-exploded array of {expected}",
        )


def check_free_form_maps(spec: dict) -> None:
    found = set()
    for owner, prop, schema in walk_properties(spec, REQUEST_BODIES):
        target = resolve(spec, schema)
        if target.get("type") == "object" and "properties" not in target:
            found.add((owner, prop))
            pointer = f"{SCHEMA_PREFIX}{owner}/properties/{prop}"
            values = target.get("additionalProperties", True)
            if prop == "env" and values != {"type": "string"}:
                fail(
                    pointer,
                    f"env values must be strings (additionalProperties {values!r})",
                )
            if prop == "backend_options" and values not in (True, {}):
                fail(
                    pointer,
                    f"backend_options must accept any members (additionalProperties {values!r})",
                )
    if found != FREE_FORM_MAPS:
        fail(
            "request schemas",
            f"free-form map properties {sorted(found)} != {sorted(FREE_FORM_MAPS)}",
        )


CONSTRAINT_KEYWORDS = (
    "pattern",
    "minItems",
    "maxItems",
    "minimum",
    "maximum",
    "minLength",
    "maxLength",
)
MIRRORED_VALUES = [
    (("CreateSandboxRequest", "name"), ("SandboxDocument", "name")),
    (("CommandSpecWrite", "command"), ("CommandSpecRead", "command")),
    (("CommandSpecWrite", "uid"), ("CommandSpecRead", "uid")),
    (("CommandSpecWrite", "gid"), ("CommandSpecRead", "gid")),
    (("ConfigCreate", "backend_options"), ("ConfigRead", "backend_options")),
    (("ConfigCreate", "mounts"), ("ConfigRead", "mounts")),
]


def check_mirrored_constraints(spec: dict) -> None:
    schemas = spec["components"]["schemas"]
    for (write_owner, prop), (read_owner, read_prop) in MIRRORED_VALUES:
        write = schemas[write_owner]["properties"][prop]
        read = schemas[read_owner]["properties"][read_prop]
        for keyword in CONSTRAINT_KEYWORDS:
            if write.get(keyword) != read.get(keyword):
                fail(
                    f"{SCHEMA_PREFIX}{read_owner}/properties/{read_prop}",
                    f"{keyword} {read.get(keyword)!r} must match {write_owner}.{prop} ({write.get(keyword)!r})",
                )
    if schemas["CommandSpecRead"]["properties"]["command"].get("minItems") != 1:
        fail(f"{SCHEMA_PREFIX}CommandSpecRead/properties/command", "minItems must be 1")
    problem = schemas["Problem"]
    if problem["properties"].get("type", {}).get("enum") != [
        "about:blank"
    ] or "type" in problem.get("required", []):
        fail(
            f"{SCHEMA_PREFIX}Problem/properties/type",
            "must be optional and only `about:blank`",
        )


OPEN_FIELDS = [
    ("Status", "desired"),
    ("Status", "state"),
    ("Status", "teardown"),
    ("Reason", "code"),
    ("Backend", "isolation_tier"),
    ("Dial", "dial"),
    ("Dial", "level"),
    ("DenyDetails", "protocol"),
    ("DenyDetails", "cause"),
    ("FlushIncompleteDetails", "phase"),
    ("ProcessRecord", "role"),
]
OPEN_UNIONS = {"NoticeEvent": "code", "ProcessState": "kind", "NetworkRead": "mode"}


def check_open_vocabularies(spec: dict) -> None:
    schemas = spec["components"]["schemas"]
    for owner, prop in OPEN_FIELDS:
        pointer = f"{SCHEMA_PREFIX}{owner}/properties/{prop}"
        found = [
            part["properties"][prop]
            for part in object_parts(spec, schemas[owner])
            if prop in part["properties"]
        ]
        if not found:
            fail(pointer, "missing")
            continue
        schema = found[0]
        types = schema.get("type")
        if (
            "$ref" in schema
            or "enum" in schema
            or types not in ("string", ["string", "null"])
        ):
            fail(pointer, "must be an open string (no enum or reference)")
    lost_teardown = next(
        b["properties"]["teardown"]
        for b in schemas["ProcessState"]["oneOf"]
        if b["properties"]["kind"].get("enum") == ["lost"]
    )
    if "enum" in lost_teardown or lost_teardown.get("type") != "string":
        fail(f"{SCHEMA_PREFIX}ProcessState/lost/teardown", "must be an open string")
    for name, tag in OPEN_UNIONS.items():
        branches = schemas[name]["oneOf"]
        known = [
            b["properties"][tag]["enum"][0]
            for b in branches
            if "enum" in b["properties"][tag]
        ]
        fallbacks = [b for b in branches if "not" in b["properties"][tag]]
        if len(fallbacks) != 1 or fallbacks[0]["properties"][tag]["not"] != {
            "enum": known
        }:
            fail(
                f"{SCHEMA_PREFIX}{name}",
                f"must have one fallback whose {tag} excludes exactly {known}",
            )


def instance_validator(spec: dict, name: str) -> jsonschema.Draft202012Validator:
    return jsonschema.Draft202012Validator(
        {"$ref": f"urn:openapi{SCHEMA_PREFIX}{name}"},
        registry=openapi_registry(spec),
        format_checker=jsonschema.Draft202012Validator.FORMAT_CHECKER,
    )


INSTANCE_CASES = [
    ("PatchSandboxRequest", {"if_version": 9223372036854775807}, True),
    ("PatchSandboxRequest", {"if_version": 9223372036854775808}, False),
    ("PatchSandboxRequest", {"if_version": -1}, False),
    (
        "ChangedEvent",
        {"seq": 9223372036854775808, "at": "2026-10-10T00:00:00Z", "document": {}},
        False,
    ),
    (
        "PatchConflictProblem",
        {
            "type": "https://playpencil.dev/problems/conflict",
            "current_state": None,
            "required_state": "stopped",
        },
        True,
    ),
    (
        "ProcessConflictProblem",
        {
            "type": "https://playpencil.dev/problems/conflict",
            "current_state": None,
            "detail": "not ready",
        },
        True,
    ),
    (
        "ProcessConflictProblem",
        {"type": "https://playpencil.dev/problems/conflict", "current_state": 1},
        False,
    ),
    ("ProcessState", {"kind": "future_kind", "future_field": 1}, True),
    ("ProcessState", {"kind": "exited", "code": 0, "future_field": 1}, True),
    (
        "NoticeEvent",
        {"seq": 1, "at": "2026-10-10T00:00:00Z", "code": "resync", "future_field": 1},
        True,
    ),
    (
        "SandboxDocument",
        {
            "id": "s",
            "name": "sb",
            "namespace": "ns",
            "version": 1,
            "status": {
                "desired": "running",
                "state": None,
                "created_at": "2026-10-10T00:00:00Z",
                "last_transition_at": "2026-10-10T00:00:00Z",
                "future_field": 1,
            },
            "config": {"backend": "b", "network": {"mode": "none"}},
            "future_field": 1,
        },
        True,
    ),
    (
        "NoticeEvent",
        {"seq": 1, "at": "2026-10-10T00:00:00Z", "code": "flush_incomplete"},
        False,
    ),
    (
        "CommandSpecWrite",
        {"command": ["sh"], "env": {}, "cwd": "/", "uid": 4294967295, "gid": 0},
        True,
    ),
    (
        "CommandSpecWrite",
        {"command": ["sh"], "env": {}, "cwd": "/", "uid": 4294967296},
        False,
    ),
    ("CommandSpecWrite", {"command": ["sh"], "env": {}, "cwd": "/", "gid": -1}, False),
    (
        "CommandSpecRead",
        {"command": ["sh"], "env": [], "cwd": "/", "uid": 4294967295},
        True,
    ),
    (
        "CommandSpecRead",
        {"command": ["sh"], "env": [], "cwd": "/", "gid": 4294967296},
        False,
    ),
    ("NoticeEvent", {"seq": 1, "at": "yesterday", "code": "resync"}, False),
    (
        "Status",
        {
            "desired": "running",
            "state": None,
            "created_at": "2026-10-10 00:00",
            "last_transition_at": "2026-10-10T00:00:00Z",
        },
        False,
    ),
    (
        "ConfigCreate",
        {
            "backend": "x",
            "network": {"mode": "none"},
            "backend_options": {"image": {"uri": "u"}, "any": [1, {"x": None}]},
        },
        True,
    ),
    (
        "ConfigCreate",
        {"backend": "x", "network": {"mode": "none"}, "env": {"A": "1"}},
        True,
    ),
    (
        "ConfigCreate",
        {"backend": "x", "network": {"mode": "none"}, "env": {"A": 1}},
        False,
    ),
    ("ConfigPatch", {"backend_options": {"anything": True}}, True),
    ("ConfigPatch", {"env": {"A": None}}, False),
    ("CommandSpecWrite", {"command": ["sh"], "env": {"A": 1}, "cwd": "/"}, False),
    ("NetworkRead", {"mode": "allowlist", "entries": ["github.com:443"]}, True),
    ("NetworkRead", {"mode": "allowlist", "entries": [443]}, False),
    (
        "Status",
        {
            "desired": "running",
            "created_at": "2026-10-10T00:00:00Z",
            "last_transition_at": "2026-10-10T00:00:00Z",
        },
        False,
    ),
    (
        "Status",
        {
            "desired": "running",
            "state": None,
            "reason": None,
            "created_at": "2026-10-10T00:00:00Z",
            "last_transition_at": "2026-10-10T00:00:00Z",
        },
        False,
    ),
    (
        "ProcessRecord",
        {
            "id": "p",
            "boot": 1,
            "command_spec": {"command": ["sh"], "env": [], "cwd": "/"},
            "state": {"kind": "running"},
        },
        False,
    ),
    (
        "NoticeEvent",
        {"seq": 1, "at": "2026-10-10T00:00:00Z", "code": "pin_registered"},
        False,
    ),
    (
        "Status",
        {
            "desired": "future",
            "state": "future",
            "created_at": "2026-10-10T00:00:00Z",
            "last_transition_at": "2026-10-10T00:00:00Z",
            "teardown": "Future",
        },
        True,
    ),
    ("Reason", {"id": "r-1", "code": "future_reason"}, True),
    (
        "Dial",
        {
            "dial": "future_dial",
            "level": "Future",
            "mechanism": "m",
            "known_limitations": [],
        },
        True,
    ),
    (
        "Backend",
        {
            "backend_id": "b",
            "isolation_tier": "future",
            "provenance": {
                "backend_id": "b",
                "version": "v",
                "build": "b",
                "os": "o",
                "kernel": "k",
                "schema": "s",
            },
            "dials": [],
        },
        True,
    ),
    (
        "DenyDetails",
        {"ip": "192.0.2.1", "port": 1, "protocol": "future", "cause": "future"},
        True,
    ),
    ("ProcessState", {"kind": "lost", "teardown": "Future"}, True),
    (
        "NoticeEvent",
        {"seq": 1, "at": "2026-10-10T00:00:00Z", "code": "future_fact"},
        True,
    ),
    ("Problem", {}, True),
    ("Problem", {"title": "Bad Request", "status": 400}, True),
    ("Problem", {"type": "about:blank", "status": 400}, True),
    (
        "Problem",
        {"type": "https://playpencil.dev/problems/invalid_input", "status": 422},
        False,
    ),
    ("CommandSpecRead", {"command": [], "env": [], "cwd": "/"}, False),
    ("CommandSpecRead", {"command": ["sh"], "env": [], "cwd": "/"}, True),
    (
        "NoticeEvent",
        {
            "seq": 1,
            "at": "2026-10-10T00:00:00Z",
            "code": "deny",
            "details": {"port": 443, "protocol": "tcp", "cause": "unmatched"},
        },
        False,
    ),
    (
        "NoticeEvent",
        {
            "seq": 1,
            "at": "2026-10-10T00:00:00Z",
            "code": "deny",
            "details": {
                "name": "a.com",
                "port": 443,
                "protocol": "tcp",
                "cause": "unmatched",
            },
        },
        True,
    ),
    (
        "NoticeEvent",
        {
            "seq": 1,
            "at": "2026-10-10T00:00:00Z",
            "code": "deny",
            "details": {
                "ip": "192.0.2.1",
                "port": 443,
                "protocol": "tcp",
                "cause": "unmatched",
            },
        },
        True,
    ),
    (
        "NoticeEvent",
        {
            "seq": 1,
            "at": "2026-10-10T00:00:00Z",
            "code": "deny",
            "details": {
                "name": "a.com",
                "ip": "192.0.2.1",
                "port": 443,
                "protocol": "tcp",
                "cause": "unmatched",
            },
        },
        True,
    ),
    (
        "NoticeEvent",
        {
            "seq": 1,
            "at": "2026-10-10T00:00:00Z",
            "code": "flush_incomplete",
            "details": {"phase": "stop", "waited_ms": 5},
        },
        True,
    ),
    (
        "NoticeEvent",
        {
            "seq": 1,
            "at": "2026-10-10T00:00:00Z",
            "notice": {
                "code": "flush_incomplete",
                "details": {"phase": "stop", "waited_ms": 5},
            },
        },
        False,
    ),
    ("NoticeEvent", {"at": "2026-10-10T00:00:00Z", "code": "resync"}, False),
    ("NoticeEvent", {"seq": 1, "code": "resync"}, False),
    ("NoticeEvent", {"seq": 1, "at": "2026-10-10T00:00:00Z", "code": "resync"}, True),
    (
        "NoticeEvent",
        {
            "seq": 1,
            "at": "2026-10-10T00:00:00Z",
            "code": "flush_incomplete",
            "details": {"phase": "stop", "waited_ms": 5},
        },
        True,
    ),
    (
        "NoticeEvent",
        {
            "seq": 1,
            "at": "2026-10-10T00:00:00Z",
            "code": "flush_incomplete",
            "details": {"phase": "stop", "waited_ms": "x"},
        },
        False,
    ),
    (
        "NoticeEvent",
        {
            "seq": 1,
            "at": "2026-10-10T00:00:00Z",
            "code": "deny",
            "details": {"name": "a.com", "protocol": "tcp", "cause": "unmatched"},
        },
        False,
    ),
    (
        "NoticeEvent",
        {
            "seq": 1,
            "at": "2026-10-10T00:00:00Z",
            "code": "future_fact",
            "details": {"any": 1},
        },
        True,
    ),
    (
        "NoticeEvent",
        {
            "seq": 1,
            "at": "2026-10-10T00:00:00Z",
            "code": "future_fact",
            "message": None,
        },
        False,
    ),
    (
        "NoticeEvent",
        {
            "seq": 1,
            "at": "2026-10-10T00:00:00Z",
            "code": "future_fact",
            "details": None,
        },
        False,
    ),
    (
        "NoticeEvent",
        {"seq": 1, "at": "2026-10-10T00:00:00Z", "code": "future_fact", "extra": 1},
        True,
    ),
    ("ProcessState", {"kind": "exited", "code": 0}, True),
    ("ProcessState", {"kind": "lost", "teardown": "BestEffort"}, True),
    ("ProcessState", {"kind": "exited"}, False),
    ("ProcessState", {"kind": "start_failed", "message": 1}, False),
    ("ProcessState", {"kind": "lost"}, False),
    ("ProcessState", {"kind": "future_kind"}, True),
    ("ProcessState", {"kind": None}, False),
    ("ProcessState", {"kind": "future_kind", "extra": 1}, True),
    ("DenyDetails", {"port": 443, "protocol": "tcp", "cause": "unmatched"}, False),
    (
        "DenyDetails",
        {"name": "a.com", "port": 443, "protocol": "tcp", "cause": "unmatched"},
        True,
    ),
    (
        "DenyDetails",
        {"ip": "192.0.2.1", "port": 443, "protocol": "tcp", "cause": "unmatched"},
        True,
    ),
    (
        "DenyDetails",
        {
            "name": "a.com",
            "ip": "192.0.2.1",
            "port": 443,
            "protocol": "tcp",
            "cause": "unmatched",
        },
        True,
    ),
    ("NetworkRead", {"mode": "none"}, True),
    ("NetworkRead", {"mode": "none", "entries": []}, True),
    ("NetworkRead", {"mode": "none", "entries": ["a.com:1"]}, False),
    ("NetworkRead", {"mode": "allowlist"}, False),
    ("NetworkRead", {"mode": "future_mode"}, True),
    ("NetworkRead", {"mode": "future_mode", "entries": None}, False),
    ("NetworkRead", {"mode": "future_mode", "extra": 1}, True),
]


TIMESTAMPS = [
    ("ChangedEvent", "at"),
    ("NoticeEvent", "at"),
    ("Status", "created_at"),
    ("Status", "last_transition_at"),
    ("ProcessRecord", "started_at"),
    ("ProcessRecord", "exited_at"),
    ("PinRegisteredDetails", "expires_at"),
]


def check_timestamps(spec: dict) -> None:
    schemas = spec["components"]["schemas"]
    for owner, prop in TIMESTAMPS:
        found = [
            part["properties"][prop]
            for part in object_parts(spec, schemas[owner])
            if prop in part["properties"]
        ]
        if (
            not found
            or found[0].get("type") != "string"
            or found[0].get("format") != "date-time"
        ):
            fail(
                f"{SCHEMA_PREFIX}{owner}/properties/{prop}",
                "must be a string with format date-time",
            )


ID_MEMBERS = [
    (owner, prop)
    for owner in ("CommandSpecWrite", "CommandSpecRead")
    for prop in ("uid", "gid")
]


def check_ids(spec: dict) -> None:
    schemas = spec["components"]["schemas"]
    expected = {
        "type": "integer",
        "format": "int64",
        "minimum": 0,
        "maximum": 4294967295,
    }
    for owner, prop in ID_MEMBERS:
        schema = schemas[owner]["properties"][prop]
        actual = {key: schema.get(key) for key in expected}
        if actual != expected:
            fail(f"{SCHEMA_PREFIX}{owner}/properties/{prop}", f"{actual} != {expected}")


def check_no_union_in_all_of(spec: dict) -> None:
    """No allOf may reference a oneOf/anyOf component: such a union is
    distributed into its branches instead."""
    schemas = spec["components"]["schemas"]
    pending = [(f"{SCHEMA_PREFIX}{name}", schema) for name, schema in schemas.items()]
    while pending:
        pointer, node = pending.pop()
        if isinstance(node, dict):
            for item in node.get("allOf", []):
                target = ref_name(item)
                if target and (
                    "oneOf" in schemas[target] or "anyOf" in schemas[target]
                ):
                    fail(pointer, f"allOf references the union {target}")
            pending.extend((f"{pointer}/{key}", value) for key, value in node.items())
        elif isinstance(node, list):
            pending.extend((f"{pointer}/{i}", value) for i, value in enumerate(node))


TYPED_MAPS = {"EnvWrite": {"type": "string"}}


def check_open_objects(spec: dict) -> None:
    """Every object schema accepts additional members, except typed maps,
    which keep their exact value schema."""
    pending = [
        (f"{SCHEMA_PREFIX}{name}", schema)
        for name, schema in spec["components"]["schemas"].items()
    ]
    while pending:
        pointer, node = pending.pop()
        if isinstance(node, dict):
            name = pointer[len(SCHEMA_PREFIX) :]
            if node.get("type") == "object" or "properties" in node:
                expected = TYPED_MAPS.get(name, True)
                if node.get("additionalProperties") != expected:
                    fail(
                        pointer,
                        f"additionalProperties {node.get('additionalProperties')!r} != {expected!r}",
                    )
            pending.extend((f"{pointer}/{key}", value) for key, value in node.items())
        elif isinstance(node, list):
            pending.extend((f"{pointer}/{i}", value) for i, value in enumerate(node))


INT64_MAX = 9223372036854775807
COUNTERS = [
    ("PatchSandboxRequest", "if_version"),
    ("SandboxDocument", "version"),
    ("ChangedEvent", "seq"),
    ("NoticeEvent", "seq"),
    ("PatchConflictProblem", "current_version"),
    ("ProcessRecord", "boot"),
    ("FlushIncompleteDetails", "waited_ms"),
]


def check_counters(spec: dict) -> None:
    schemas = spec["components"]["schemas"]
    expected = {
        "type": "integer",
        "format": "int64",
        "minimum": 0,
        "maximum": INT64_MAX,
    }
    for owner, prop in COUNTERS:
        found = [
            part["properties"][prop]
            for part in object_parts(spec, schemas[owner])
            if prop in part["properties"]
        ]
        if not found:
            fail(f"{SCHEMA_PREFIX}{owner}/properties/{prop}", "missing")
        for schema in found:
            actual = {key: schema.get(key) for key in expected}
            if actual != expected:
                fail(
                    f"{SCHEMA_PREFIX}{owner}/properties/{prop}",
                    f"{actual} != {expected}",
                )


def check_state_filter_min_items(spec: dict) -> None:
    params = spec["paths"]["/v1/sandboxes"]["get"]["parameters"]
    state = next(p for p in params if p["name"] == "state")["schema"]
    validator = jsonschema.Draft202012Validator(state)
    if (
        state.get("minItems") != 1
        or validator.is_valid([])
        or not validator.is_valid(["running"])
    ):
        fail(
            "/paths/v1/sandboxes/get/parameters/state",
            "must require at least one state",
        )


def check_instances(spec: dict) -> None:
    validators: dict[str, jsonschema.Draft202012Validator] = {}
    for name, instance, valid in INSTANCE_CASES:
        validator = validators.setdefault(name, instance_validator(spec, name))
        if validator.is_valid(instance) != valid:
            expectation = "accept" if valid else "reject"
            fail(f"{SCHEMA_PREFIX}{name}", f"must {expectation} {json.dumps(instance)}")


def nested_request_map(spec: dict) -> None:
    mount = spec["components"]["schemas"]["Mount"]
    mount["properties"]["labels"] = {
        "type": "object",
        "properties": {
            "extra": {"type": "object", "additionalProperties": {"type": "string"}}
        },
    }


def nested_response_env(spec: dict) -> None:
    status = spec["components"]["schemas"]["Status"]
    status["properties"]["detail"] = {
        "type": "object",
        "properties": {
            "env": {"type": "object", "additionalProperties": {"type": "string"}}
        },
    }


# Mutations each check must detect; run against a copy of the document.
REGRESSION_CASES = [
    ("nested inline request map", nested_request_map, check_free_form_maps),
    ("nested response env map", nested_response_env, check_env),
]


def check_regressions(spec: dict) -> None:
    for name, mutate, check in REGRESSION_CASES:
        mutated = copy.deepcopy(spec)
        mutate(mutated)
        before = len(failures)
        check(mutated)
        detected = len(failures) > before
        del failures[before:]
        if not detected:
            fail("checker", f"{check.__name__} does not detect: {name}")


def main() -> int:
    path = sys.argv[1]
    with open(path) as f:
        spec = json.load(f)
    validate(spec)
    for check in (
        check_operations,
        check_lists,
        check_env,
        check_nullability,
        check_defaults,
        check_network,
        check_network_parity,
        check_timestamps,
        check_ids,
        check_counters,
        check_state_filter_min_items,
        check_no_union_in_all_of,
        check_open_objects,
        check_notices,
        check_state_filter,
        check_free_form_maps,
        check_mirrored_constraints,
        check_open_vocabularies,
        check_response_required,
        check_instances,
        check_regressions,
    ):
        try:
            check(spec)
        except (KeyError, IndexError, TypeError, StopIteration) as error:
            fail(check.__name__, f"unexpected document shape: {error!r}")
    if failures:
        for failure in failures:
            print(failure, file=sys.stderr)
        print(f"{path}: {len(failures)} check(s) failed", file=sys.stderr)
        return 1
    print(f"{path}: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
