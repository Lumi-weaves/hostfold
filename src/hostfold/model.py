"""Strict TOML model for a Hostfold cluster and its controller-only vault."""

from __future__ import annotations

import base64
import hashlib
import os
import re
import stat
import struct
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

try:  # Python 3.11+
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - exercised on Python 3.10
    import tomli as tomllib

from .errors import HostfoldError

NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
FINGERPRINT_RE = re.compile(r"^SHA256:[A-Za-z0-9+/]{43}$")
SAFE_AUTHORIZED_KEY_OPTIONS = {
    "no-agent-forwarding",
    "no-port-forwarding",
    "no-pty",
    "no-user-rc",
    "no-X11-forwarding",
}


@dataclass(frozen=True)
class Endpoint:
    host: str
    port: int


@dataclass(frozen=True)
class HostKey:
    kind: str
    key: str
    fingerprint: str

    @property
    def public_line(self) -> str:
        return f"{self.kind} {self.key}"


@dataclass(frozen=True)
class Node:
    name: str
    user: str
    private_keys: tuple[str, ...]
    authorized_keys: tuple[str, ...]
    endpoints: dict[str, Endpoint]
    host_keys: tuple[HostKey, ...]


@dataclass(frozen=True)
class View:
    name: str
    routes: dict[str, str]
    private_keys: tuple[str, ...] | None


@dataclass(frozen=True)
class Policy:
    authorized_key_options: tuple[str, ...]
    connect_timeout: int
    server_alive_interval: int
    server_alive_count_max: int


@dataclass(frozen=True)
class KeySpec:
    name: str
    kind: str
    generation: int
    private_file: str
    public_file: str
    fingerprint: str


@dataclass(frozen=True)
class Model:
    version: int
    view_revision: str
    controllers: tuple[str, ...]
    nodes: dict[str, Node]
    views: dict[str, View]
    policy: Policy
    keys: dict[str, KeySpec]
    config_path: Path
    vault_path: Path
    config_sha256: str
    manifest_sha256: str

    def assigned_private_keys(self, view_name: str) -> tuple[str, ...]:
        view = self.views[view_name]
        if view.private_keys is not None:
            return view.private_keys
        node = self.nodes.get(view_name)
        return node.private_keys if node else ()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def openssh_fingerprint(kind: str, encoded_key: str) -> str:
    try:
        blob = base64.b64decode(encoded_key.encode("ascii"), validate=True)
    except (ValueError, UnicodeEncodeError) as exc:
        raise HostfoldError(f"invalid base64 payload for {kind} public key") from exc
    if len(blob) < 4:
        raise HostfoldError(f"invalid OpenSSH key blob for {kind}")
    algorithm_length = struct.unpack(">I", blob[:4])[0]
    algorithm_bytes = blob[4 : 4 + algorithm_length]
    if len(algorithm_bytes) != algorithm_length:
        raise HostfoldError(f"invalid OpenSSH key blob for {kind}")
    try:
        algorithm = algorithm_bytes.decode("ascii")
    except UnicodeDecodeError as exc:
        raise HostfoldError(f"invalid OpenSSH key algorithm for {kind}") from exc
    if algorithm != kind:
        raise HostfoldError(
            f"OpenSSH key type {kind!r} does not match encoded algorithm {algorithm!r}"
        )
    digest = base64.b64encode(hashlib.sha256(blob).digest()).decode("ascii")
    return f"SHA256:{digest.rstrip('=')}"


def load_model(config_path: Path, vault_path: Path) -> Model:
    config_path = config_path.expanduser().resolve()
    vault_path = vault_path.expanduser().resolve()
    manifest_path = vault_path / "manifest.toml"
    config = _load_toml(config_path, "cluster config")
    manifest = _load_toml(manifest_path, "vault manifest")

    _only_keys(
        config,
        {"version", "view_revision", "controllers", "policy", "nodes", "views"},
        "cluster config",
    )
    _only_keys(manifest, {"version", "keys"}, "vault manifest")

    version = _integer(config.get("version"), "version")
    manifest_version = _integer(manifest.get("version"), "manifest.version")
    if version != 1 or manifest_version != 1:
        raise HostfoldError("only cluster and manifest schema version 1 are supported")

    view_revision = _string(config.get("view_revision"), "view_revision")
    controllers = _name_list(config.get("controllers", []), "controllers")
    keys = _parse_keys(_table(manifest.get("keys"), "manifest.keys"))
    nodes = _parse_nodes(_table(config.get("nodes"), "nodes"))
    views = _parse_views(_table(config.get("views"), "views"))
    policy = _parse_policy(config.get("policy", {}))

    _validate_graph(controllers, nodes, views, keys)
    model = Model(
        version=version,
        view_revision=view_revision,
        controllers=controllers,
        nodes=nodes,
        views=views,
        policy=policy,
        keys=keys,
        config_path=config_path,
        vault_path=vault_path,
        config_sha256=sha256_file(config_path),
        manifest_sha256=sha256_file(manifest_path),
    )
    validate_vault(model)
    return model


def validate_vault(model: Model) -> None:
    for key_id in sorted(model.keys):
        spec = model.keys[key_id]
        private_path = _vault_file(model.vault_path, spec.private_file, key_id, True)
        public_path = _vault_file(model.vault_path, spec.public_file, key_id, False)
        _validate_private_permissions(private_path, key_id)

        public_parts = _read_public_key(public_path, key_id)
        if public_parts[0] != spec.kind:
            raise HostfoldError(
                f"key {key_id}: manifest kind {spec.kind!r} does not match public key"
            )
        fingerprint = openssh_fingerprint(public_parts[0], public_parts[1])
        if fingerprint != spec.fingerprint:
            raise HostfoldError(
                f"key {key_id}: public fingerprint is {fingerprint}, expected "
                f"{spec.fingerprint}"
            )

        result = subprocess.run(
            ["ssh-keygen", "-y", "-P", "", "-f", os.fspath(private_path)],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode != 0:
            raise HostfoldError(
                f"key {key_id}: ssh-keygen could not read the private key "
                "non-interactively"
            )
        derived = _split_public_line(result.stdout, f"derived public key for {key_id}")
        if derived[:2] != public_parts[:2]:
            raise HostfoldError(f"key {key_id}: private and public key do not match")


def public_key_line(model: Model, key_id: str) -> str:
    spec = model.keys[key_id]
    path = _vault_file(model.vault_path, spec.public_file, key_id, False)
    kind, encoded, _ = _read_public_key(path, key_id)
    return f"{kind} {encoded} hostfold:{key_id}:generation-{spec.generation}"


def private_key_path(model: Model, key_id: str) -> Path:
    spec = model.keys[key_id]
    return _vault_file(model.vault_path, spec.private_file, key_id, True)


def _load_toml(path: Path, label: str) -> dict[str, Any]:
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise HostfoldError(f"{label} does not exist: {path}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise HostfoldError(f"invalid {label}: {exc}") from exc
    if not isinstance(data, dict):
        raise HostfoldError(f"{label} must be a TOML table")
    return data


def _parse_keys(raw: dict[str, Any]) -> dict[str, KeySpec]:
    if not raw:
        raise HostfoldError("manifest.keys must not be empty")
    keys: dict[str, KeySpec] = {}
    for name, value in raw.items():
        _name(name, f"manifest.keys.{name}")
        table = _table(value, f"manifest.keys.{name}")
        _only_keys(
            table,
            {"kind", "generation", "private_file", "public_file", "fingerprint"},
            f"manifest.keys.{name}",
        )
        keys[name] = KeySpec(
            name=name,
            kind=_string(table.get("kind"), f"keys.{name}.kind"),
            generation=_positive_integer(
                table.get("generation"), f"keys.{name}.generation"
            ),
            private_file=_relative_path(
                table.get("private_file"), f"keys.{name}.private_file"
            ),
            public_file=_relative_path(
                table.get("public_file"), f"keys.{name}.public_file"
            ),
            fingerprint=_fingerprint(
                table.get("fingerprint"), f"keys.{name}.fingerprint"
            ),
        )
    return keys


def _parse_nodes(raw: dict[str, Any]) -> dict[str, Node]:
    if not raw:
        raise HostfoldError("nodes must not be empty")
    nodes: dict[str, Node] = {}
    for name, value in raw.items():
        _name(name, f"nodes.{name}")
        table = _table(value, f"nodes.{name}")
        _only_keys(
            table,
            {
                "user",
                "private_keys",
                "authorized_keys",
                "endpoints",
                "host_keys",
            },
            f"nodes.{name}",
        )
        endpoints_raw = _table(table.get("endpoints"), f"nodes.{name}.endpoints")
        endpoints: dict[str, Endpoint] = {}
        for route, endpoint_value in endpoints_raw.items():
            _name(route, f"nodes.{name}.endpoints.{route}")
            endpoint = _table(endpoint_value, f"nodes.{name}.endpoints.{route}")
            _only_keys(endpoint, {"host", "port"}, f"nodes.{name}.endpoints.{route}")
            host = _string(endpoint.get("host"), f"nodes.{name}.{route}.host")
            if any(character.isspace() for character in host):
                raise HostfoldError(f"nodes.{name}.{route}.host contains whitespace")
            port = _integer(endpoint.get("port"), f"nodes.{name}.{route}.port")
            if not 1 <= port <= 65535:
                raise HostfoldError(f"nodes.{name}.{route}.port is outside 1..65535")
            endpoints[route] = Endpoint(host=host, port=port)
        if not endpoints:
            raise HostfoldError(f"nodes.{name}.endpoints must not be empty")

        host_keys_raw = table.get("host_keys")
        if not isinstance(host_keys_raw, list) or not host_keys_raw:
            raise HostfoldError(f"nodes.{name}.host_keys must be a non-empty array")
        host_keys: list[HostKey] = []
        for index, host_key_value in enumerate(host_keys_raw):
            label = f"nodes.{name}.host_keys[{index}]"
            host_key = _table(host_key_value, label)
            _only_keys(host_key, {"kind", "key", "fingerprint"}, label)
            kind = _string(host_key.get("kind"), f"{label}.kind")
            encoded = _string(host_key.get("key"), f"{label}.key")
            fingerprint = _fingerprint(host_key.get("fingerprint"), label)
            actual = openssh_fingerprint(kind, encoded)
            if actual != fingerprint:
                raise HostfoldError(
                    f"{label}: host fingerprint is {actual}, expected {fingerprint}"
                )
            host_keys.append(HostKey(kind, encoded, fingerprint))

        nodes[name] = Node(
            name=name,
            user=_string(table.get("user"), f"nodes.{name}.user"),
            private_keys=_name_list(
                table.get("private_keys", []), f"nodes.{name}.private_keys"
            ),
            authorized_keys=_name_list(
                table.get("authorized_keys", []), f"nodes.{name}.authorized_keys"
            ),
            endpoints=endpoints,
            host_keys=tuple(host_keys),
        )
    return nodes


def _parse_views(raw: dict[str, Any]) -> dict[str, View]:
    views: dict[str, View] = {}
    for name, value in raw.items():
        _name(name, f"views.{name}")
        table = _table(value, f"views.{name}")
        _only_keys(table, {"routes", "private_keys"}, f"views.{name}")
        routes_raw = _table(table.get("routes"), f"views.{name}.routes")
        routes = {
            _name(destination, f"views.{name}.routes.{destination}"): _name(
                route, f"views.{name}.routes.{destination}"
            )
            for destination, route in routes_raw.items()
        }
        private_keys = (
            _name_list(table["private_keys"], f"views.{name}.private_keys")
            if "private_keys" in table
            else None
        )
        views[name] = View(name=name, routes=routes, private_keys=private_keys)
    return views


def _parse_policy(value: Any) -> Policy:
    table = _table(value, "policy")
    _only_keys(
        table,
        {
            "authorized_key_options",
            "connect_timeout",
            "server_alive_interval",
            "server_alive_count_max",
        },
        "policy",
    )
    options = table.get(
        "authorized_key_options", ["no-agent-forwarding", "no-X11-forwarding"]
    )
    if not isinstance(options, list) or not all(
        isinstance(item, str) for item in options
    ):
        raise HostfoldError("policy.authorized_key_options must be an array of strings")
    if len(set(options)) != len(options):
        raise HostfoldError("policy.authorized_key_options contains duplicates")
    unknown = set(options) - SAFE_AUTHORIZED_KEY_OPTIONS
    if unknown:
        raise HostfoldError(
            "policy.authorized_key_options contains unsupported values: "
            + ", ".join(sorted(unknown))
        )
    return Policy(
        authorized_key_options=tuple(options),
        connect_timeout=_bounded_integer(
            table.get("connect_timeout", 10), "policy.connect_timeout", 1, 300
        ),
        server_alive_interval=_bounded_integer(
            table.get("server_alive_interval", 30),
            "policy.server_alive_interval",
            0,
            3600,
        ),
        server_alive_count_max=_bounded_integer(
            table.get("server_alive_count_max", 3),
            "policy.server_alive_count_max",
            1,
            100,
        ),
    )


def _validate_graph(
    controllers: tuple[str, ...],
    nodes: dict[str, Node],
    views: dict[str, View],
    keys: dict[str, KeySpec],
) -> None:
    overlap = set(controllers) & set(nodes)
    if overlap:
        raise HostfoldError(
            "controllers and nodes must be distinct: " + ", ".join(sorted(overlap))
        )
    expected_views = set(controllers) | set(nodes)
    if set(views) != expected_views:
        missing = expected_views - set(views)
        extra = set(views) - expected_views
        details = []
        if missing:
            details.append("missing " + ", ".join(sorted(missing)))
        if extra:
            details.append("unknown " + ", ".join(sorted(extra)))
        raise HostfoldError(
            "views must exactly cover controllers and nodes: " + "; ".join(details)
        )

    for node in nodes.values():
        for field, references in (
            ("private_keys", node.private_keys),
            ("authorized_keys", node.authorized_keys),
        ):
            unknown = set(references) - set(keys)
            if unknown:
                raise HostfoldError(
                    f"nodes.{node.name}.{field} references unknown keys: "
                    + ", ".join(sorted(unknown))
                )

    node_names = set(nodes)
    for view in views.values():
        if view.name in controllers and not view.private_keys:
            raise HostfoldError(
                f"controller view {view.name} must explicitly assign private_keys"
            )
        if (
            view.name in nodes
            and view.private_keys is not None
            and view.private_keys != nodes[view.name].private_keys
        ):
            raise HostfoldError(
                f"views.{view.name}.private_keys must match the node assignment"
            )
        unknown_keys = set(view.private_keys or ()) - set(keys)
        if unknown_keys:
            raise HostfoldError(
                f"views.{view.name}.private_keys references unknown keys: "
                + ", ".join(sorted(unknown_keys))
            )
        if set(view.routes) != node_names:
            missing = node_names - set(view.routes)
            extra = set(view.routes) - node_names
            details = []
            if missing:
                details.append("missing " + ", ".join(sorted(missing)))
            if extra:
                details.append("unknown " + ", ".join(sorted(extra)))
            raise HostfoldError(
                f"views.{view.name}.routes must cover every node: " + "; ".join(details)
            )
        for destination, route in view.routes.items():
            if route not in nodes[destination].endpoints:
                raise HostfoldError(
                    f"views.{view.name}.routes.{destination} selects unknown endpoint "
                    f"{route!r}"
                )


def _vault_file(vault: Path, relative: str, key_id: str, private: bool) -> Path:
    path = (vault / relative).resolve()
    try:
        path.relative_to(vault)
    except ValueError as exc:
        raise HostfoldError(f"key {key_id}: vault path escapes the vault") from exc
    if not path.is_file():
        kind = "private" if private else "public"
        raise HostfoldError(f"key {key_id}: {kind} key does not exist: {relative}")
    unresolved = vault / relative
    if unresolved.is_symlink():
        raise HostfoldError(f"key {key_id}: key files must not be symlinks")
    return path


def _validate_private_permissions(path: Path, key_id: str) -> None:
    metadata = path.stat()
    if metadata.st_uid != os.getuid():
        raise HostfoldError(
            f"key {key_id}: private key is not owned by the current user"
        )
    if not stat.S_ISREG(metadata.st_mode):
        raise HostfoldError(f"key {key_id}: private key is not a regular file")
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        raise HostfoldError(
            f"key {key_id}: private key permissions must not grant group or "
            "other access"
        )


def _read_public_key(path: Path, key_id: str) -> tuple[str, str, str]:
    try:
        line = path.read_text(encoding="utf-8").strip()
    except UnicodeDecodeError as exc:
        raise HostfoldError(f"key {key_id}: public key is not UTF-8") from exc
    return _split_public_line(line, f"public key {key_id}")


def _split_public_line(line: str, label: str) -> tuple[str, str, str]:
    parts = line.split()
    if len(parts) < 2:
        raise HostfoldError(f"{label} is not an OpenSSH public key")
    return parts[0], parts[1], " ".join(parts[2:])


def _only_keys(table: dict[str, Any], allowed: set[str], label: str) -> None:
    unknown = set(table) - allowed
    if unknown:
        raise HostfoldError(
            f"{label} contains unknown fields: {', '.join(sorted(unknown))}"
        )


def _table(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise HostfoldError(f"{label} must be a TOML table")
    return value


def _string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise HostfoldError(f"{label} must be a non-empty string")
    if "\n" in value or "\r" in value:
        raise HostfoldError(f"{label} must not contain newlines")
    return value


def _name(value: Any, label: str) -> str:
    text = _string(value, label)
    if not NAME_RE.fullmatch(text):
        raise HostfoldError(f"{label} must match {NAME_RE.pattern}")
    return text


def _name_list(value: Any, label: str) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise HostfoldError(f"{label} must be an array")
    result = tuple(_name(item, label) for item in value)
    if len(set(result)) != len(result):
        raise HostfoldError(f"{label} contains duplicates")
    return result


def _integer(value: Any, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise HostfoldError(f"{label} must be an integer")
    return value


def _positive_integer(value: Any, label: str) -> int:
    number = _integer(value, label)
    if number < 1:
        raise HostfoldError(f"{label} must be positive")
    return number


def _bounded_integer(value: Any, label: str, minimum: int, maximum: int) -> int:
    number = _integer(value, label)
    if not minimum <= number <= maximum:
        raise HostfoldError(f"{label} must be between {minimum} and {maximum}")
    return number


def _relative_path(value: Any, label: str) -> str:
    text = _string(value, label)
    path = Path(text)
    if path.is_absolute() or ".." in path.parts:
        raise HostfoldError(f"{label} must be a vault-relative path without '..'")
    return text


def _fingerprint(value: Any, label: str) -> str:
    text = _string(value, label)
    if not FINGERPRINT_RE.fullmatch(text):
        raise HostfoldError(f"{label} must be an SHA256 OpenSSH fingerprint")
    return text
