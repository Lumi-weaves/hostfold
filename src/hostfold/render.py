"""Deterministic rendering of one source host's SSH materialized view."""

from __future__ import annotations

import hashlib
import importlib.resources
import json
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import __version__
from .errors import HostfoldError
from .model import Model, private_key_path, public_key_line, sha256_file


@dataclass(frozen=True)
class Bundle:
    path: Path
    view: str
    bundle_id: str
    receipt: dict[str, Any]


def render_bundle(model: Model, view_name: str, output: Path) -> Bundle:
    if view_name not in model.views:
        raise HostfoldError(f"unknown view: {view_name}")
    output = output.expanduser().resolve()
    if output.exists():
        raise HostfoldError(f"output already exists: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(
        prefix=".hostfold-render-", dir=output.parent
    ) as temp:
        staging = Path(temp) / output.name
        staging.mkdir(mode=0o700)
        _write_bundle_files(model, view_name, staging)
        receipt = _build_receipt(model, view_name, staging)
        _write_text(
            staging / "receipt.json",
            json.dumps(receipt, indent=2, sort_keys=True) + "\n",
            0o644,
        )
        _validate_private_inventory(model, view_name, staging)
        validate_rendered_ssh(model, view_name, staging / "config")
        os.replace(staging, output)

    return Bundle(
        path=output,
        view=view_name,
        bundle_id=receipt["bundle_id"],
        receipt=receipt,
    )


def validate_rendered_ssh(model: Model, view_name: str, config_path: Path) -> None:
    view = model.views[view_name]
    expected_identities = [
        os.path.expanduser(f"~/.ssh/hostfold/current/keys/{key_id}")
        for key_id in model.assigned_private_keys(view_name)
    ]
    expected_known_hosts = os.path.expanduser("~/.ssh/hostfold/current/known_hosts")

    for destination in sorted(model.nodes):
        node = model.nodes[destination]
        endpoint = node.endpoints[view.routes[destination]]
        result = subprocess.run(
            ["ssh", "-G", "-F", os.fspath(config_path), destination],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode != 0:
            message = result.stderr.strip().splitlines()[-1:] or ["unknown error"]
            raise HostfoldError(
                f"ssh -G rejected rendered alias {destination}: {message[0]}"
            )
        expanded = _parse_ssh_g(result.stdout)
        _expect(expanded, destination, "hostname", endpoint.host)
        _expect(expanded, destination, "port", str(endpoint.port))
        _expect(expanded, destination, "user", node.user)
        _expect(expanded, destination, "hostkeyalias", destination)
        _expect(expanded, destination, "identitiesonly", "yes")
        _expect(expanded, destination, "stricthostkeychecking", "true")
        _expect(expanded, destination, "checkhostip", "no")
        _expect(expanded, destination, "updatehostkeys", "false")

        actual_identities = [
            os.path.expanduser(value) for value in expanded.get("identityfile", [])
        ]
        if actual_identities != expected_identities:
            raise HostfoldError(
                f"rendered alias {destination}: identity allowlist does not match "
                f"the {view_name} assignment"
            )
        actual_known_hosts = [
            os.path.expanduser(value)
            for value in expanded.get("userknownhostsfile", [])
        ]
        if actual_known_hosts != [expected_known_hosts]:
            raise HostfoldError(
                f"rendered alias {destination}: unexpected UserKnownHostsFile"
            )


def _write_bundle_files(model: Model, view_name: str, staging: Path) -> None:
    keys_dir = staging / "keys"
    keys_dir.mkdir(mode=0o700)
    assigned = model.assigned_private_keys(view_name)
    for key_id in assigned:
        private_target = keys_dir / key_id
        shutil.copyfile(private_key_path(model, key_id), private_target)
        private_target.chmod(0o600)
        _write_text(
            keys_dir / f"{key_id}.pub", public_key_line(model, key_id) + "\n", 0o644
        )

    _write_text(staging / "config", _render_config(model, view_name), 0o644)
    _write_text(staging / "known_hosts", _render_known_hosts(model), 0o644)
    _write_text(
        staging / "authorized_keys.block",
        _render_authorized_keys(model, view_name),
        0o644,
    )
    installer = importlib.resources.files("hostfold").joinpath("_install_payload.py")
    _write_text(staging / "install.py", installer.read_text(encoding="utf-8"), 0o755)


def _render_config(model: Model, view_name: str) -> str:
    view = model.views[view_name]
    assigned = model.assigned_private_keys(view_name)
    lines = [
        "# Generated by Hostfold. Do not edit this materialized view.",
        f"# view={view_name} revision={model.view_revision}",
        "",
    ]
    for destination in sorted(model.nodes):
        node = model.nodes[destination]
        route = view.routes[destination]
        endpoint = node.endpoints[route]
        lines.extend(
            [
                f"Host {destination}",
                f"    HostName {endpoint.host}",
                f"    Port {endpoint.port}",
                f"    User {node.user}",
            ]
        )
        for key_id in assigned:
            lines.append(f"    IdentityFile ~/.ssh/hostfold/current/keys/{key_id}")
        lines.extend(
            [
                "    IdentitiesOnly yes",
                "    PreferredAuthentications publickey",
                "    PasswordAuthentication no",
                "    KbdInteractiveAuthentication no",
                "    BatchMode yes",
                f"    HostKeyAlias {destination}",
                "    UserKnownHostsFile ~/.ssh/hostfold/current/known_hosts",
                "    GlobalKnownHostsFile /dev/null",
                "    StrictHostKeyChecking yes",
                "    CheckHostIP no",
                "    UpdateHostKeys no",
                "    ForwardAgent no",
                "    ForwardX11 no",
                "    ControlMaster no",
                "    ControlPath none",
                "    ControlPersist no",
                f"    ConnectTimeout {model.policy.connect_timeout}",
                f"    ServerAliveInterval {model.policy.server_alive_interval}",
                f"    ServerAliveCountMax {model.policy.server_alive_count_max}",
                f"    # hostfold-route {route}",
                "",
            ]
        )
    return "\n".join(lines)


def _render_known_hosts(model: Model) -> str:
    lines = ["# Generated by Hostfold. Keys are pinned to canonical aliases."]
    for node_name in sorted(model.nodes):
        for host_key in sorted(
            model.nodes[node_name].host_keys, key=lambda item: item.fingerprint
        ):
            lines.append(
                f"{node_name} {host_key.kind} {host_key.key} "
                f"hostfold:{host_key.fingerprint}"
            )
    return "\n".join(lines) + "\n"


def _render_authorized_keys(model: Model, view_name: str) -> str:
    node = model.nodes.get(view_name)
    if node is None:
        return ""
    prefix = ",".join(model.policy.authorized_key_options)
    if prefix:
        prefix += " "
    return "".join(
        f"{prefix}{public_key_line(model, key_id)}\n" for key_id in node.authorized_keys
    )


def _build_receipt(model: Model, view_name: str, staging: Path) -> dict[str, Any]:
    files: dict[str, str] = {}
    for path in sorted(staging.rglob("*")):
        if path.is_file():
            files[path.relative_to(staging).as_posix()] = sha256_file(path)
    private_keys = [
        {
            "id": key_id,
            "fingerprint": model.keys[key_id].fingerprint,
            "generation": model.keys[key_id].generation,
        }
        for key_id in model.assigned_private_keys(view_name)
    ]
    core: dict[str, Any] = {
        "schema_version": 1,
        "hostfold_version": __version__,
        "view": view_name,
        "view_revision": model.view_revision,
        "config_sha256": model.config_sha256,
        "manifest_sha256": model.manifest_sha256,
        "private_keys": private_keys,
        "canonical_hosts": sorted(model.nodes),
        "ssh_hosts": {
            destination: {
                "hostname": model.nodes[destination]
                .endpoints[model.views[view_name].routes[destination]]
                .host,
                "port": model.nodes[destination]
                .endpoints[model.views[view_name].routes[destination]]
                .port,
                "user": model.nodes[destination].user,
                "host_key_alias": destination,
            }
            for destination in sorted(model.nodes)
        },
        "files": files,
    }
    encoded = json.dumps(core, sort_keys=True, separators=(",", ":")).encode()
    core["bundle_id"] = hashlib.sha256(encoded).hexdigest()
    return core


def _validate_private_inventory(model: Model, view_name: str, staging: Path) -> None:
    expected = set(model.assigned_private_keys(view_name))
    keys_dir = staging / "keys"
    actual = {
        path.name
        for path in keys_dir.iterdir()
        if path.is_file() and not path.name.endswith(".pub")
    }
    if actual != expected:
        raise HostfoldError(
            f"staged private key inventory differs from {view_name} allowlist"
        )
    for key_id in sorted(expected):
        staged = keys_dir / key_id
        if sha256_file(staged) != sha256_file(private_key_path(model, key_id)):
            raise HostfoldError(f"staged private key {key_id} differs from vault input")
        if staged.stat().st_mode & 0o077:
            raise HostfoldError(f"staged private key {key_id} has unsafe permissions")


def _parse_ssh_g(output: str) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    for line in output.splitlines():
        key, separator, value = line.partition(" ")
        if separator:
            result.setdefault(key.lower(), []).append(value.strip())
    return result


def _expect(
    expanded: dict[str, list[str]], alias: str, key: str, expected: str
) -> None:
    actual = expanded.get(key, [])
    if actual != [expected]:
        raise HostfoldError(
            f"rendered alias {alias}: {key} expanded to {actual!r}, expected "
            f"{expected!r}"
        )


def _write_text(path: Path, content: str, mode: int) -> None:
    path.write_text(content, encoding="utf-8")
    path.chmod(mode)
