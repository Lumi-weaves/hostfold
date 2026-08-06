"""Bounded controller-to-host bundle transfer over an existing SSH route."""

from __future__ import annotations

import json
import os
import re
import subprocess
import tarfile
import tempfile
from pathlib import Path
from typing import Any

from .errors import HostfoldError
from .render import Bundle

ADMIN_ALIAS_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
REMOTE_INCOMING_ROOT = ".local/state/hostfold/incoming"


def apply_remote(bundle: Bundle, admin_alias: str) -> dict[str, Any]:
    if not ADMIN_ALIAS_RE.fullmatch(admin_alias):
        raise HostfoldError("administrative SSH alias contains unsafe characters")
    remote_root = f"{REMOTE_INCOMING_ROOT}/{bundle.bundle_id}"
    ssh = [
        "ssh",
        "-T",
        "-o",
        "BatchMode=yes",
        "-o",
        "ConnectTimeout=10",
        "-o",
        "ConnectionAttempts=1",
        admin_alias,
    ]
    scp = [
        "scp",
        "-q",
        "-o",
        "BatchMode=yes",
        "-o",
        "ConnectTimeout=10",
    ]

    _run(ssh + [f'umask 077; mkdir -p "$HOME/{remote_root}"'], "prepare remote")
    with tempfile.TemporaryDirectory(prefix="hostfold-apply-") as temp:
        archive = Path(temp) / "bundle.tar.gz"
        with tarfile.open(archive, "w:gz") as handle:
            handle.add(bundle.path, arcname="bundle", recursive=True)
        _run(
            scp + [os.fspath(archive), f"{admin_alias}:{remote_root}/bundle.tar.gz"],
            "transfer bundle",
        )

    install_command = (
        f'cd "$HOME/{remote_root}" && '
        "mkdir -p bundle && "
        "tar -xzf bundle.tar.gz -C . && "
        "python3 bundle/install.py --bundle bundle"
    )
    installed = _run(ssh + [install_command], "install bundle")
    try:
        result = json.loads(installed.stdout.strip().splitlines()[-1])
    except (IndexError, json.JSONDecodeError) as exc:
        raise HostfoldError("remote installer did not return a valid receipt") from exc
    if result.get("bundle_id") != bundle.bundle_id or result.get("view") != bundle.view:
        raise HostfoldError(
            "remote installation receipt does not match the staged bundle"
        )

    for alias in bundle.receipt["canonical_hosts"]:
        expanded = _run(ssh + [f"ssh -G {alias}"], f"expand SSH alias {alias}")
        _verify_remote_expansion(bundle, alias, expanded.stdout, result["release"])
    return result


def _verify_remote_expansion(
    bundle: Bundle, alias: str, output: str, release: str
) -> None:
    parsed: dict[str, list[str]] = {}
    for line in output.splitlines():
        key, separator, value = line.partition(" ")
        if separator:
            parsed.setdefault(key.lower(), []).append(value.strip())
    expected = bundle.receipt["ssh_hosts"][alias]
    for key, value in (
        ("hostname", expected["hostname"]),
        ("port", str(expected["port"])),
        ("user", expected["user"]),
        ("hostkeyalias", expected["host_key_alias"]),
        ("identitiesonly", "yes"),
        ("stricthostkeychecking", "true"),
    ):
        if parsed.get(key) != [value]:
            raise HostfoldError(
                f"fresh SSH alias {alias} has unexpected {key}: {parsed.get(key, [])!r}"
            )

    marker = "/.ssh/hostfold/releases/"
    if marker not in release:
        raise HostfoldError(
            "remote installation receipt has an unexpected release path"
        )
    remote_home = release.split(marker, 1)[0]
    expected_identities = [
        f"{remote_home}/.ssh/hostfold/current/keys/{item['id']}"
        for item in bundle.receipt["private_keys"]
    ]
    actual_identities = [
        _expand_remote_home(value, remote_home)
        for value in parsed.get("identityfile", [])
    ]
    if actual_identities != expected_identities:
        raise HostfoldError(
            f"fresh SSH alias {alias} has an unexpected identity allowlist: "
            f"{parsed.get('identityfile', [])!r}"
        )
    expected_known_hosts = f"{remote_home}/.ssh/hostfold/current/known_hosts"
    actual_known_hosts = [
        _expand_remote_home(value, remote_home)
        for value in parsed.get("userknownhostsfile", [])
    ]
    if actual_known_hosts != [expected_known_hosts]:
        raise HostfoldError(
            f"fresh SSH alias {alias} has an unexpected known-hosts file"
        )


def _expand_remote_home(value: str, remote_home: str) -> str:
    if value == "~":
        return remote_home
    if value.startswith("~/"):
        return f"{remote_home}/{value[2:]}"
    return value


def _run(command: list[str], action: str) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        command,
        check=False,
        capture_output=True,
        text=True,
        timeout=120,
    )
    if result.returncode != 0:
        detail = result.stderr.strip().splitlines()[-1:] or ["unknown error"]
        raise HostfoldError(f"could not {action}: {detail[0]}")
    return result
