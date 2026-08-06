#!/usr/bin/env python3
"""Self-contained Hostfold bundle installer (stdlib only)."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

CONFIG_START = "# >>> hostfold managed include"
CONFIG_END = "# <<< hostfold managed include"
AUTH_START = "# >>> hostfold managed keys"
AUTH_END = "# <<< hostfold managed keys"


class InstallError(Exception):
    pass


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def install_bundle(
    bundle: Path, home: Path | None = None, *, verify_ssh: bool = True
) -> dict[str, Any]:
    bundle = Path(os.path.abspath(os.fspath(bundle.expanduser())))
    home = (home or Path.home()).expanduser().resolve()
    receipt = _load_and_verify_bundle(bundle)
    bundle_id = _safe_id(receipt.get("bundle_id"), "bundle_id")
    view = _safe_id(receipt.get("view"), "view")

    ssh_dir = home / ".ssh"
    root = ssh_dir / "hostfold"
    releases = root / "releases"
    backups = root / "backups"
    ssh_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    ssh_dir.chmod(0o700)
    root.mkdir(mode=0o700, exist_ok=True)
    releases.mkdir(mode=0o700, exist_ok=True)
    backups.mkdir(mode=0o700, exist_ok=True)

    lock_path = root / "install.lock"
    with lock_path.open("a+", encoding="utf-8") as lock:
        lock_path.chmod(0o600)
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        release = _install_release(bundle, receipt, releases, bundle_id)
        _verify_release(release, receipt)

        config_path = ssh_dir / "config"
        authorized_keys_path = ssh_dir / "authorized_keys"
        _reject_symlink(config_path)
        _reject_symlink(authorized_keys_path)
        old_config = _read_optional(config_path)
        old_authorized = _read_optional(authorized_keys_path)
        new_config = _managed_text(
            old_config,
            CONFIG_START,
            CONFIG_END,
            "Include ~/.ssh/hostfold/current/config\n",
            prepend=True,
        )
        authorization_body = (bundle / "authorized_keys.block").read_text(
            encoding="utf-8"
        )
        new_authorized = _managed_text(
            old_authorized,
            AUTH_START,
            AUTH_END,
            authorization_body,
            prepend=False,
        )

        changed = old_config != new_config or old_authorized != new_authorized
        backup_dir: Path | None = None
        if changed:
            timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            backup_dir = backups / f"{timestamp}-{bundle_id[:12]}"
            backup_dir.mkdir(mode=0o700)
            _backup_if_present(config_path, backup_dir / "config")
            _backup_if_present(authorized_keys_path, backup_dir / "authorized_keys")

        _atomic_symlink(root / "current", Path("releases") / bundle_id)
        _atomic_write(config_path, new_config, 0o600)
        _atomic_write(authorized_keys_path, new_authorized, 0o600)
        _verify_installed_inventory(release, receipt)
        if verify_ssh:
            _verify_ssh_expansions(config_path, receipt)

        installation = {
            "schema_version": 1,
            "bundle_id": bundle_id,
            "view": view,
            "installed_at": datetime.now(timezone.utc).isoformat(),
            "release": os.fspath(release),
            "backup": os.fspath(backup_dir) if backup_dir else None,
            "config_sha256": sha256_file(config_path),
            "authorized_keys_sha256": sha256_file(authorized_keys_path),
        }
        _atomic_write(
            release / "installation.json",
            json.dumps(installation, indent=2, sort_keys=True) + "\n",
            0o600,
        )
        return installation


def _load_and_verify_bundle(bundle: Path) -> dict[str, Any]:
    receipt_path = bundle / "receipt.json"
    if not bundle.is_dir() or bundle.is_symlink():
        raise InstallError("bundle must be a real directory")
    try:
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    except (FileNotFoundError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InstallError("bundle receipt is missing or invalid") from exc
    if not isinstance(receipt, dict) or receipt.get("schema_version") != 1:
        raise InstallError("unsupported bundle receipt schema")
    claimed_bundle_id = _safe_id(receipt.get("bundle_id"), "bundle_id")
    if len(claimed_bundle_id) != 64 or any(
        character not in "0123456789abcdef" for character in claimed_bundle_id
    ):
        raise InstallError("receipt bundle_id is not a lowercase SHA256 digest")
    unsigned_receipt = dict(receipt)
    del unsigned_receipt["bundle_id"]
    encoded = json.dumps(
        unsigned_receipt, sort_keys=True, separators=(",", ":")
    ).encode()
    if hashlib.sha256(encoded).hexdigest() != claimed_bundle_id:
        raise InstallError("bundle ID does not match its receipt")
    _validate_receipt_shape(receipt)
    files = receipt.get("files")
    if not isinstance(files, dict) or not files:
        raise InstallError("bundle receipt has no file inventory")

    expected = {"receipt.json"}
    for relative, expected_hash in files.items():
        path = _bundle_file(bundle, relative)
        if not isinstance(expected_hash, str) or sha256_file(path) != expected_hash:
            raise InstallError(f"bundle hash mismatch: {relative}")
        expected.add(relative)
    actual = {
        path.relative_to(bundle).as_posix()
        for path in bundle.rglob("*")
        if path.is_file()
    }
    if actual != expected:
        raise InstallError("bundle file inventory does not exactly match its receipt")
    return receipt


def _validate_receipt_shape(receipt: dict[str, Any]) -> None:
    view = _safe_id(receipt.get("view"), "view")
    private_keys = receipt.get("private_keys")
    if not isinstance(private_keys, list):
        raise InstallError("receipt private_keys must be an array")
    key_ids: list[str] = []
    for item in private_keys:
        if not isinstance(item, dict) or set(item) != {
            "id",
            "fingerprint",
            "generation",
        }:
            raise InstallError("receipt private-key entry is invalid")
        key_id = _safe_id(item.get("id"), "private key id")
        if not isinstance(item.get("fingerprint"), str) or not isinstance(
            item.get("generation"), int
        ):
            raise InstallError("receipt private-key metadata is invalid")
        key_ids.append(key_id)
    if len(set(key_ids)) != len(key_ids):
        raise InstallError("receipt private-key inventory contains duplicates")

    aliases = receipt.get("canonical_hosts")
    expectations = receipt.get("ssh_hosts")
    if not isinstance(aliases, list) or not all(
        isinstance(alias, str) and _safe_id(alias, "canonical host")
        for alias in aliases
    ):
        raise InstallError("receipt canonical_hosts must be an array of safe names")
    if len(set(aliases)) != len(aliases):
        raise InstallError("receipt canonical_hosts contains duplicates")
    if not isinstance(expectations, dict) or set(expectations) != set(aliases):
        raise InstallError("receipt SSH expectations do not cover canonical hosts")
    for alias, expected in expectations.items():
        if not isinstance(expected, dict) or set(expected) != {
            "hostname",
            "port",
            "user",
            "host_key_alias",
        }:
            raise InstallError(f"receipt SSH expectation is invalid: {alias}")
        if (
            not isinstance(expected["hostname"], str)
            or not expected["hostname"]
            or any(character.isspace() for character in expected["hostname"])
            or not isinstance(expected["user"], str)
            or not expected["user"]
            or not isinstance(expected["port"], int)
            or not 1 <= expected["port"] <= 65535
            or expected["host_key_alias"] != alias
        ):
            raise InstallError(f"receipt SSH expectation is unsafe: {alias}")

    files = receipt.get("files")
    expected_files = {
        "config",
        "known_hosts",
        "authorized_keys.block",
        "install.py",
    }
    for key_id in key_ids:
        expected_files.update({f"keys/{key_id}", f"keys/{key_id}.pub"})
    if not isinstance(files, dict) or set(files) != expected_files:
        raise InstallError(f"receipt file inventory is invalid for view {view}")


def _bundle_file(bundle: Path, relative: Any) -> Path:
    if not isinstance(relative, str):
        raise InstallError("bundle inventory paths must be strings")
    candidate = Path(relative)
    if candidate.is_absolute() or ".." in candidate.parts:
        raise InstallError("bundle inventory contains an unsafe path")
    unresolved = bundle / candidate
    if unresolved.is_symlink():
        raise InstallError(f"bundle file must not be a symlink: {relative}")
    path = unresolved.resolve()
    try:
        path.relative_to(bundle)
    except ValueError as exc:
        raise InstallError("bundle inventory path escapes the bundle") from exc
    if not path.is_file():
        raise InstallError(f"bundle file is missing: {relative}")
    return path


def _install_release(
    bundle: Path, receipt: dict[str, Any], releases: Path, bundle_id: str
) -> Path:
    release = releases / bundle_id
    if release.exists():
        if release.is_symlink() or not release.is_dir():
            raise InstallError("existing release path is not a real directory")
        return release
    temporary = releases / f".{bundle_id}.installing-{os.getpid()}"
    if temporary.exists():
        raise InstallError("stale Hostfold release staging path exists")
    temporary.mkdir(mode=0o700)
    for relative in sorted(receipt["files"]):
        source = _bundle_file(bundle, relative)
        target = temporary / relative
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        target.chmod(
            0o600
            if relative.startswith("keys/") and not relative.endswith(".pub")
            else 0o644
        )
    shutil.copyfile(bundle / "receipt.json", temporary / "receipt.json")
    (temporary / "receipt.json").chmod(0o644)
    os.replace(temporary, release)
    return release


def _verify_release(release: Path, receipt: dict[str, Any]) -> None:
    for relative, expected_hash in receipt["files"].items():
        path = release / relative
        if (
            path.is_symlink()
            or not path.is_file()
            or sha256_file(path) != expected_hash
        ):
            raise InstallError(f"installed release differs from bundle: {relative}")
    expected = set(receipt["files"]) | {"receipt.json"}
    installation = release / "installation.json"
    if installation.is_file() and not installation.is_symlink():
        expected.add("installation.json")
    actual = {
        path.relative_to(release).as_posix()
        for path in release.rglob("*")
        if path.is_file() or path.is_symlink()
    }
    if actual != expected:
        raise InstallError("installed release has an unexpected file inventory")


def _verify_installed_inventory(release: Path, receipt: dict[str, Any]) -> None:
    expected = {item["id"] for item in receipt.get("private_keys", [])}
    keys_dir = release / "keys"
    actual = {
        path.name
        for path in keys_dir.iterdir()
        if path.is_file() and not path.name.endswith(".pub")
    }
    if actual != expected:
        raise InstallError("installed private-key inventory differs from receipt")
    for key_id in actual:
        if stat.S_IMODE((keys_dir / key_id).stat().st_mode) != 0o600:
            raise InstallError(f"installed private key has unsafe mode: {key_id}")


def _managed_text(
    existing: str,
    start: str,
    end: str,
    body: str,
    *,
    prepend: bool,
) -> str:
    lines = existing.splitlines(keepends=True)
    starts = [index for index, line in enumerate(lines) if line.rstrip("\n") == start]
    ends = [index for index, line in enumerate(lines) if line.rstrip("\n") == end]
    if len(starts) != len(ends) or len(starts) > 1:
        raise InstallError(f"malformed managed block: {start}")
    if starts:
        if starts[0] >= ends[0]:
            raise InstallError(f"malformed managed block ordering: {start}")
        del lines[starts[0] : ends[0] + 1]
    remainder = "".join(lines).strip("\n")
    block = f"{start}\n{body.rstrip()}\n{end}"
    if prepend:
        return block + (f"\n\n{remainder}" if remainder else "") + "\n"
    return (f"{remainder}\n\n" if remainder else "") + block + "\n"


def _atomic_symlink(link: Path, target: Path) -> None:
    if link.exists() and not link.is_symlink():
        raise InstallError(f"refusing to replace non-symlink path: {link}")
    temporary = link.with_name(f".{link.name}.new-{os.getpid()}")
    if temporary.exists() or temporary.is_symlink():
        temporary.unlink()
    temporary.symlink_to(target)
    os.replace(temporary, link)


def _atomic_write(path: Path, content: str, mode: int) -> None:
    temporary = path.with_name(f".{path.name}.new-{os.getpid()}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor = os.open(temporary, flags, mode)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        path.chmod(mode)
    except Exception:
        if temporary.exists():
            temporary.unlink()
        raise


def _verify_ssh_expansions(config_path: Path, receipt: dict[str, Any]) -> None:
    aliases = receipt.get("canonical_hosts")
    expectations = receipt.get("ssh_hosts")
    if (
        not isinstance(aliases, list)
        or not isinstance(expectations, dict)
        or set(aliases) != set(expectations)
    ):
        raise InstallError("bundle SSH expectations are invalid")
    key_ids = [item["id"] for item in receipt.get("private_keys", [])]
    expected_identities = [
        os.fspath(Path.home() / ".ssh" / "hostfold" / "current" / "keys" / key_id)
        for key_id in key_ids
    ]
    expected_known_hosts = os.fspath(
        Path.home() / ".ssh" / "hostfold" / "current" / "known_hosts"
    )
    for alias in aliases:
        result = subprocess.run(
            ["ssh", "-G", "-F", os.fspath(config_path), alias],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode != 0:
            raise InstallError(f"installed SSH config does not expand alias: {alias}")
        expanded = _parse_ssh_g(result.stdout)
        expected = expectations[alias]
        for key, value in (
            ("hostname", expected["hostname"]),
            ("port", str(expected["port"])),
            ("user", expected["user"]),
            ("hostkeyalias", expected["host_key_alias"]),
            ("identitiesonly", "yes"),
            ("stricthostkeychecking", "true"),
        ):
            if expanded.get(key) != [value]:
                raise InstallError(f"installed SSH alias {alias} has unexpected {key}")
        actual_identities = [
            _expand_ssh_home(value) for value in expanded.get("identityfile", [])
        ]
        if actual_identities != expected_identities:
            raise InstallError(
                f"installed SSH alias {alias} has an unexpected identity allowlist"
            )
        actual_known_hosts = [
            _expand_ssh_home(value) for value in expanded.get("userknownhostsfile", [])
        ]
        if actual_known_hosts != [expected_known_hosts]:
            raise InstallError(
                f"installed SSH alias {alias} has an unexpected known-hosts file"
            )


def _parse_ssh_g(output: str) -> dict[str, list[str]]:
    parsed: dict[str, list[str]] = {}
    for line in output.splitlines():
        key, separator, value = line.partition(" ")
        if separator:
            parsed.setdefault(key.lower(), []).append(value.strip())
    return parsed


def _expand_ssh_home(value: str) -> str:
    if value == "~":
        return os.fspath(Path.home())
    if value.startswith("~/"):
        return os.fspath(Path.home() / value[2:])
    return value


def _backup_if_present(source: Path, target: Path) -> None:
    if source.exists():
        shutil.copy2(source, target)
        target.chmod(0o600)


def _read_optional(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return ""
    except UnicodeDecodeError as exc:
        raise InstallError(f"existing SSH file is not UTF-8: {path}") from exc


def _reject_symlink(path: Path) -> None:
    if path.is_symlink():
        raise InstallError(f"refusing to manage symlink: {path}")


def _safe_id(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or not all(character.isalnum() or character in "._-" for character in value)
    ):
        raise InstallError(f"receipt {label} is invalid")
    return value


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", type=Path, default=Path(__file__).resolve().parent)
    parser.add_argument("--home", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        installation = install_bundle(args.bundle, args.home)
    except (InstallError, OSError, subprocess.SubprocessError) as exc:
        print(f"hostfold install: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(installation, sort_keys=True))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
