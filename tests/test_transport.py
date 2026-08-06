from __future__ import annotations

import json
import os
import subprocess

import pytest

from hostfold import transport
from hostfold.errors import HostfoldError
from hostfold.model import load_model
from hostfold.render import render_bundle
from hostfold.transport import _verify_remote_expansion


def test_apply_stages_under_user_state_not_cache(
    fixture_model, tmp_path, monkeypatch
) -> None:
    model = load_model(fixture_model.config, fixture_model.vault)
    bundle = render_bundle(model, "alpha", tmp_path / "bundle")
    calls: list[list[str]] = []
    remote_home = "/home/cluster-user"
    release = f"{remote_home}/.ssh/hostfold/releases/{bundle.bundle_id}"

    def fake_run(command: list[str], action: str) -> subprocess.CompletedProcess[str]:
        calls.append(command)
        if action == "install bundle":
            stdout = json.dumps(
                {"bundle_id": bundle.bundle_id, "view": bundle.view, "release": release}
            )
        elif action.startswith("expand SSH alias "):
            alias = action.rsplit(" ", 1)[-1]
            expected = bundle.receipt["ssh_hosts"][alias]
            identities = "".join(
                f"identityfile {remote_home}/.ssh/hostfold/current/keys/{item['id']}\n"
                for item in bundle.receipt["private_keys"]
            )
            stdout = (
                f"hostname {expected['hostname']}\n"
                f"port {expected['port']}\n"
                f"user {expected['user']}\n"
                f"hostkeyalias {alias}\n"
                "identitiesonly yes\n"
                "stricthostkeychecking true\n"
                f"{identities}"
                f"userknownhostsfile {remote_home}/.ssh/hostfold/current/known_hosts\n"
            )
        else:
            stdout = ""
        return subprocess.CompletedProcess(command, 0, stdout=stdout, stderr="")

    monkeypatch.setattr(transport, "_run", fake_run)

    result = transport.apply_remote(bundle, "alpha-admin")

    assert result["bundle_id"] == bundle.bundle_id
    flattened = "\n".join(" ".join(command) for command in calls)
    assert ".local/state/hostfold/incoming" in flattened
    assert ".cache/hostfold" not in flattened


def test_fresh_remote_expansion_matches_receipt(fixture_model, tmp_path) -> None:
    model = load_model(fixture_model.config, fixture_model.vault)
    bundle = render_bundle(model, "alpha", tmp_path / "bundle")
    expanded = subprocess.run(
        ["ssh", "-G", "-F", os.fspath(bundle.path / "config"), "beta"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    remote_home = "/home/cluster-user"
    expanded = expanded.replace(os.path.expanduser("~"), remote_home)

    _verify_remote_expansion(
        bundle,
        "beta",
        expanded,
        f"{remote_home}/.ssh/hostfold/releases/{bundle.bundle_id}",
    )


def test_fresh_remote_expansion_rejects_wrong_route(fixture_model, tmp_path) -> None:
    model = load_model(fixture_model.config, fixture_model.vault)
    bundle = render_bundle(model, "alpha", tmp_path / "bundle")
    expanded = subprocess.run(
        ["ssh", "-G", "-F", os.fspath(bundle.path / "config"), "beta"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    expanded = expanded.replace("hostname 10.0.0.2", "hostname wrong.example")

    with pytest.raises(HostfoldError, match="unexpected hostname"):
        _verify_remote_expansion(
            bundle,
            "beta",
            expanded,
            f"{os.path.expanduser('~')}/.ssh/hostfold/releases/{bundle.bundle_id}",
        )
