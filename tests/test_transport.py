from __future__ import annotations

import os
import subprocess

import pytest

from hostfold.errors import HostfoldError
from hostfold.model import load_model
from hostfold.render import render_bundle
from hostfold.transport import _verify_remote_expansion


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
