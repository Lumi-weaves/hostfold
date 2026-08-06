from __future__ import annotations

import json
import stat

import pytest

from hostfold._install_payload import (
    AUTH_END,
    AUTH_START,
    CONFIG_END,
    CONFIG_START,
    InstallError,
    install_bundle,
)
from hostfold.model import load_model
from hostfold.render import render_bundle


def test_install_preserves_unmanaged_ssh_state_and_is_idempotent(
    fixture_model, tmp_path
) -> None:
    model = load_model(fixture_model.config, fixture_model.vault)
    bundle = render_bundle(model, "alpha", tmp_path / "bundle")
    home = tmp_path / "home"
    ssh = home / ".ssh"
    ssh.mkdir(parents=True)
    (ssh / "config").write_text("Host existing\n    HostName existing.test\n")
    (ssh / "authorized_keys").write_text("ssh-ed25519 AAAAunmanaged existing\n")

    first = install_bundle(bundle.path, home, verify_ssh=False)
    config = (ssh / "config").read_text()
    authorized = (ssh / "authorized_keys").read_text()
    assert config.startswith(CONFIG_START)
    assert "Host existing" in config
    assert config.count(CONFIG_START) == config.count(CONFIG_END) == 1
    assert "ssh-ed25519 AAAAunmanaged existing" in authorized
    assert authorized.count(AUTH_START) == authorized.count(AUTH_END) == 1
    assert "hostfold:controller:generation-1" in authorized
    assert "hostfold:beta:generation-1" in authorized
    current = ssh / "hostfold" / "current"
    assert current.is_symlink()
    release = current.resolve()
    assert sorted(path.name for path in (release / "keys").iterdir()) == [
        "alpha",
        "alpha.pub",
    ]
    assert stat.S_IMODE((release / "keys" / "alpha").stat().st_mode) == 0o600
    assert first["backup"] is not None

    second = install_bundle(bundle.path, home, verify_ssh=False)
    assert second["bundle_id"] == first["bundle_id"]
    assert second["backup"] is None
    assert (ssh / "config").read_text().count(CONFIG_START) == 1
    assert (ssh / "authorized_keys").read_text().count(AUTH_START) == 1


def test_install_rejects_tampered_bundle(fixture_model, tmp_path) -> None:
    model = load_model(fixture_model.config, fixture_model.vault)
    bundle = render_bundle(model, "beta", tmp_path / "bundle")
    with (bundle.path / "config").open("a") as handle:
        handle.write("# tampered\n")

    with pytest.raises(InstallError, match="hash mismatch"):
        install_bundle(bundle.path, tmp_path / "home", verify_ssh=False)


def test_installation_receipt_does_not_contain_private_key(
    fixture_model, tmp_path
) -> None:
    model = load_model(fixture_model.config, fixture_model.vault)
    bundle = render_bundle(model, "alpha", tmp_path / "bundle")
    home = tmp_path / "home"
    result = install_bundle(bundle.path, home, verify_ssh=False)
    installation = json.loads(
        (home / ".ssh" / "hostfold" / "current" / "installation.json").read_text()
    )

    assert installation["bundle_id"] == result["bundle_id"]
    assert fixture_model.keys["alpha"].read_text() not in json.dumps(installation)


def test_install_rejects_symlink_to_bundle(fixture_model, tmp_path) -> None:
    model = load_model(fixture_model.config, fixture_model.vault)
    bundle = render_bundle(model, "alpha", tmp_path / "bundle")
    link = tmp_path / "bundle-link"
    link.symlink_to(bundle.path, target_is_directory=True)

    with pytest.raises(InstallError, match="real directory"):
        install_bundle(link, tmp_path / "home", verify_ssh=False)


def test_install_rejects_receipt_with_forged_bundle_id(fixture_model, tmp_path) -> None:
    model = load_model(fixture_model.config, fixture_model.vault)
    bundle = render_bundle(model, "beta", tmp_path / "bundle")
    receipt_path = bundle.path / "receipt.json"
    receipt = json.loads(receipt_path.read_text())
    receipt["bundle_id"] = "0" * 64
    receipt_path.write_text(json.dumps(receipt))

    with pytest.raises(InstallError, match="bundle ID"):
        install_bundle(bundle.path, tmp_path / "home", verify_ssh=False)
