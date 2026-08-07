from __future__ import annotations

import json
import stat

from hostfold.model import load_model
from hostfold.render import render_bundle


def test_render_is_deterministic_and_key_scoped(fixture_model, tmp_path) -> None:
    model = load_model(fixture_model.config, fixture_model.vault)
    first = render_bundle(model, "alpha", tmp_path / "first")
    second = render_bundle(model, "alpha", tmp_path / "second")

    assert first.bundle_id == second.bundle_id
    assert first.receipt == second.receipt
    assert sorted(path.name for path in (first.path / "keys").iterdir()) == [
        "alpha",
        "alpha.pub",
    ]
    assert stat.S_IMODE((first.path / "keys" / "alpha").stat().st_mode) == 0o600
    assert (first.path / "secrets" / "demo-token").read_text() == (
        "sk-test-hostfold-secret\n"
    )
    assert stat.S_IMODE((first.path / "secrets" / "demo-token").stat().st_mode) == 0o600
    assert (first.path / "config").read_bytes() == (second.path / "config").read_bytes()


def test_render_selects_routes_without_changing_canonical_names(
    fixture_model, tmp_path
) -> None:
    model = load_model(fixture_model.config, fixture_model.vault)
    controller = render_bundle(model, "mac", tmp_path / "controller")
    alpha = render_bundle(model, "alpha", tmp_path / "alpha")

    controller_config = (controller.path / "config").read_text()
    alpha_config = (alpha.path / "config").read_text()
    assert "Host alpha" in controller_config
    assert "Host beta" in controller_config
    assert "HostName alpha.example.test" in controller_config
    assert "HostName 10.0.0.1" in alpha_config
    assert "HostKeyAlias alpha" in alpha_config
    assert "StrictHostKeyChecking yes" in alpha_config
    assert "UserKnownHostsFile ~/.ssh/hostfold/current/known_hosts" in alpha_config


def test_render_omits_nodes_outside_a_view_route_allowlist(
    fixture_model, tmp_path
) -> None:
    content = fixture_model.config.read_text().replace(
        '[views.beta.routes]\nalpha = "private"\nbeta = "private"',
        '[views.beta.routes]\nbeta = "private"',
    )
    fixture_model.config.write_text(content)
    model = load_model(fixture_model.config, fixture_model.vault)

    beta = render_bundle(model, "beta", tmp_path / "beta")

    assert beta.receipt["canonical_hosts"] == ["beta"]
    assert set(beta.receipt["ssh_hosts"]) == {"beta"}
    assert "Host beta" in (beta.path / "config").read_text()
    assert "Host alpha" not in (beta.path / "config").read_text()
    known_hosts = (beta.path / "known_hosts").read_text()
    assert "beta ssh-ed25519" in known_hosts
    assert "alpha ssh-ed25519" not in known_hosts


def test_receipt_contains_only_safe_provenance(fixture_model, tmp_path) -> None:
    model = load_model(fixture_model.config, fixture_model.vault)
    bundle = render_bundle(model, "alpha", tmp_path / "bundle")
    receipt = json.loads((bundle.path / "receipt.json").read_text())

    assert receipt["view"] == "alpha"
    assert receipt["private_keys"] == [
        {
            "fingerprint": model.keys["alpha"].fingerprint,
            "generation": 1,
            "id": "alpha",
        }
    ]
    assert receipt["secrets"] == [{"generation": 1, "id": "demo-token"}]
    serialized = json.dumps(receipt)
    assert fixture_model.keys["alpha"].read_text() not in serialized
    assert fixture_model.secrets["demo-token"].read_text() not in serialized
    assert set(receipt["files"]) >= {
        "config",
        "known_hosts",
        "authorized_keys.block",
        "install.py",
        "keys/alpha",
        "keys/alpha.pub",
        "secrets/demo-token",
    }


def test_render_omits_unassigned_secrets(fixture_model, tmp_path) -> None:
    model = load_model(fixture_model.config, fixture_model.vault)

    beta = render_bundle(model, "beta", tmp_path / "beta-without-secrets")

    assert beta.receipt["secrets"] == []
    assert not (beta.path / "secrets").exists()
