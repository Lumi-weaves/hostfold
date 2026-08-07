from __future__ import annotations

import pytest

from hostfold.errors import HostfoldError
from hostfold.model import load_model, openssh_fingerprint


def test_loads_strict_cluster_and_vault(fixture_model) -> None:
    model = load_model(fixture_model.config, fixture_model.vault)

    assert sorted(model.nodes) == ["alpha", "beta"]
    assert sorted(model.views) == ["alpha", "beta", "mac"]
    assert model.assigned_private_keys("mac") == ("controller",)
    assert model.assigned_private_keys("alpha") == ("alpha",)
    assert model.views["alpha"].routes["beta"] == "private"
    assert model.views["alpha"].secrets == ("demo-token",)
    assert model.views["beta"].secrets == ()


def test_rejects_group_readable_private_key(fixture_model) -> None:
    fixture_model.keys["alpha"].chmod(0o640)

    with pytest.raises(HostfoldError, match="permissions"):
        load_model(fixture_model.config, fixture_model.vault)


def test_rejects_group_readable_secret(fixture_model) -> None:
    fixture_model.secrets["demo-token"].chmod(0o640)

    with pytest.raises(HostfoldError, match="secret demo-token: permissions"):
        load_model(fixture_model.config, fixture_model.vault)


def test_rejects_symlinked_secret(fixture_model) -> None:
    secret = fixture_model.secrets["demo-token"]
    real = secret.with_name("demo-token-real")
    secret.rename(real)
    secret.symlink_to(real.name)

    with pytest.raises(HostfoldError, match="secret demo-token: file must not be"):
        load_model(fixture_model.config, fixture_model.vault)


def test_rejects_unknown_secret_assignment(fixture_model) -> None:
    content = fixture_model.config.read_text().replace(
        'secrets = ["demo-token"]', 'secrets = ["missing"]'
    )
    fixture_model.config.write_text(content)

    with pytest.raises(HostfoldError, match="unknown secrets: missing"):
        load_model(fixture_model.config, fixture_model.vault)


def test_rejects_private_public_mismatch(fixture_model) -> None:
    alpha_public = fixture_model.keys["alpha"].with_suffix(".pub")
    beta_public = fixture_model.keys["beta"].with_suffix(".pub")
    alpha_public.write_bytes(beta_public.read_bytes())

    with pytest.raises(HostfoldError, match="fingerprint|do not match"):
        load_model(fixture_model.config, fixture_model.vault)


def test_rejects_unknown_route(fixture_model) -> None:
    content = fixture_model.config.read_text().replace(
        'beta = "private"', 'beta = "missing"', 1
    )
    fixture_model.config.write_text(content)

    with pytest.raises(HostfoldError, match="unknown endpoint"):
        load_model(fixture_model.config, fixture_model.vault)


def test_allows_a_view_to_omit_unreachable_nodes(fixture_model) -> None:
    content = fixture_model.config.read_text().replace(
        '[views.beta.routes]\nalpha = "private"\nbeta = "private"',
        '[views.beta.routes]\nbeta = "private"',
    )
    fixture_model.config.write_text(content)

    model = load_model(fixture_model.config, fixture_model.vault)

    assert model.views["beta"].routes == {"beta": "private"}


def test_rejects_route_to_unknown_node(fixture_model) -> None:
    content = fixture_model.config.read_text().replace(
        "[views.beta.routes]\n", '[views.beta.routes]\nghost = "private"\n'
    )
    fixture_model.config.write_text(content)

    with pytest.raises(HostfoldError, match="unknown nodes: ghost"):
        load_model(fixture_model.config, fixture_model.vault)


def test_rejects_controller_without_explicit_key_assignment(fixture_model) -> None:
    content = fixture_model.config.read_text().replace(
        '[views.mac]\nprivate_keys = ["controller"]\n\n', ""
    )
    fixture_model.config.write_text(content)

    with pytest.raises(HostfoldError, match="controller view mac"):
        load_model(fixture_model.config, fixture_model.vault)


def test_rejects_vault_path_traversal(fixture_model) -> None:
    manifest = fixture_model.vault / "manifest.toml"
    content = manifest.read_text().replace(
        'private_file = "keys/alpha"', 'private_file = "../alpha"'
    )
    manifest.write_text(content)

    with pytest.raises(HostfoldError, match="vault-relative"):
        load_model(fixture_model.config, fixture_model.vault)


def test_rejects_key_type_that_disagrees_with_blob(fixture_model) -> None:
    _, encoded, *_ = fixture_model.keys["alpha"].with_suffix(".pub").read_text().split()

    with pytest.raises(HostfoldError, match="does not match encoded algorithm"):
        openssh_fingerprint("ssh-rsa", encoded)
