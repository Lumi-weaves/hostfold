from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass
from pathlib import Path

import pytest

from hostfold.model import openssh_fingerprint


@dataclass
class FixtureModel:
    config: Path
    vault: Path
    keys: dict[str, Path]


@pytest.fixture
def fixture_model(tmp_path: Path) -> FixtureModel:
    vault = tmp_path / "vault"
    keys_dir = vault / "keys"
    keys_dir.mkdir(parents=True)
    keys: dict[str, Path] = {}
    manifest_lines = ["version = 1", ""]
    public: dict[str, tuple[str, str, str]] = {}
    for key_id in ("controller", "alpha", "beta"):
        private = keys_dir / key_id
        subprocess.run(
            [
                "ssh-keygen",
                "-q",
                "-t",
                "ed25519",
                "-N",
                "",
                "-C",
                f"hostfold-test-{key_id}",
                "-f",
                os.fspath(private),
            ],
            check=True,
        )
        private.chmod(0o600)
        kind, encoded, *_ = private.with_suffix(".pub").read_text().split()
        fingerprint = openssh_fingerprint(kind, encoded)
        public[key_id] = (kind, encoded, fingerprint)
        keys[key_id] = private
        manifest_lines.extend(
            [
                f"[keys.{key_id}]",
                f'kind = "{kind}"',
                "generation = 1",
                f'private_file = "keys/{key_id}"',
                f'public_file = "keys/{key_id}.pub"',
                f'fingerprint = "{fingerprint}"',
                "",
            ]
        )
    (vault / "manifest.toml").write_text("\n".join(manifest_lines))

    alpha_kind, alpha_encoded, alpha_fingerprint = public["alpha"]
    beta_kind, beta_encoded, beta_fingerprint = public["beta"]
    config = tmp_path / "config.toml"
    config.write_text(
        f'''version = 1
view_revision = "test-1"
controllers = ["mac"]

[policy]
authorized_key_options = ["no-agent-forwarding", "no-X11-forwarding"]
connect_timeout = 9
server_alive_interval = 20
server_alive_count_max = 2

[nodes.alpha]
user = "alice"
private_keys = ["alpha"]
authorized_keys = ["controller", "beta"]

[nodes.alpha.endpoints.public]
host = "alpha.example.test"
port = 2201

[nodes.alpha.endpoints.private]
host = "10.0.0.1"
port = 22

[[nodes.alpha.host_keys]]
kind = "{alpha_kind}"
key = "{alpha_encoded}"
fingerprint = "{alpha_fingerprint}"

[nodes.beta]
user = "bob"
private_keys = ["beta"]
authorized_keys = ["controller", "alpha"]

[nodes.beta.endpoints.public]
host = "beta.example.test"
port = 2202

[nodes.beta.endpoints.private]
host = "10.0.0.2"
port = 22

[[nodes.beta.host_keys]]
kind = "{beta_kind}"
key = "{beta_encoded}"
fingerprint = "{beta_fingerprint}"

[views.mac]
private_keys = ["controller"]

[views.mac.routes]
alpha = "public"
beta = "public"

[views.alpha.routes]
alpha = "private"
beta = "private"

[views.beta.routes]
alpha = "private"
beta = "private"
'''
    )
    return FixtureModel(config=config, vault=vault, keys=keys)
