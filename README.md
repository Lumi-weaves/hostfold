# Hostfold

**One cluster. One vocabulary. A safe view for every host.**

Hostfold compiles one controller-owned SSH topology into a different, minimal
materialized view for each machine. Every view exposes the same canonical host
names, while choosing routes at render time and carrying only the private keys
explicitly assigned to that source machine.

```text
controller truth + local key vault
             │
             ├── render mac view ─────── canonical names, public routes
             ├── render alpha view ───── canonical names, private routes
             └── render beta view ────── canonical names, private routes
```

After installation, users and agents simply run `ssh alpha` or `ssh beta`.
They do not need to know which route was selected for the machine they are on.

> [!WARNING]
> Hostfold is alpha software. Read the rendered bundle and test it on disposable
> accounts before using it for important infrastructure.

## What it does

- validates a strict TOML topology and a controller-local vault manifest;
- verifies every private/public key pair and pinned host-key fingerprint;
- fails closed when a view's route or private-key allowlist is incomplete;
- renders deterministic, hash-inventoried bundles;
- installs into a bounded `~/.ssh/hostfold` directory;
- updates only marked blocks in `~/.ssh/config` and
  `~/.ssh/authorized_keys`, preserving unrelated entries;
- applies through an already-working administrative SSH alias, then verifies
  the canonical aliases from a fresh session.

Hostfold is intentionally **not** a daemon, overlay network, secret manager,
SSH certificate authority, route failover system, or inventory discovery
service. Remote hosts receive materialized views; they never become a source of
truth and never redistribute keys.

## Requirements

- Python 3.10 or newer on the controller;
- OpenSSH client tools (`ssh`, `ssh-keygen`, and `scp`);
- Python 3 on target machines for the self-contained installer;
- unencrypted automation keys: validation uses `ssh-keygen -y -P ""`
  non-interactively.

## Install for development

```console
$ git clone https://github.com/Lumi-weaves/hostfold.git
$ cd hostfold
$ uv sync --dev
$ uv run hostfold --help
```

The published package can later be installed with `pipx install hostfold` once
releases are available.

## Controller layout

Keep topology and secrets separate. The public Hostfold project does not need
your deployment repository or vault.

```text
cluster/
├── config.toml          # may live in a private, controller-only Git repo
└── vault/               # never commit
    ├── manifest.toml
    └── keys/
        ├── mac-a
        ├── mac-a.pub
        ├── alpha
        └── alpha.pub
```

`examples/config.toml` and `examples/manifest.toml` document schema version 1.
Host-key and public-key values in those files are deliberately placeholders.

## Workflow

### 1. Record keys and topology

Generate each key on a trusted controller and record its files and fingerprint
in `vault/manifest.toml`. Private keys must be regular, non-symlink files with
no group or other permissions.

For each node, declare:

- which private key(s) that node may hold;
- which public keys its `authorized_keys` managed block accepts;
- all possible endpoints;
- one or more pinned SSH host keys.

For each source-machine view, map every canonical destination to one endpoint
name. Controller views also declare their private-key allowlist explicitly.

### 2. Validate everything before transfer

```console
$ hostfold validate --config config.toml --vault vault
$ hostfold doctor --config config.toml --vault vault
```

`doctor` renders every view into a temporary directory and asks `ssh -G` to
verify the effective hostname, port, user, identity allowlist, and host-key
policy.

### 3. Inspect a bundle

```console
$ hostfold render alpha \
    --config config.toml \
    --vault vault \
    --output alpha.hostfold-bundle
```

The bundle includes generated SSH configuration, pinned `known_hosts`, the
target's managed `authorized_keys` body, a self-contained installer, an exact
receipt, and only the private keys assigned to `alpha`.

### 4. Apply through an existing administrative route

```console
$ hostfold apply alpha \
    --via alpha-admin \
    --config config.toml \
    --vault vault
```

`--via` is deliberately separate from the canonical Hostfold name. It is the
already-trusted bootstrap route used to install the new view; Hostfold neither
discovers nor rewrites it.

For a local or manually transferred bundle:

```console
$ hostfold install-local alpha.hostfold-bundle
```

## Result on a target

```text
~/.ssh/
├── config                    # one Hostfold include block + existing content
├── authorized_keys           # one Hostfold key block + existing content
└── hostfold/
    ├── current -> releases/<bundle-id>
    ├── releases/<bundle-id>/
    ├── backups/
    └── install.lock
```

The managed include is intentionally placed first because OpenSSH uses the
first obtained value for each parameter. Generated host blocks use
`IdentitiesOnly yes`, a dedicated `UserKnownHostsFile`, pinned canonical
`HostKeyAlias` values, and `StrictHostKeyChecking yes`.

## Security boundary

Hostfold assumes its controller and vault are trusted. It reduces accidental
secret spread; it cannot protect secrets after a controller or assigned node is
compromised.

Its central invariant is:

```text
private keys in rendered view V == explicitly allowed private keys for V
```

The renderer and installer independently check that inventory. Bundles also
carry hashes for every file, and installation refuses unexpected, missing,
symlinked, or modified files. Treat rendered bundles as secrets and remove
controller-side bundle directories after inspection or transfer.

Hostfold does not fetch host keys from the network. Obtain and verify them
through an independent trusted channel before adding them to the topology.
See `SECURITY.md` for reporting and operational guidance.

## Design notes

- Configuration selects routes at compile time; runtime names stay canonical.
- The vault manifest records key generations and fingerprints, while key bytes
  remain outside the topology file.
- Releases are content-addressed by a deterministic bundle ID.
- Existing SSH entry points remain outside Hostfold's marked blocks, allowing a
  gradual migration and a separate recovery path.

The safety settings are grounded in the OpenBSD project's contracts for
[`ssh_config`](https://man.openbsd.org/ssh_config),
[`sshd`/`authorized_keys`](https://man.openbsd.org/sshd), and
[`ssh-keygen`](https://man.openbsd.org/ssh-keygen).

## Contributing

Small, reviewable changes are welcome. Please read `CONTRIBUTING.md` and do not
include real hostnames, usernames, public keys, fingerprints, or private
deployment topology in examples or reports.

## License

MIT © Lumi
