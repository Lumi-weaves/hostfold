# Security

Hostfold handles SSH private keys. Treat every release as security-sensitive.

Please report vulnerabilities privately to `lumi_tian@qq.com`. Do not attach
private keys, real vaults, credentials, or credential-bearing logs. A minimal
synthetic reproducer is preferred.

Hostfold's useful security boundary assumes that the controller running it is
trusted. It limits which private keys reach each rendered host, pins server
host keys, and preserves unmanaged SSH state; it is not a general secret
manager and cannot protect a vault after controller compromise.
