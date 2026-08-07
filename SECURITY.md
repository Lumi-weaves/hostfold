# Security

Hostfold handles SSH private keys and optional opaque secret files. Treat every
release as security-sensitive.

Please report vulnerabilities privately to `lumi_tian@qq.com`. Do not attach
private keys, real vaults, credentials, or credential-bearing logs. A minimal
synthetic reproducer is preferred.

Hostfold's useful security boundary assumes that the controller running it is
trusted. It limits which private keys reach each rendered host, pins server
host keys, scopes low-risk secret files to explicit view allowlists, and
preserves unmanaged SSH state. It is not a general secret manager and cannot
protect a vault after controller compromise. Do not use its opaque-file feature
for high-value or independently revocable production credentials without a
dedicated secret-management system.
