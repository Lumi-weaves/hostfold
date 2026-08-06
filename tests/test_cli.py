from __future__ import annotations

import subprocess

from hostfold import cli


def test_cli_reports_subprocess_timeout_without_traceback(monkeypatch, capsys) -> None:
    def timeout(*_args, **_kwargs):
        raise subprocess.TimeoutExpired(["ssh-keygen"], 10)

    monkeypatch.setattr(cli, "load_model", timeout)

    assert cli.main(["validate"]) == 1
    assert "timed out" in capsys.readouterr().err
