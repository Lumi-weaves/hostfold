"""Command-line interface for Hostfold controllers and bundle targets."""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path

from . import __version__
from ._install_payload import InstallError, install_bundle
from .errors import HostfoldError
from .model import load_model
from .render import render_bundle
from .transport import apply_remote


def _add_model_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--config", type=Path, default=Path("config.toml"), help="cluster TOML"
    )
    parser.add_argument(
        "--vault", type=Path, default=Path("vault"), help="controller-only vault"
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="hostfold",
        description="Compile one SSH cluster truth into safe per-host views.",
    )
    parser.add_argument("--version", action="version", version=__version__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    validate = subparsers.add_parser(
        "validate", help="validate config, graph, and vault"
    )
    _add_model_arguments(validate)

    render = subparsers.add_parser(
        "render", help="render one deterministic host bundle"
    )
    _add_model_arguments(render)
    render.add_argument("view")
    render.add_argument("--output", type=Path, required=True)

    doctor = subparsers.add_parser("doctor", help="render-check one or every view")
    _add_model_arguments(doctor)
    doctor.add_argument("views", nargs="*")
    doctor.add_argument("--json", action="store_true", dest="as_json")

    apply = subparsers.add_parser(
        "apply", help="render and install through an existing administrative SSH alias"
    )
    _add_model_arguments(apply)
    apply.add_argument("view")
    apply.add_argument("--via", required=True, help="trusted administrative SSH alias")
    apply.add_argument("--json", action="store_true", dest="as_json")

    local = subparsers.add_parser(
        "install-local", help="install an already-rendered bundle on this host"
    )
    local.add_argument("bundle", type=Path)
    local.add_argument("--home", type=Path, help=argparse.SUPPRESS)
    local.add_argument("--json", action="store_true", dest="as_json")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "validate":
            model = load_model(args.config, args.vault)
            print(
                f"valid: {len(model.nodes)} nodes, {len(model.views)} views, "
                f"{len(model.keys)} keys"
            )
            return 0

        if args.command == "render":
            model = load_model(args.config, args.vault)
            bundle = render_bundle(model, args.view, args.output)
            print(f"rendered {bundle.view} bundle {bundle.bundle_id} at {bundle.path}")
            return 0

        if args.command == "doctor":
            model = load_model(args.config, args.vault)
            views = args.views or sorted(model.views)
            unknown = set(views) - set(model.views)
            if unknown:
                raise HostfoldError("unknown views: " + ", ".join(sorted(unknown)))
            results = []
            with tempfile.TemporaryDirectory(prefix="hostfold-doctor-") as temp:
                for view in views:
                    bundle = render_bundle(
                        model, view, Path(temp) / f"{view}.hostfold-bundle"
                    )
                    results.append({"view": view, "bundle_id": bundle.bundle_id})
            if args.as_json:
                print(json.dumps(results, sort_keys=True))
            else:
                for result in results:
                    print(f"ok {result['view']} {result['bundle_id']}")
            return 0

        if args.command == "apply":
            model = load_model(args.config, args.vault)
            with tempfile.TemporaryDirectory(prefix="hostfold-apply-") as temp:
                bundle = render_bundle(
                    model, args.view, Path(temp) / f"{args.view}.hostfold-bundle"
                )
                result = apply_remote(bundle, args.via)
            if args.as_json:
                print(json.dumps(result, sort_keys=True))
            else:
                print(
                    f"installed {result['view']} bundle {result['bundle_id']} "
                    f"at {result['release']}"
                )
            return 0

        if args.command == "install-local":
            result = install_bundle(args.bundle, args.home)
            if args.as_json:
                print(json.dumps(result, sort_keys=True))
            else:
                print(
                    f"installed {result['view']} bundle {result['bundle_id']} "
                    f"at {result['release']}"
                )
            return 0
    except (HostfoldError, InstallError, OSError) as exc:
        print(f"hostfold: {exc}", file=sys.stderr)
        return 1
    raise AssertionError(f"unhandled command: {args.command}")


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
