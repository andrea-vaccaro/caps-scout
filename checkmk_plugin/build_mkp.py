#!/usr/bin/env python3
"""Assemble a Checkmk MKP for caps-scout's SNMP capability plugin.

Replicates the on-disk layout produced by cmk/mkp_tool (a gzip tar containing
``info``, ``info.json`` and a per-part ``<part>.tar``) using only the standard
library, so no running site or extra dependency is required.

Every file under ``cmk_addons/plugins/`` (Python plug-ins, and the raw agent
binaries the bakery plug-in bakes onto hosts) is packaged under the
``cmk_addons_plugins`` package part, which a site installs at
``local/lib/python3/cmk_addons/plugins/`` (see
``packages/cmk-mkp-tool/cmk/mkp_tool/_parts.py`` in the Checkmk source, which this
also mirrors for per-file permissions: executable for files directly inside a
``libexec/`` directory, read/write-only otherwise - matching real mkp packages,
harmless here since the bakery engine sets the executable bit on what it actually
deploys to a host, independently of the source file's permission on the site).

The two agent binaries the bakery plug-in bakes onto hosts
(``cmk_addons/plugins/caps_scout/agents/caps-scout`` and ``caps-scout.exe``) are
build output, not checked into the repo - this script builds them fresh from
``src/`` via ``cargo`` (native + the ``x86_64-pc-windows-gnu`` target) before
packaging, so the MKP can never ship a binary older than the source it was built
from. Pass ``--skip-agent-build`` to reuse whatever is already sitting in that
`agents/` folder instead (e.g. a CI job that already built them in an earlier step).

Usage:
    python build_mkp.py --manifest manifest.json --output caps-scout-snmp-1.0.0.mkp
"""

from __future__ import annotations

import argparse
import io
import json
import pprint
import shutil
import subprocess
import sys
import tarfile
import time
from pathlib import Path

_ALIASES = {
    "version_packaged": "version.packaged",
    "version_min_required": "version.min_required",
    "version_usable_until": "version.usable_until",
}
_REQUIRED = (
    "title",
    "name",
    "description",
    "version",
    "version.packaged",
    "version.min_required",
    "author",
    "download_url",
)
_PART_IDENT = "cmk_addons_plugins"
_PART_ROOT = Path(__file__).parent / "cmk_addons" / "plugins"
_REPO_ROOT = Path(__file__).parent.parent
_AGENTS_DIR = _PART_ROOT / "caps_scout" / "agents"
# (rustup target, release binary name)
_AGENT_BUILD_TARGETS = (
    (None, "caps-scout"),
    ("x86_64-pc-windows-gnu", "caps-scout.exe"),
)


def _build_agent_binaries() -> None:
    _AGENTS_DIR.mkdir(parents=True, exist_ok=True)
    for target, binary_name in _AGENT_BUILD_TARGETS:
        cmd = ["cargo", "build", "--release"]
        if target is not None:
            cmd += ["--target", target]
        result = subprocess.run(cmd, cwd=_REPO_ROOT)
        if result.returncode != 0:
            raise SystemExit(
                f"cargo build failed for target {target or 'native'} - see 'Building' in the "
                "top-level README (cross-compiling for Windows needs the "
                "x86_64-pc-windows-gnu rustup target and a mingw linker)"
            )

        release_dir = _REPO_ROOT / "target" / (target or "") / "release"
        built = release_dir / binary_name
        if not built.is_file():
            raise SystemExit(f"cargo build reported success but {built} is missing")

        destination = _AGENTS_DIR / binary_name
        shutil.copy2(built, destination)
        destination.chmod(0o755)


def _normalise_manifest(raw: dict) -> dict:
    out: dict = {}
    for key, value in raw.items():
        out[_ALIASES.get(key, key)] = value
    out.setdefault("version.usable_until", None)
    return out


def _permission(rel_path: Path) -> int:
    # Mirrors cmk.mkp_tool._parts.permissions() for PackagePart.CMK_ADDONS_PLUGINS.
    return 0o700 if len(rel_path.parts) > 1 and rel_path.parts[-2] == "libexec" else 0o600


def _tar_member(name: str, content: bytes, mtime: int, mode: int) -> tuple[tarfile.TarInfo, io.BytesIO]:
    info = tarfile.TarInfo(name=name)
    info.size = len(content)
    info.mtime = mtime
    info.mode = mode
    info.uid = info.gid = 0
    info.type = tarfile.REGTYPE
    return info, io.BytesIO(content)


def _build_part_tar(part_root: Path, mtime: int) -> tuple[bytes, list[Path]]:
    files = sorted(p for p in part_root.rglob("*") if p.is_file() and "__pycache__" not in p.parts)
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as tar:
        for path in files:
            rel_path = path.relative_to(part_root)
            arcname = str(rel_path)
            tinfo, fobj = _tar_member(arcname, path.read_bytes(), mtime, _permission(rel_path))
            tar.addfile(tinfo, fobj)
    return buffer.getvalue(), [p.relative_to(part_root) for p in files]


def build_mkp(manifest: dict, output: Path, mtime: int, *, skip_agent_build: bool = False) -> None:
    manifest = _normalise_manifest(manifest)

    if not skip_agent_build:
        _build_agent_binaries()

    part_tar, part_files = _build_part_tar(_PART_ROOT, mtime)
    if not part_files:
        raise SystemExit(f"no files found under {_PART_ROOT}")

    files = {part: list(items) for part, items in manifest.get("files", {}).items()}
    files[_PART_IDENT] = [str(f) for f in part_files]
    manifest["files"] = files

    missing = [key for key in _REQUIRED if not manifest.get(key)]
    if missing:
        raise SystemExit(f"manifest is missing required fields: {', '.join(missing)}")

    info_py = pprint.pformat(manifest).encode() + b"\n"
    info_json = json.dumps(manifest).encode()

    members = [
        ("info", info_py),
        ("info.json", info_json),
        (f"{_PART_IDENT}.tar", part_tar),
    ]
    with tarfile.open(name=str(output), mode="w:gz") as tar:
        for name, content in members:
            tinfo, fobj = _tar_member(name, content, mtime, 0o644)
            tar.addfile(tinfo, fobj)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path, help="JSON manifest spec")
    parser.add_argument("--output", required=True, type=Path, help="output .mkp path")
    parser.add_argument(
        "--mtime",
        type=int,
        default=int(time.time()),
        help="archive mtime (default: now; pass 0 for reproducible builds)",
    )
    parser.add_argument(
        "--skip-agent-build",
        action="store_true",
        help="reuse the binaries already in cmk_addons/plugins/caps_scout/agents/ instead of "
        "rebuilding them with cargo",
    )
    args = parser.parse_args(argv)

    if not args.manifest.is_file():
        parser.error(f"manifest not found: {args.manifest}")

    manifest = json.loads(args.manifest.read_text())
    build_mkp(manifest, args.output, args.mtime, skip_agent_build=args.skip_agent_build)
    print(f"wrote {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
