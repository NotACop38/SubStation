"""A source archive must rebuild a wheel containing every shipped rule/scenario."""

from __future__ import annotations

import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

_REPO = Path(__file__).resolve().parent.parent


def test_sdist_rebuilds_wheel_with_detection_content(tmp_path: Path) -> None:
    def build(source: Path, kind: str, out: Path) -> None:
        proc = subprocess.run(  # noqa: S603
            [sys.executable, "-m", "build", kind, "--no-isolation", "--outdir", str(out)],
            cwd=source,
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert proc.returncode == 0, proc.stdout + proc.stderr

    build(_REPO, "--sdist", tmp_path / "sdist")
    archive = next((tmp_path / "sdist").glob("*.tar.gz"))
    unpack = tmp_path / "unpack"
    with tarfile.open(archive) as tf:
        # Only regular, safe files from the archive we just built are needed.
        for member in tf.getmembers():
            name = Path(member.name)
            assert not name.is_absolute() and ".." not in name.parts
            if not member.isfile():
                continue
            data = tf.extractfile(member)
            assert data is not None
            target = unpack / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data.read())
    source = next(unpack.iterdir())
    # The source distribution must retain the protocol/backend verification gates.
    for relative in (
        "scripts/verify/dnp3-observe.zeek",
        "scripts/verify/dnp3.py",
        "tests/data/fidelity/dnp3/boundaries.yaml",
        "tests/data/fidelity/dnp3/no-responses.yaml",
        "scripts/verify/build_s7.py",
        "scripts/verify/patches/icsnpp-s7comm-bounds.patch",
        "scripts/verify/s7.py",
        "scripts/verify/sigma_backend.py",
        "tests/data/fidelity/s7/operations.yaml",
    ):
        assert (source / relative).read_bytes() == (_REPO / relative).read_bytes()
    build(source, "--wheel", tmp_path / "wheel")
    wheel = next((tmp_path / "wheel").glob("*.whl"))
    with zipfile.ZipFile(wheel) as zf:
        for tree in ("detections", "scenarios"):
            for original in (_REPO / tree).rglob("*"):
                if original.is_file() and original.suffix in {".yaml", ".yml", ".md", ".zeek"}:
                    wheel_name = "substation/content/" + str(original.relative_to(_REPO))
                    assert zf.read(wheel_name) == original.read_bytes(), wheel_name
