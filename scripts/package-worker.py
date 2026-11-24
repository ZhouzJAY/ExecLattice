"""Build and verify a standalone Windows LAN worker."""

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path

from release_artifacts import ArtifactReviewError, verify_worker
from release_source import SourcePrivacyError, read_private_terms, read_reviewed_source, stage_reviewed_source


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scratch-root", type=Path, required=True)
    parser.add_argument("--deny-term-file", type=Path, help="Optional private terms file outside this source tree")
    args = parser.parse_args()
    project = Path(__file__).resolve().parents[1]
    private_terms = read_private_terms(project, args.deny_term_file)
    with tempfile.TemporaryDirectory(prefix="execlattice-lan-freeze-", dir=args.scratch_root) as folder:
        work = Path(folder)
        source = work / "source"
        stage_reviewed_source(project, source, private_terms)
        reviewed = read_reviewed_source(source, private_terms)
        version = tomllib.loads(reviewed["pyproject.toml"].decode("utf-8"))["project"]["version"]
        destination = project / "dist" / f"ExecLattice-LAN-Worker-{version}.exe"
        if destination.exists():
            raise SystemExit("A worker build already exists for this version")
        environment = {
            **os.environ,
            "TEMP": folder,
            "TMP": folder,
            "PYTHONPATH": str(source / "src"),
            "PYINSTALLER_CONFIG_DIR": str(work / "cache"),
        }
        spec = work / "worker.spec"
        spec.write_text(
            f"""from pathlib import Path

a = Analysis([{str(source / 'scripts' / 'worker-entry.py')!r}],
             pathex=[{str(source / 'src')!r}],
             excludes=['mcp', 'fastapi', 'uvicorn', 'PIL', 'asyncssh', 'pytest', '_pytest',
                       'pydantic.mypy', 'rich', 'pygments', 'IPython', 'watchfiles',
                       'websockets', 'opentelemetry'])
a.binaries = [item for item in a.binaries
              if not Path(item[0]).name.lower().startswith(('api-ms-win-', 'ext-ms-win-'))
              and Path(item[0]).name.lower() != 'ucrtbase.dll']
pyz = PYZ(a.pure)
exe = EXE(pyz, a.scripts, a.binaries, a.datas,
          name={destination.stem!r}, console=True, upx=False)
""",
            encoding="utf-8",
        )
        command = [
            sys.executable, "-m", "PyInstaller", "--distpath", str(work / "dist"),
            "--workpath", str(work / "build"), str(spec),
        ]
        build = subprocess.run(command, cwd=source, env=environment, capture_output=True)
        if build.returncode:
            raise SystemExit(f"Worker build failed with exit code {build.returncode}.")
        executable = work / "dist" / destination.name
        check = subprocess.run([str(executable), "--help"], cwd=work, env=environment,
                               capture_output=True, text=True, timeout=35)
        if check.returncode or "init-worker" not in check.stdout:
            raise SystemExit("Frozen worker did not display its supported commands")
        verify_worker(executable, reviewed, private_terms)
        destination.parent.mkdir(exist_ok=True)
        with executable.open("rb") as source_file, destination.open("xb") as output:
            shutil.copyfileobj(source_file, output)
    with destination.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    print(json.dumps({"file": destination.name, "sha256": digest,
                      "size_bytes": destination.stat().st_size}))


if __name__ == "__main__":
    try:
        main()
    except (SourcePrivacyError, ArtifactReviewError) as error:
        raise SystemExit(f"Worker release review failed. {error}") from None
    except (OSError, ValueError, ImportError, subprocess.TimeoutExpired):
        raise SystemExit("Worker build or review could not complete.") from None
