"""Verify distribution contents against the reviewed source files."""

from __future__ import annotations

import argparse
import marshal
import re
import tomllib
from email.parser import BytesParser
from email.policy import default
from pathlib import Path, PurePosixPath, PureWindowsPath
from types import CodeType
from zipfile import ZipFile

from release_source import (
    LICENSE_FILES,
    SourcePrivacyError,
    check_public_text,
    read_private_terms,
    read_reviewed_source,
)

_WHEEL_RECORDS = {"METADATA", "WHEEL", "RECORD", "entry_points.txt", "top_level.txt"}
_RUNTIME_FILES = re.compile(r"(?i)(?:^|/)(?:\.env[^/]*|[^/]+\.(?:key|pfx|p12|log|sqlite3(?:-wal|-shm)?))$")
_NATIVE_STRINGS = (re.compile(rb"[\x20-\x7e]{12,}"), re.compile(rb"(?:[\x20-\x7e]\x00){12,}"))


class ArtifactReviewError(ValueError):
    """A fixed, shareable diagnostic from an artifact check."""


def verify_wheel(path: Path, reviewed: dict[str, bytes], private_terms=()) -> int:
    project = tomllib.loads(reviewed["pyproject.toml"].decode("utf-8"))["project"]
    prefix = f"{project['name'].replace('-', '_')}-{project['version']}.dist-info/"
    if sorted(project["license-files"]) != sorted(LICENSE_FILES):
        raise ArtifactReviewError("The project must declare the reviewed license and notice.")
    modules = {name.removeprefix("src/"): data for name, data in reviewed.items()
               if name.startswith("src/execlattice/")}
    license_files = {f"{prefix}licenses/{name}": reviewed[name] for name in LICENSE_FILES}
    expected = modules.keys() | license_files.keys() | {prefix + name for name in _WHEEL_RECORDS}
    with ZipFile(path) as archive:
        names = archive.namelist()
        if len(names) != len(expected) or set(names) != expected or archive.testzip() is not None:
            raise ArtifactReviewError("The wheel contents differ from the reviewed source and metadata.")
        for name, data in {**modules, **license_files}.items():
            if archive.read(name) != data:
                raise ArtifactReviewError("A packaged file differs from its reviewed version.")
        for name in _WHEEL_RECORDS:
            check_public_text(f"wheel metadata/{name}", archive.read(prefix + name).decode("utf-8"), private_terms)
        metadata = BytesParser(policy=default).parsebytes(archive.read(prefix + "METADATA"))
        if (metadata.get_all("License-Expression", []) != [project["license"]]
                or sorted(metadata.get_all("License-File", [])) != sorted(LICENSE_FILES)):
            raise ArtifactReviewError("The wheel metadata differs from the reviewed license declaration.")
    return len(modules)


def _check_code(code: CodeType, label: str, *, first_party: bool, private_terms) -> None:
    if PureWindowsPath(code.co_filename).anchor or PurePosixPath(code.co_filename).is_absolute():
        raise ArtifactReviewError("An absolute build path was found in compiled code.")
    for entry in code.co_consts:
        if isinstance(entry, CodeType):
            _check_code(entry, label, first_party=first_party, private_terms=private_terms)
        elif first_party and isinstance(entry, str):
            check_public_text(label, entry, private_terms)


def verify_worker(path: Path, reviewed: dict[str, bytes], private_terms=()) -> int:
    from PyInstaller.archive.readers import CArchiveReader

    approved = {"execlattice." + PurePosixPath(name).stem for name in reviewed if name.startswith("src/execlattice/")}
    approved.add("execlattice")
    archive = CArchiveReader(str(path))
    members = set()
    for name, entry in archive.toc.items():
        normalized = name.replace("\\", "/")
        if (PureWindowsPath(name).anchor or ".." in PurePosixPath(normalized).parts
                or _RUNTIME_FILES.search(normalized)
                or normalized.lower().endswith(".pem") and normalized != "certifi/cacert.pem"):
            raise ArtifactReviewError("The worker contains a private or unexpected resource.")
        kind = entry[-1]
        if kind == "z":
            embedded = archive.open_embedded_archive(name)
            for module in embedded.toc:
                first_party = module == "execlattice" or module.startswith("execlattice.")
                if first_party:
                    if module not in approved:
                        raise ArtifactReviewError("The worker contains an unreviewed first-party module.")
                    members.add(module)
                code = embedded.extract(module)
                if isinstance(code, CodeType):
                    _check_code(code, f"worker module {module}" if first_party else "a dependency",
                                first_party=first_party, private_terms=private_terms)
        elif kind in {"s", "m", "M"}:
            code = marshal.loads(archive.extract(name))
            _check_code(code, "a worker entry point", first_party=name == "worker-entry", private_terms=private_terms)
    if not {"execlattice.cli", "execlattice.worker"} <= members:
        raise ArtifactReviewError("The worker package is missing its entry modules.")
    data = path.read_bytes()
    for pattern, encoding in zip(_NATIVE_STRINGS, ("ascii", "utf-16-le"), strict=True):
        for match in pattern.finditer(data):
            check_public_text("worker executable metadata", match.group().decode(encoding), private_terms)
    return len(members)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wheel", type=Path)
    parser.add_argument("--worker", type=Path)
    parser.add_argument("--deny-term-file", type=Path, help="Optional private terms file outside this source tree")
    args = parser.parse_args()
    if not args.wheel and not args.worker:
        parser.error("Select a wheel or Windows worker executable to review.")
    source = Path(__file__).resolve().parents[1]
    try:
        terms = read_private_terms(source, args.deny_term_file)
        reviewed = read_reviewed_source(source, terms)
        if args.wheel:
            print(f"Reviewed wheel: {verify_wheel(args.wheel, reviewed, terms)} source files.")
        if args.worker:
            print(f"Reviewed worker: {verify_worker(args.worker, reviewed, terms)} first-party modules.")
    except (SourcePrivacyError, ArtifactReviewError) as error:
        parser.exit(1, f"Release review failed. {error}\n")
    except Exception:
        parser.exit(1, "Release review could not read or inspect the selected artifact.\n")


if __name__ == "__main__":
    main()
