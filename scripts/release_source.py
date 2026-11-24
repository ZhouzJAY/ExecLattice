"""Stage only reviewed text files and report privacy findings without their contents."""

from __future__ import annotations

import argparse
import os
import re
import stat
import unicodedata
from pathlib import Path

_MANIFEST = "release-files.txt"
LICENSE_FILES = ("LICENSE", "NOTICE")
_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
_NAME = re.compile(r"(?:\.gitignore|[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*)(?:/[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*)*")
_RESERVED = {"con", "prn", "aux", "nul"} | {f"{prefix}{number}" for prefix in ("com", "lpt") for number in range(10)}
_RULES = (
    ("private-key", re.compile(r"-----BEGIN (?:[A-Z0-9 -]+ )?PRIVATE KEY-----")),
    ("credential-shape", re.compile(
        r"(?:\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{24,}"
        r"|\btskey-(?:auth|api|client|webhook)-[A-Za-z0-9_-]{12,}"
        r"|\b(?:gh[pousr]_|github_pat_)[A-Za-z0-9_]{20,}"
        r"|\bxox[baprs]-[A-Za-z0-9-]{12,}"
        r"|\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"
        r"|\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{12,})"
    )),
    ("user-profile-path", re.compile(
        r"(?:\b[A-Z]:[\\/]+(?:Users|Documents and Settings)[\\/]+"
        r"|(?:\\\\|//)[^\\/]+[\\/]+Users[\\/]+"
        r"|/(?:(?:Users|home)/|root/))[^\\/\s'\":]+",
        re.IGNORECASE,
    )),
)


def _safe_name(name: str) -> bool:
    return (
        _NAME.fullmatch(name) is not None
        and all(part.split(".", 1)[0].casefold() not in _RESERVED for part in name.split("/"))
    )


class SourcePrivacyError(ValueError):
    """A rule and safe relative path, without the matching text."""

    def __init__(self, rule: str, path: str):
        self.rule = rule
        self.path = path if _safe_name(path) and not any(pattern.search(path) for _, pattern in _RULES) else "artifact"
        super().__init__(f"{rule}: {self.path}")


def _fold(text: str) -> str:
    return unicodedata.normalize("NFKC", text).casefold()


def check_public_text(name: str, text: str, private_terms: tuple[str, ...] = ()) -> None:
    """Check text that would be shown as source, help, or package metadata."""
    terms = tuple(_fold(term) for term in private_terms if term)
    if terms and any(term in _fold(name) for term in terms):
        raise SourcePrivacyError("private-term", "artifact")
    for rule, pattern in _RULES:
        if pattern.search(name):
            raise SourcePrivacyError(rule, "artifact")
        if pattern.search(text):
            raise SourcePrivacyError(rule, name)
    if terms:
        folded = _fold(text)
        if any(term in folded for term in terms):
            raise SourcePrivacyError("private-term", name)


def _directory(path: Path, name: str) -> None:
    try:
        for item in (*reversed(path.parents), path):
            info = item.lstat()
            if not stat.S_ISDIR(info.st_mode) or getattr(info, "st_file_attributes", 0) & _REPARSE_POINT:
                raise SourcePrivacyError("unsafe-directory", name)
    except OSError:
        raise SourcePrivacyError("unreadable-directory", name) from None


def _identity(info: stat.stat_result) -> tuple[int, ...]:
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns


def _plain_file(info: stat.stat_result) -> bool:
    return (
        stat.S_ISREG(info.st_mode) and info.st_nlink == 1
        and not getattr(info, "st_file_attributes", 0) & _REPARSE_POINT
    )


def _read_file(path: Path, name: str) -> bytes:
    _directory(path.parent, name)
    try:
        before = path.lstat()
        if not _plain_file(before):
            raise SourcePrivacyError("unsafe-file", name)
        with path.open("rb") as stream:
            opened = os.fstat(stream.fileno())
            if not _plain_file(opened) or _identity(before) != _identity(opened):
                raise SourcePrivacyError("source-changed", name)
            data = stream.read()
        _directory(path.parent, name)
        after = path.lstat()
        if not _plain_file(after) or _identity(before) != _identity(after) or len(data) != before.st_size:
            raise SourcePrivacyError("source-changed", name)
        return data
    except OSError:
        raise SourcePrivacyError("unreadable-file", name) from None


def _decode(data: bytes, name: str) -> str:
    try:
        decoded = data.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise SourcePrivacyError("non-utf8-text", name) from None
    if "\0" in decoded:
        raise SourcePrivacyError("non-text-data", name)
    return decoded


def read_private_terms(source: Path, deny_term_file: Path | None) -> tuple[str, ...]:
    """Read separately stored deny terms without displaying their file or contents."""
    if deny_term_file is None:
        return ()
    name = "deny-terms"
    try:
        candidate = source.resolve(strict=True)
        terms_path = deny_term_file.absolute()
        if terms_path.resolve(strict=True).is_relative_to(candidate):
            raise SourcePrivacyError("deny-terms-inside-source", name)
    except OSError:
        raise SourcePrivacyError("unreadable-file", name) from None
    text = _decode(_read_file(terms_path, name), name)
    return tuple(line.strip() for line in text.splitlines() if line.strip())


def _manifest_names(data: bytes, private_terms: tuple[str, ...]) -> tuple[str, ...]:
    manifest = _decode(data, _MANIFEST)
    check_public_text(_MANIFEST, manifest, private_terms)
    names = tuple(line for line in manifest.splitlines() if line and not line.startswith("#"))
    if not {_MANIFEST, "scripts/release_source.py", *LICENSE_FILES}.issubset(names):
        raise SourcePrivacyError("incomplete-manifest", _MANIFEST)
    if len({name.casefold() for name in names}) != len(names):
        raise SourcePrivacyError("duplicate-source", _MANIFEST)
    if any(not _safe_name(name) or (
        name not in {".gitignore", *LICENSE_FILES} and Path(name).suffix not in {".py", ".md", ".toml", ".txt"}
    ) for name in names):
        raise SourcePrivacyError("invalid-source-name", _MANIFEST)
    return names


def read_reviewed_source(source: Path, private_terms: tuple[str, ...] = ()) -> dict[str, bytes]:
    """Read one exact inventory of plain source files. Extra files are ignored."""
    source = source.absolute()
    manifest = _read_file(source / _MANIFEST, _MANIFEST)
    names = _manifest_names(manifest, private_terms)
    files = {}
    for name in names:
        path = source.joinpath(*name.split("/"))
        data = manifest if name == _MANIFEST else _read_file(path, name)
        check_public_text(name, _decode(data, name), private_terms)
        files[name] = data
    return files


def stage_reviewed_source(
    source: Path, dest: Path, private_terms: tuple[str, ...] = ()
) -> Path:
    """Check the complete source first, then write it to a fresh destination."""
    files = read_reviewed_source(source, private_terms)
    dest = dest.absolute()
    _directory(dest.parent, "destination")
    try:
        dest.mkdir()
    except FileExistsError:
        raise SourcePrivacyError("destination-exists", "destination") from None
    except OSError:
        raise SourcePrivacyError("destination-unwritable", "destination") from None
    for name, data in files.items():
        path = dest.joinpath(*name.split("/"))
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            _directory(path.parent, name)
            with path.open("xb") as stream:
                stream.write(data)
        except OSError:
            raise SourcePrivacyError("destination-unwritable", name) from None
    return dest


class _PrivacyArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        self.exit(2, "invalid-option: command\n")


def main() -> int:
    parser = _PrivacyArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True, help="Fresh destination in an existing parent directory")
    parser.add_argument("--deny-term-file", type=Path, help="Optional UTF-8 file outside the release source")
    args = parser.parse_args()
    source = Path(__file__).absolute().parents[1]
    try:
        terms = read_private_terms(source, args.deny_term_file)
        stage_reviewed_source(source, args.out, terms)
    except SourcePrivacyError as error:
        parser.exit(1, f"{error}\n")
    print("Staged reviewed release source.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
