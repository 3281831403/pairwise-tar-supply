"""Supply-chain checks for shipping artifacts (contract only).

This module defines the public contract. Every public function is a stub
that raises :class:`NotImplementedError` until the task is implemented.
Do not change the signatures, the exception type or the documented rules:
``tests/test_manifest.py`` is the acceptance suite and must not be edited.

A manifest is a mapping with two keys::

    {
        "algorithm": "sha256",
        "entries": [
            {
                "name": "pkg/mod.py",
                "sha256": "<64 lowercase hex characters>",
                "mode": 0o644,
                "size": 12,
            },
            ...
        ],
    }

Names are repository-relative POSIX paths (``/`` separators).  Entries may
carry the optional boolean keys ``allow_exec`` and ``allow_entry_points``
described in :func:`check_entry`.
"""

from __future__ import annotations

import hashlib
import os
import re
import unicodedata
from collections.abc import Mapping

_SHA256_RE = re.compile(r"[0-9a-f]{64}")

#: Largest accepted file size, in bytes (10 MiB).
MAX_ENTRY_SIZE = 10 * 1024 * 1024

#: Digest algorithms accepted by :func:`verify_hashes`.
ALLOWED_ALGORITHMS = frozenset({"sha256"})

#: Basenames that are always rejected as import-time injection points.
INJECTION_BASENAMES = frozenset({"sitecustomize.py", "usercustomize.py"})


class UnsignedArtifact(Exception):
    """Raised when an artifact, manifest entry or dependency name fails a
    supply-chain check.

    Callers only need the exception type; messages are free-form.
    """


def normalize_name(name: str) -> str:
    """Return the canonical repository-relative spelling of *name*.

    Contract:

    * *name* must be a ``str``; any other type raises
      :class:`UnsignedArtifact`.
    * A NUL character or a backslash anywhere in *name* raises
      :class:`UnsignedArtifact`; only ``/`` is a path separator.
    * The name is Unicode-normalised to NFC.
    * It is split on ``/``; ``"."`` segments are discarded, so
      ``"./pkg/a.py"`` becomes ``"pkg/a.py"``.
    * Any ``".."`` segment raises :class:`UnsignedArtifact`; traversal is
      never resolved.
    * Absolute names (leading ``/``) and empty segments (for example a
      trailing ``/`` or a doubled ``//``) raise
      :class:`UnsignedArtifact`.
    * If no segments remain the name is invalid and raises.
    * The returned string joins the segments with ``/`` and preserves
      letter case.  Callers that compare names case-insensitively compare
      ``normalize_name(...).casefold()``.
    """
    if not isinstance(name, str):
        raise UnsignedArtifact(f"name must be str, not {type(name).__name__}")
    if "\x00" in name or "\\" in name:
        raise UnsignedArtifact(f"invalid separator in name: {name!r}")

    segments: list[str] = []
    for segment in unicodedata.normalize("NFC", name).split("/"):
        if segment == ".":
            continue
        if segment == "..":
            raise UnsignedArtifact(f"path traversal in name: {name!r}")
        if segment == "":
            raise UnsignedArtifact(f"empty path segment in name: {name!r}")
        segments.append(segment)

    if not segments:
        raise UnsignedArtifact(f"empty name: {name!r}")
    return "/".join(segments)


def check_entry(entry: dict) -> None:
    """Validate one manifest entry.

    Required keys: ``name``, ``sha256``, ``mode``, ``size``.  Optional keys
    understood by this contract:

    * ``allow_exec`` -- executable permission bits are accepted only when
      this value is ``True``.
    * ``allow_entry_points`` -- an ``entry_points.txt`` entry is accepted
      only when this value is ``True``.

    Any violation raises :class:`UnsignedArtifact`; a valid entry returns
    ``None``.  Rules:

    * *entry* must be a mapping containing all required keys with the
      documented types.
    * ``name`` must satisfy :func:`normalize_name`.
    * The basename must not be ``sitecustomize.py`` or
      ``usercustomize.py``: both are import-time injection points.
    * The basename must not end with ``.pth`` (``.pth`` files execute
      arbitrary code at interpreter start-up).
    * The basename ``entry_points.txt`` is rejected unless
      ``allow_entry_points`` is true; console-script rewrites are an
      injection point and may only ship when explicitly pinned.
    * ``sha256`` must be exactly 64 lowercase hexadecimal characters
      (``[0-9a-f]{64}``); uppercase hex is rejected.
    * ``size`` must be a plain ``int`` (not ``bool``) in the inclusive
      range ``0..MAX_ENTRY_SIZE``.
    * ``mode`` must be a plain ``int`` (not ``bool``) in the inclusive
      range ``0..0o7777``.  setuid (``0o4000``), setgid (``0o2000``) and
      sticky (``0o1000``) bits are always rejected.  Any executable bit
      (``0o111``) is rejected unless ``allow_exec`` is ``True``.
    """
    if not isinstance(entry, Mapping):
        raise UnsignedArtifact("manifest entry must be a mapping")

    missing = [key for key in ("name", "sha256", "mode", "size") if key not in entry]
    if missing:
        raise UnsignedArtifact(f"manifest entry is missing {missing!r}")

    name = normalize_name(entry["name"])
    basename = name.rsplit("/", 1)[-1]

    if basename in INJECTION_BASENAMES:
        raise UnsignedArtifact(f"import-time injection point: {name!r}")
    if basename.endswith(".pth"):
        raise UnsignedArtifact(f".pth startup hook is not allowed: {name!r}")
    if basename == "entry_points.txt" and entry.get("allow_entry_points") is not True:
        raise UnsignedArtifact(f"entry_points.txt is not pinned: {name!r}")

    digest = entry["sha256"]
    if not isinstance(digest, str) or _SHA256_RE.fullmatch(digest) is None:
        raise UnsignedArtifact(f"sha256 must be 64 lowercase hex characters: {name!r}")

    size = entry["size"]
    if isinstance(size, bool) or not isinstance(size, int):
        raise UnsignedArtifact(f"size must be an int: {name!r}")
    if not 0 <= size <= MAX_ENTRY_SIZE:
        raise UnsignedArtifact(f"size out of range: {name!r}")

    mode = entry["mode"]
    if isinstance(mode, bool) or not isinstance(mode, int):
        raise UnsignedArtifact(f"mode must be an int: {name!r}")
    if not 0 <= mode <= 0o7777:
        raise UnsignedArtifact(f"mode out of range: {name!r}")
    if mode & 0o7000:
        raise UnsignedArtifact(f"setuid/setgid/sticky bits are not allowed: {name!r}")
    if mode & 0o111 and entry.get("allow_exec") is not True:
        raise UnsignedArtifact(f"executable bit is not allowed: {name!r}")


def verify_coverage(manifest: dict, files: list[str]) -> None:
    """Check that *manifest* covers exactly the given *files*.

    Any violation raises :class:`UnsignedArtifact`; success returns
    ``None``.  Rules:

    * *manifest* must be a mapping whose ``"entries"`` value is a list of
      entry mappings.  A missing ``entries`` key, an empty entry list for
      non-empty *files*, or an entry without a ``name`` raises.
    * Every entry name and every file name is canonicalised with
      :func:`normalize_name`; a name that cannot be canonicalised raises.
    * Case-insensitive aliases collide: two manifest entries, or two file
      names, whose canonical spellings are equal under ``str.casefold``
      raise even when their original spelling differs.
    * The set of canonical entry names must equal the set of canonical
      file names.  A file absent from the manifest raises, and so does a
      manifest entry with no matching file.
    """
    if not isinstance(manifest, Mapping):
        raise UnsignedArtifact("manifest must be a mapping")
    entries = manifest.get("entries")
    if not isinstance(entries, list):
        raise UnsignedArtifact("manifest must contain an 'entries' list")
    if not isinstance(files, list):
        raise UnsignedArtifact("files must be a list")
    if not entries and files:
        raise UnsignedArtifact("manifest has no entries but files were given")

    entry_names = _canonical_unique_names(
        [entry.get("name") for entry in _entry_mappings(entries)]
    )
    file_names = _canonical_unique_names(files)

    if entry_names != file_names:
        missing = sorted(file_names - entry_names)
        extra = sorted(entry_names - file_names)
        raise UnsignedArtifact(
            f"manifest does not cover the artifact (missing={missing!r}, "
            f"extra={extra!r})"
        )


def verify_hashes(manifest: dict, root: str, reader) -> None:
    """Recompute every entry digest and compare it with the manifest.

    Any violation raises :class:`UnsignedArtifact`; success returns
    ``None``.  Rules:

    * ``manifest["algorithm"]`` must be the string ``"sha256"``.  A
      missing algorithm or any other value -- ``"md5"``, ``"sha1"`` and
      everything outside :data:`ALLOWED_ALGORITHMS` -- raises without
      calling *reader*.
    * ``manifest["entries"]`` must be a list and every entry name is
      canonicalised with :func:`normalize_name` before use.
    * ``reader(path)`` returns the file contents as ``bytes``.  *path* is
      *root* joined with the canonical name using the platform separator.
    * The bytes are hashed with ``hashlib.sha256``; the lowercase hex
      digest must equal the entry's ``sha256``.  A mismatch (including an
      uppercase digest) raises.
    * ``OSError`` raised by *reader* propagates unchanged.
    """
    if not isinstance(manifest, Mapping):
        raise UnsignedArtifact("manifest must be a mapping")
    algorithm = manifest.get("algorithm")
    if not isinstance(algorithm, str) or algorithm not in ALLOWED_ALGORITHMS:
        raise UnsignedArtifact(f"unsupported digest algorithm: {algorithm!r}")

    entries = manifest.get("entries")
    if not isinstance(entries, list):
        raise UnsignedArtifact("manifest must contain an 'entries' list")

    for entry in _entry_mappings(entries):
        name = normalize_name(entry.get("name"))
        expected = entry.get("sha256")
        if not isinstance(expected, str) or _SHA256_RE.fullmatch(expected) is None:
            raise UnsignedArtifact(f"sha256 must be 64 lowercase hex characters: {name!r}")

        path = os.path.join(root, *name.split("/"))
        digest = hashlib.sha256(reader(path)).hexdigest()
        if digest != expected:
            raise UnsignedArtifact(f"digest mismatch for {name!r}")


def detect_confusion(
    names: list[str], registry: dict, threshold: int = 2
) -> list[str]:
    """Return the package names that look like typos of trusted names.

    This models dependency-confusion attacks, where ``reqeusts`` or
    ``urllib3-py`` is installed instead of ``requests`` / ``urllib3``.

    Contract:

    * For each name in *names*, compute the Levenshtein edit distance
      (insertions, deletions and substitutions each cost 1) to every key
      of *registry*.  Comparison is case-insensitive: names and registry
      keys are compared casefolded.
    * A name is suspicious when it is not itself a registry key and its
      minimum distance to any registry key is less than or equal to
      *threshold*.
    * Return the suspicious names in input order, spelled exactly as they
      were received, each at most once.  Return an empty list when
      nothing is suspicious.
    * *threshold* must be an ``int`` greater than or equal to 0.
    * Registry values are metadata and are ignored.
    """
    if isinstance(threshold, bool) or not isinstance(threshold, int) or threshold < 0:
        raise UnsignedArtifact("threshold must be an int >= 0")
    if not isinstance(names, list):
        raise UnsignedArtifact("names must be a list")
    if not isinstance(registry, Mapping):
        raise UnsignedArtifact("registry must be a mapping")

    trusted = {key.casefold() for key in registry if isinstance(key, str)}

    suspicious: list[str] = []
    seen: set[str] = set()
    for name in names:
        if not isinstance(name, str):
            raise UnsignedArtifact("names must be strings")
        folded = name.casefold()
        if name in seen:
            continue
        seen.add(name)
        if folded in trusted:
            continue
        if any(_levenshtein(folded, key) <= threshold for key in trusted):
            suspicious.append(name)
    return suspicious


def _levenshtein(left: str, right: str) -> int:
    """Return the Levenshtein edit distance between *left* and *right*."""
    if left == right:
        return 0
    if len(left) < len(right):
        left, right = right, left
    previous = list(range(len(right) + 1))
    for i, left_char in enumerate(left, 1):
        current = [i]
        for j, right_char in enumerate(right, 1):
            cost = 0 if left_char == right_char else 1
            current.append(
                min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + cost)
            )
        previous = current
    return previous[-1]


def _entry_mappings(entries: list) -> list[Mapping]:
    """Return *entries* after checking each element is a mapping."""
    for entry in entries:
        if not isinstance(entry, Mapping):
            raise UnsignedArtifact("manifest entry must be a mapping")
    return entries


def _canonical_unique_names(names: list) -> set[str]:
    """Canonicalise *names*, rejecting duplicates and case-insensitive aliases."""
    canonical: set[str] = set()
    folded: set[str] = set()
    for name in names:
        canonical_name = normalize_name(name)
        key = canonical_name.casefold()
        if key in folded:
            raise UnsignedArtifact(f"duplicate or case-alias entry: {name!r}")
        folded.add(key)
        canonical.add(canonical_name)
    return canonical
