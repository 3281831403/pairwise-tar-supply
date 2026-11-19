"""Artifact supply-chain guard used by the pairwise-tar-supply task."""

from .manifest import (
    UnsignedArtifact,
    check_entry,
    detect_confusion,
    normalize_name,
    verify_coverage,
    verify_hashes,
)

__all__ = [
    "UnsignedArtifact",
    "check_entry",
    "detect_confusion",
    "normalize_name",
    "verify_coverage",
    "verify_hashes",
]
