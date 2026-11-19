"""Acceptance tests for artifact_guard.manifest.

The repository starts red on purpose: every public function is a stub that
raises ``NotImplementedError``.  Each test below is written against the
contract in ``artifact_guard/manifest.py`` and must not be modified.
"""

import hashlib

import pytest

from artifact_guard.manifest import (
    UnsignedArtifact,
    check_entry,
    detect_confusion,
    normalize_name,
    verify_coverage,
    verify_hashes,
)

PAYLOAD = b"payload"
SHA_PAYLOAD = hashlib.sha256(PAYLOAD).hexdigest()


def test_rejects_pth_injection():
    with pytest.raises(UnsignedArtifact):
        check_entry(
            {
                "name": "pkg-1.0.dist-info/inject.pth",
                "sha256": SHA_PAYLOAD,
                "mode": 0o644,
                "size": len(PAYLOAD),
            }
        )


def test_rejects_sitecustomize_injection():
    with pytest.raises(UnsignedArtifact):
        check_entry(
            {
                "name": "sitecustomize.py",
                "sha256": SHA_PAYLOAD,
                "mode": 0o644,
                "size": len(PAYLOAD),
            }
        )


def test_rejects_unexpected_entry_points_change():
    with pytest.raises(UnsignedArtifact):
        check_entry(
            {
                "name": "pkg-1.0.dist-info/entry_points.txt",
                "sha256": SHA_PAYLOAD,
                "mode": 0o644,
                "size": len(PAYLOAD),
            }
        )


def test_normalizes_dot_prefix():
    assert normalize_name("./pkg/a.py") == "pkg/a.py"


def test_rejects_parent_segments():
    with pytest.raises(UnsignedArtifact):
        normalize_name("pkg/../pkg/a.py")


def test_rejects_case_alias_entries():
    manifest = {
        "algorithm": "sha256",
        "entries": [
            {
                "name": "pkg/a.py",
                "sha256": SHA_PAYLOAD,
                "mode": 0o644,
                "size": len(PAYLOAD),
            },
            {
                "name": "pkg/A.py",
                "sha256": SHA_PAYLOAD,
                "mode": 0o644,
                "size": len(PAYLOAD),
            },
        ],
    }
    with pytest.raises(UnsignedArtifact):
        verify_coverage(manifest, ["pkg/a.py", "pkg/A.py"])


def test_rejects_unlisted_file():
    manifest = {
        "algorithm": "sha256",
        "entries": [
            {
                "name": "pkg/a.py",
                "sha256": SHA_PAYLOAD,
                "mode": 0o644,
                "size": len(PAYLOAD),
            }
        ],
    }
    with pytest.raises(UnsignedArtifact):
        verify_coverage(manifest, ["pkg/a.py", "pkg/b.py"])


def test_rejects_duplicate_entries():
    manifest = {
        "algorithm": "sha256",
        "entries": [
            {
                "name": "pkg/a.py",
                "sha256": SHA_PAYLOAD,
                "mode": 0o644,
                "size": len(PAYLOAD),
            },
            {
                "name": "pkg/a.py",
                "sha256": SHA_PAYLOAD,
                "mode": 0o644,
                "size": len(PAYLOAD),
            },
        ],
    }
    with pytest.raises(UnsignedArtifact):
        verify_coverage(manifest, ["pkg/a.py"])


def test_rejects_manifest_without_entries():
    with pytest.raises(UnsignedArtifact):
        verify_coverage({"algorithm": "sha256", "entries": []}, ["pkg/a.py"])
    with pytest.raises(UnsignedArtifact):
        verify_coverage({"algorithm": "sha256"}, ["pkg/a.py"])


def test_rejects_setuid_bit():
    with pytest.raises(UnsignedArtifact):
        check_entry(
            {
                "name": "pkg/tool",
                "sha256": SHA_PAYLOAD,
                "mode": 0o4644,
                "size": len(PAYLOAD),
            }
        )


def test_rejects_executable_bit_without_allow_exec():
    with pytest.raises(UnsignedArtifact):
        check_entry(
            {
                "name": "pkg/tool",
                "sha256": SHA_PAYLOAD,
                "mode": 0o755,
                "size": len(PAYLOAD),
                "allow_exec": False,
            }
        )


def test_rejects_md5_algorithm():
    manifest = {
        "algorithm": "md5",
        "entries": [
            {
                "name": "pkg/a.py",
                "sha256": SHA_PAYLOAD,
                "mode": 0o644,
                "size": len(PAYLOAD),
            }
        ],
    }
    with pytest.raises(UnsignedArtifact):
        verify_hashes(manifest, ".", lambda path: PAYLOAD)


def test_rejects_sha256_mismatch():
    manifest = {
        "algorithm": "sha256",
        "entries": [
            {
                "name": "pkg/a.py",
                "sha256": "0" * 64,
                "mode": 0o644,
                "size": len(PAYLOAD),
            }
        ],
    }
    with pytest.raises(UnsignedArtifact):
        verify_hashes(manifest, ".", lambda path: PAYLOAD)


def test_detects_confusable_dependency_names():
    registry = {"requests": "2.32.0", "urllib3": "2.2.0"}
    assert detect_confusion(["reqeusts", "requests", "urllib3-py"], registry) == [
        "reqeusts"
    ]
    assert detect_confusion(["urllib3-py"], registry, threshold=3) == ["urllib3-py"]


def test_normal_manifest_passes():
    entry = {
        "name": "pkg/mod.py",
        "sha256": SHA_PAYLOAD,
        "mode": 0o644,
        "size": len(PAYLOAD),
    }
    manifest = {"algorithm": "sha256", "entries": [entry]}
    assert check_entry(entry) is None
    assert verify_coverage(manifest, ["pkg/mod.py"]) is None
    assert verify_hashes(manifest, ".", lambda path: PAYLOAD) is None
    assert detect_confusion(["requests"], {"requests": "2.32.0"}) == []
