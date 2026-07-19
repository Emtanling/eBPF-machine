"""Safe deterministic construction and replay of the published evidence capsule."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import io
import json
import lzma
from pathlib import Path, PurePosixPath
import tarfile
from typing import Any, Mapping


MANIFEST_SCHEMA = "rac-stock-r-replay-manifest-v1"
RAW_REPLAY_SCHEMA = "rac-stock-r-replay-raw-v1"
SUMMARY_SCHEMA = "rac-stock-r-reproduction-summary-v1"
MAX_ARCHIVE_SIZE = 25 * 1024 * 1024
MAX_UNCOMPRESSED_SIZE = 64 * 1024 * 1024
MAX_MEMBER_COUNT = 4096


class ReproductionError(ValueError):
    """The replay artifact is malformed, unsafe, or outside its frozen bounds."""


@dataclass(frozen=True)
class CapsuleInputs:
    v2_bundle: Path
    context_bundles: tuple[Path, Path]


@dataclass(frozen=True)
class _ProjectedFile:
    path: str
    value: bytes
    role: str

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.value).hexdigest()


_V2_FIXED_PATHS: tuple[tuple[str, str], ...] = (
    ("query/query.json", "V2_QUERY"),
    ("query/selection-policy.json", "V2_SELECTION_POLICY"),
    ("query/precommit.json", "V2_PRECOMMIT"),
    ("contract/capture-contract.json", "V2_CAPTURE_CONTRACT"),
    ("raw/runtime.json", "V2_RUNTIME"),
    ("raw/events.jsonl", "V2_EVENTS"),
    ("raw/program-info.json", "V2_PROGRAM_INFO"),
    ("raw/xlated-rac_v2_single.txt", "V2_XLATED"),
    ("proof/must-outcome-proof.json", "V2_MUST_OUTCOME_PROOF"),
    ("proof/history-case-binding.json", "V2_HISTORY_CASE_BINDING"),
    ("build/source-manifest.json", "V2_SOURCE_MANIFEST"),
    ("build/artifact-manifest.json", "V2_BUILD_MANIFEST"),
)

_CONTEXT_FIXED_PATHS: tuple[tuple[str, str], ...] = (
    (
        "work/linux/witness/rac_v2_witness.bpf.c",
        "CONTEXT_GENERATED_SOURCE",
    ),
    ("context/transform-metadata.json", "CONTEXT_TRANSFORM_METADATA"),
    ("target/build/rac_v2_contextual.bpf.o", "CONTEXT_OBJECT"),
    ("target/raw/xlated-rac_v2_contextual.txt", "CONTEXT_XLATED"),
    ("target/raw/runtime.json", "CONTEXT_RUNTIME"),
    ("target/raw/program-info.json", "CONTEXT_PROGRAM_INFO"),
    ("target/identity.json", "CONTEXT_IDENTITY"),
    ("target/audit/runtime-validation.json", "CONTEXT_RUNTIME_VALIDATION"),
)


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _safe_relative(value: object, reason: str) -> PurePosixPath:
    if not isinstance(value, str) or not value or "\\" in value:
        raise ReproductionError(f"{reason}: path must be a non-empty POSIX path")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in ("", ".", "..") for part in path.parts):
        raise ReproductionError(f"{reason}: {value}")
    if path.as_posix() != value:
        raise ReproductionError(f"{reason}: path is not canonical: {value}")
    return path


def _read_source_file(root: Path, relative: str) -> bytes:
    rel = _safe_relative(relative, "INPUT_PATH_UNSAFE")
    if root.is_symlink() or not root.is_dir():
        raise ReproductionError(f"INPUT_ROOT_INVALID: {root}")
    candidate = root.joinpath(*rel.parts)
    current = root
    for part in rel.parts:
        current = current / part
        if current.is_symlink():
            raise ReproductionError(f"INPUT_SYMLINK_UNSAFE: {relative}")
    try:
        if not candidate.is_file():
            raise ReproductionError(f"INPUT_FILE_MISSING: {relative}")
        resolved_root = root.resolve(strict=True)
        resolved = candidate.resolve(strict=True)
        if resolved_root not in resolved.parents:
            raise ReproductionError(f"INPUT_PATH_UNSAFE: {relative}")
        return candidate.read_bytes()
    except OSError as exc:
        raise ReproductionError(f"INPUT_FILE_UNREADABLE: {relative}: {exc}") from exc


def _read_json_source(root: Path, relative: str) -> Mapping[str, object]:
    try:
        value = json.loads(_read_source_file(root, relative).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReproductionError(f"INPUT_JSON_MALFORMED: {relative}: {exc}") from exc
    if not isinstance(value, dict):
        raise ReproductionError(f"INPUT_JSON_MALFORMED: {relative} must be an object")
    return value


def _closure_entries(
    root: Path,
    manifest_relative: str,
    base_relative: str,
) -> list[tuple[str, bytes]]:
    manifest = _read_json_source(root, manifest_relative)
    raw_entries = manifest.get("entries")
    if not isinstance(raw_entries, list) or not raw_entries:
        raise ReproductionError(f"CLOSURE_MANIFEST_MALFORMED: {manifest_relative}")
    entries: list[tuple[str, bytes]] = []
    seen: set[str] = set()
    for raw_entry in raw_entries:
        if not isinstance(raw_entry, dict):
            raise ReproductionError(f"CLOSURE_MANIFEST_MALFORMED: {manifest_relative}")
        path = _safe_relative(raw_entry.get("path"), "CLOSURE_ENTRY_PATH_UNSAFE").as_posix()
        if path in seen:
            raise ReproductionError(f"CLOSURE_ENTRY_DUPLICATE: {path}")
        seen.add(path)
        value = _read_source_file(root, f"{base_relative}/{path}")
        expected_digest = raw_entry.get("sha256")
        expected_size = raw_entry.get("size")
        if expected_digest != _sha256_bytes(value) or expected_size != len(value):
            raise ReproductionError(f"CLOSURE_ENTRY_MISMATCH: {path}")
        entries.append((path, value))
    return entries


def _add_projected(
    projected: dict[str, _ProjectedFile],
    path: str,
    value: bytes,
    role: str,
) -> None:
    _safe_relative(path, "PROJECTED_PATH_UNSAFE")
    existing = projected.get(path)
    candidate = _ProjectedFile(path=path, value=value, role=role)
    if existing is not None and existing.value != value:
        raise ReproductionError(f"PROJECTED_PATH_COLLISION: {path}")
    projected[path] = candidate


def _validate_digest_receipt(
    identity: Mapping[str, object],
    field: str,
    value: bytes,
    reason: str,
) -> None:
    if identity.get(field) != _sha256_bytes(value):
        raise ReproductionError(reason)


def _checked_certificates(
    v2: Path,
    contexts: tuple[Path, Path],
) -> dict[str, object]:
    query = _read_json_source(v2, "query/query.json")
    if query.get("schema") != "rac-stock-r-v2-query-v1":
        return {
            "v2": None,
            "contexts": [None for _context in contexts],
            "mode": "fixture-unchecked",
        }

    from .context_runtime import validate_context_runtime
    from .ebrc import canonical_digest, check_certificate
    from .ebrc_adapters import compile_stock_r_v2_bundle
    from .ebrc_context import make_stock_r_context_documents
    from .stock_r_v2 import audit_bundle

    audit = audit_bundle(v2)
    if audit.get("assessment", {}).get("status") != "NONFACTORING":
        raise ReproductionError("V2_SOURCE_NOT_NONFACTORING")
    source_documents = compile_stock_r_v2_bundle(v2)
    source_result = check_certificate(
        source_documents["graph"],
        source_documents["claim"],
        source_documents["proof"],
    )
    if source_result.get("status") != "CERTIFIED" or not source_result.get("certificate"):
        raise ReproductionError("V2_SOURCE_CERTIFICATE_NOT_CERTIFIED")

    context_certificates: list[str] = []
    context_claim_digests: list[str] = []
    for index, context in enumerate(contexts):
        runtime = _read_json_source(context, "target/raw/runtime.json")
        identity = _read_json_source(context, "target/identity.json")
        validation = validate_context_runtime(
            runtime,
            identity,
            {
                "object": context / "target" / "build" / "rac_v2_contextual.bpf.o",
                "btf": v2 / "build" / "btf-vmlinux",
                "xlated": context / "target" / "raw" / "xlated-rac_v2_contextual.txt",
            },
        )
        recorded_validation = _read_json_source(
            context, "target/audit/runtime-validation.json"
        )
        if validation.get("status") != "VERIFIED" or recorded_validation.get(
            "status"
        ) != "VERIFIED":
            raise ReproductionError(f"CONTEXT_{index}_RUNTIME_NOT_VERIFIED")
        metadata = _read_json_source(context, "context/transform-metadata.json")
        documents = make_stock_r_context_documents(
            source_documents["graph"],
            source_documents["claim"],
            source_documents["proof"],
            dict(identity),
            dict(metadata),
        )
        result = check_certificate(
            documents["graph"],
            documents["claim"],
            documents["proof"],
        )
        if result.get("status") != "CERTIFIED" or not result.get("certificate"):
            raise ReproductionError(f"CONTEXT_{index}_CERTIFICATE_NOT_CERTIFIED")
        context_certificates.append(str(result["certificate"]))
        context_claim_digests.append(canonical_digest(documents["claim"]))

    return {
        "v2": str(source_result["certificate"]),
        "contexts": context_certificates,
        "mode": "checked-current-code",
        "source_claim_digest_sha256": canonical_digest(source_documents["claim"]),
        "context_claim_digest_sha256": context_claim_digests,
    }


def _project_inputs(inputs: CapsuleInputs) -> tuple[list[_ProjectedFile], dict[str, object]]:
    if len(inputs.context_bundles) != 2:
        raise ReproductionError("CONTEXT_BUNDLE_COUNT_MISMATCH")
    v2 = inputs.v2_bundle
    projected: dict[str, _ProjectedFile] = {}
    for relative, role in _V2_FIXED_PATHS:
        _add_projected(projected, f"v2/{relative}", _read_source_file(v2, relative), role)
    for relative, value in _closure_entries(
        v2, "build/source-manifest.json", "build/source"
    ):
        _add_projected(
            projected,
            f"v2/build/source/{relative}",
            value,
            "V2_SOURCE_CLOSURE",
        )
    for relative, value in _closure_entries(
        v2, "build/artifact-manifest.json", "build"
    ):
        _add_projected(
            projected,
            f"v2/build/{relative}",
            value,
            "V2_BUILD_CLOSURE",
        )

    query = _read_json_source(v2, "query/query.json")
    query_identity = query.get("identity")
    if not isinstance(query_identity, dict):
        raise ReproductionError("V2_IDENTITY_MALFORMED")
    runtime = _read_json_source(v2, "raw/runtime.json")
    runtime_identity = runtime.get("identity")
    if not isinstance(runtime_identity, dict):
        raise ReproductionError("V2_RUNTIME_IDENTITY_MALFORMED")
    source_manifest_bytes = _read_source_file(v2, "build/source-manifest.json")
    artifact_manifest_bytes = _read_source_file(v2, "build/artifact-manifest.json")
    if query.get("source_closure_sha256") != _sha256_bytes(source_manifest_bytes):
        raise ReproductionError("V2_SOURCE_CLOSURE_DIGEST_MISMATCH")
    if query.get("build_closure_sha256") != _sha256_bytes(artifact_manifest_bytes):
        raise ReproductionError("V2_BUILD_CLOSURE_DIGEST_MISMATCH")
    btf = _read_source_file(v2, "build/btf-vmlinux")
    source_object = _read_source_file(v2, "build/rac_v2_witness.bpf.o")
    source_xlated = _read_source_file(v2, "raw/xlated-rac_v2_single.txt")
    _validate_digest_receipt(
        query_identity, "btf_sha256", btf, "V2_BTF_DIGEST_MISMATCH"
    )
    _validate_digest_receipt(
        query_identity, "object_sha256", source_object, "V2_OBJECT_DIGEST_MISMATCH"
    )
    _validate_digest_receipt(
        runtime_identity, "btf_sha256", btf, "V2_RUNTIME_BTF_DIGEST_MISMATCH"
    )
    _validate_digest_receipt(
        runtime_identity,
        "object_sha256",
        source_object,
        "V2_RUNTIME_OBJECT_DIGEST_MISMATCH",
    )
    _validate_digest_receipt(
        runtime_identity, "xlated_sha256", source_xlated, "V2_XLATED_DIGEST_MISMATCH"
    )

    context_descriptors: list[dict[str, object]] = []
    for index, context in enumerate(inputs.context_bundles):
        prefix = f"contexts/{index}"
        for relative, role in _CONTEXT_FIXED_PATHS:
            archive_relative = (
                "generated-source.bpf.c"
                if relative == "work/linux/witness/rac_v2_witness.bpf.c"
                else relative
            )
            _add_projected(
                projected,
                f"{prefix}/{archive_relative}",
                _read_source_file(context, relative),
                role,
            )
        identity = _read_json_source(context, "target/identity.json")
        target_object = _read_source_file(
            context, "target/build/rac_v2_contextual.bpf.o"
        )
        target_xlated = _read_source_file(
            context, "target/raw/xlated-rac_v2_contextual.txt"
        )
        _validate_digest_receipt(
            identity,
            "object_sha256",
            target_object,
            f"CONTEXT_{index}_OBJECT_DIGEST_MISMATCH",
        )
        _validate_digest_receipt(
            identity,
            "xlated_sha256",
            target_xlated,
            f"CONTEXT_{index}_XLATED_DIGEST_MISMATCH",
        )
        _validate_digest_receipt(
            identity,
            "btf_sha256",
            btf,
            f"CONTEXT_{index}_BTF_DIGEST_MISMATCH",
        )
        runtime_validation = _read_json_source(
            context, "target/audit/runtime-validation.json"
        )
        if runtime_validation.get("status") != "VERIFIED":
            raise ReproductionError(f"CONTEXT_{index}_RUNTIME_NOT_VERIFIED")
        metadata = _read_json_source(context, "context/transform-metadata.json")
        if metadata.get("claim_boundary") != "EXACT_TARGET_ONLY" and metadata.get(
            "schema"
        ) == "rac-stock-r-context-transform-metadata-v1":
            raise ReproductionError(f"CONTEXT_{index}_CLAIM_BOUNDARY_INVALID")
        context_descriptors.append(
            {
                "root": prefix,
                "case_id": metadata.get("case_id", metadata.get("variant_id")),
                "suite_id": metadata.get("suite_id"),
                "identity": dict(identity),
                "common_btf": "v2/build/btf-vmlinux",
            }
        )
    files = [projected[path] for path in sorted(projected)]
    metadata = {
        "roots": {
            "v2_bundle": "v2",
            "context_bundles": [descriptor["root"] for descriptor in context_descriptors],
        },
        "source_identity": dict(runtime_identity),
        "contexts": context_descriptors,
        "certificates": _checked_certificates(v2, inputs.context_bundles),
    }
    return files, metadata


def _tar_xz(files: list[_ProjectedFile]) -> bytes:
    raw = io.BytesIO()
    try:
        with tarfile.open(fileobj=raw, mode="w", format=tarfile.USTAR_FORMAT) as archive:
            for projected in files:
                info = tarfile.TarInfo(projected.path)
                info.type = tarfile.REGTYPE
                info.size = len(projected.value)
                info.mode = 0o644
                info.uid = 0
                info.gid = 0
                info.uname = ""
                info.gname = ""
                info.mtime = 0
                archive.addfile(info, io.BytesIO(projected.value))
    except (OSError, ValueError) as exc:
        raise ReproductionError(f"ARCHIVE_BUILD_FAILED: {exc}") from exc
    return lzma.compress(
        raw.getvalue(),
        format=lzma.FORMAT_XZ,
        check=lzma.CHECK_CRC64,
        preset=9,
    )


def build_replay_capsule(
    inputs: CapsuleInputs,
    archive_path: Path,
    manifest_path: Path,
) -> dict[str, object]:
    """Project validated receipts into a byte-deterministic Git-sized capsule."""

    if archive_path.exists() or manifest_path.exists():
        raise ReproductionError("OUTPUT_ALREADY_EXISTS")
    files, projection_metadata = _project_inputs(inputs)
    total_size = sum(len(projected.value) for projected in files)
    if len(files) > MAX_MEMBER_COUNT or total_size > MAX_UNCOMPRESSED_SIZE:
        raise ReproductionError("CAPSULE_UNCOMPRESSED_LIMIT_EXCEEDED")
    archive_bytes = _tar_xz(files)
    if len(archive_bytes) > MAX_ARCHIVE_SIZE:
        raise ReproductionError("CAPSULE_ARCHIVE_SIZE_EXCEEDED")
    entries = [
        {
            "path": projected.path,
            "sha256": projected.sha256,
            "size": len(projected.value),
            "role": projected.role,
        }
        for projected in files
    ]
    manifest: dict[str, object] = {
        "schema": MANIFEST_SCHEMA,
        "archive": {
            "sha256": _sha256_bytes(archive_bytes),
            "size": len(archive_bytes),
            "format": "USTAR+XZ",
        },
        "limits": {
            "max_archive_size": MAX_ARCHIVE_SIZE,
            "max_uncompressed_size": MAX_UNCOMPRESSED_SIZE,
            "max_member_count": MAX_MEMBER_COUNT,
            "member_count": len(entries),
            "total_uncompressed_size": total_size,
        },
        "entries": entries,
        **projection_metadata,
    }
    try:
        archive_path.parent.mkdir(parents=True, exist_ok=True)
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        archive_path.write_bytes(archive_bytes)
        manifest_path.write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    except OSError as exc:
        raise ReproductionError(f"OUTPUT_WRITE_FAILED: {exc}") from exc
    return manifest


def _load_manifest(value: Mapping[str, object] | Path) -> Mapping[str, object]:
    if isinstance(value, Path):
        try:
            document = json.loads(value.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ReproductionError(f"MANIFEST_MALFORMED: {exc}") from exc
    else:
        document = value
    if not isinstance(document, Mapping) or document.get("schema") != MANIFEST_SCHEMA:
        raise ReproductionError("MANIFEST_MALFORMED")
    return document


def _manifest_entries(manifest: Mapping[str, object]) -> dict[str, Mapping[str, object]]:
    raw_entries = manifest.get("entries")
    if not isinstance(raw_entries, list):
        raise ReproductionError("MANIFEST_ENTRIES_MALFORMED")
    entries: dict[str, Mapping[str, object]] = {}
    for raw_entry in raw_entries:
        if not isinstance(raw_entry, Mapping):
            raise ReproductionError("MANIFEST_ENTRIES_MALFORMED")
        path = _safe_relative(raw_entry.get("path"), "MANIFEST_ENTRY_PATH_UNSAFE").as_posix()
        digest = raw_entry.get("sha256")
        size = raw_entry.get("size")
        role = raw_entry.get("role")
        if (
            path in entries
            or not isinstance(digest, str)
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
            or not isinstance(size, int)
            or isinstance(size, bool)
            or size < 0
            or not isinstance(role, str)
            or not role
        ):
            raise ReproductionError("MANIFEST_ENTRIES_MALFORMED")
        entries[path] = raw_entry
    return entries


def _validate_manifest_limits(
    manifest: Mapping[str, object], entries: Mapping[str, Mapping[str, object]]
) -> None:
    limits = manifest.get("limits")
    if not isinstance(limits, Mapping):
        raise ReproductionError("MANIFEST_LIMITS_MALFORMED")
    total = sum(int(entry["size"]) for entry in entries.values())
    if (
        limits.get("max_archive_size") != MAX_ARCHIVE_SIZE
        or limits.get("max_uncompressed_size") != MAX_UNCOMPRESSED_SIZE
        or limits.get("max_member_count") != MAX_MEMBER_COUNT
        or limits.get("member_count") != len(entries)
        or limits.get("total_uncompressed_size") != total
        or len(entries) > MAX_MEMBER_COUNT
        or total > MAX_UNCOMPRESSED_SIZE
    ):
        raise ReproductionError("MANIFEST_LIMITS_MALFORMED")


def verify_and_extract_capsule(
    archive_path: Path,
    manifest_document: Mapping[str, object] | Path,
    destination: Path,
) -> None:
    """Validate all archive structure and bytes before writing any member."""

    manifest = _load_manifest(manifest_document)
    entries = _manifest_entries(manifest)
    _validate_manifest_limits(manifest, entries)
    try:
        archive_bytes = archive_path.read_bytes()
    except OSError as exc:
        raise ReproductionError(f"ARCHIVE_UNREADABLE: {exc}") from exc
    archive_descriptor = manifest.get("archive")
    if not isinstance(archive_descriptor, Mapping):
        raise ReproductionError("MANIFEST_ARCHIVE_MALFORMED")
    if (
        archive_descriptor.get("format") != "USTAR+XZ"
        or archive_descriptor.get("size") != len(archive_bytes)
        or archive_descriptor.get("sha256") != _sha256_bytes(archive_bytes)
        or len(archive_bytes) > MAX_ARCHIVE_SIZE
    ):
        raise ReproductionError("ARCHIVE_DIGEST_MISMATCH")
    if destination.exists():
        raise ReproductionError("EXTRACTION_DESTINATION_EXISTS")

    validated: list[tuple[str, bytes]] = []
    seen: set[str] = set()
    try:
        with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:xz") as archive:
            for member in archive:
                path = _safe_relative(member.name, "ARCHIVE_MEMBER_PATH_UNSAFE").as_posix()
                if not member.isreg():
                    raise ReproductionError(f"ARCHIVE_MEMBER_TYPE_UNSAFE: {path}")
                if path in seen:
                    raise ReproductionError(f"ARCHIVE_MEMBER_DUPLICATE: {path}")
                seen.add(path)
                descriptor = entries.get(path)
                if descriptor is None:
                    raise ReproductionError(f"UNMANIFESTED_ARCHIVE_MEMBER: {path}")
                if member.size != descriptor["size"]:
                    raise ReproductionError(f"ARCHIVE_MEMBER_SIZE_MISMATCH: {path}")
                extracted = archive.extractfile(member)
                if extracted is None:
                    raise ReproductionError(f"ARCHIVE_MEMBER_UNREADABLE: {path}")
                value = extracted.read(MAX_UNCOMPRESSED_SIZE + 1)
                if len(value) != member.size:
                    raise ReproductionError(f"ARCHIVE_MEMBER_SIZE_MISMATCH: {path}")
                if _sha256_bytes(value) != descriptor["sha256"]:
                    raise ReproductionError(f"ARCHIVE_MEMBER_DIGEST_MISMATCH: {path}")
                validated.append((path, value))
    except (tarfile.TarError, lzma.LZMAError, OSError) as exc:
        raise ReproductionError(f"ARCHIVE_MALFORMED: {exc}") from exc
    missing = sorted(set(entries) - seen)
    if missing:
        raise ReproductionError(f"MANIFESTED_ARCHIVE_MEMBER_MISSING: {missing[0]}")

    try:
        destination.mkdir(parents=True)
        resolved_destination = destination.resolve(strict=True)
        for relative, value in validated:
            rel = PurePosixPath(relative)
            target = destination.joinpath(*rel.parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            resolved_parent = target.parent.resolve(strict=True)
            if (
                resolved_parent != resolved_destination
                and resolved_destination not in resolved_parent.parents
            ):
                raise ReproductionError(f"EXTRACTION_PATH_ESCAPE: {relative}")
            target.write_bytes(value)
    except OSError as exc:
        raise ReproductionError(f"EXTRACTION_WRITE_FAILED: {exc}") from exc
    verify_manifested_tree(destination, manifest)


def verify_manifested_tree(
    root: Path,
    manifest_document: Mapping[str, object] | Path,
) -> None:
    """Require an extracted tree to contain exactly the manifested regular files."""

    manifest = _load_manifest(manifest_document)
    entries = _manifest_entries(manifest)
    _validate_manifest_limits(manifest, entries)
    if root.is_symlink() or not root.is_dir():
        raise ReproductionError("MANIFESTED_TREE_ROOT_INVALID")
    observed: set[str] = set()
    for path in root.rglob("*"):
        if path.is_symlink():
            raise ReproductionError("MANIFESTED_TREE_SYMLINK_UNSAFE")
        if path.is_file():
            relative = path.relative_to(root).as_posix()
            observed.add(relative)
            descriptor = entries.get(relative)
            if descriptor is None:
                raise ReproductionError(f"UNMANIFESTED_TREE_FILE: {relative}")
            try:
                value = path.read_bytes()
            except OSError as exc:
                raise ReproductionError(f"MANIFESTED_TREE_UNREADABLE: {relative}: {exc}") from exc
            if len(value) != descriptor["size"]:
                raise ReproductionError(f"MANIFESTED_TREE_SIZE_MISMATCH: {relative}")
            if _sha256_bytes(value) != descriptor["sha256"]:
                raise ReproductionError(f"MANIFESTED_TREE_DIGEST_MISMATCH: {relative}")
    missing = sorted(set(entries) - observed)
    if missing:
        raise ReproductionError(f"MANIFESTED_TREE_FILE_MISSING: {missing[0]}")


def _repository_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _sorted_context_roots(extracted: Path) -> list[Path]:
    contexts = extracted / "contexts"
    if not contexts.is_dir():
        raise ReproductionError("REPLAY_CONTEXTS_MISSING")
    roots = [path for path in contexts.iterdir() if path.is_dir()]
    try:
        return sorted(roots, key=lambda path: int(path.name))
    except ValueError as exc:
        raise ReproductionError("REPLAY_CONTEXT_ROOT_MALFORMED") from exc


def _hostile_summary(matrix: Mapping[str, object] | None) -> dict[str, object]:
    if not isinstance(matrix, Mapping):
        return {"all_expected": False, "case_count": 0, "summary": {}}
    cases = matrix.get("cases", [])
    return {
        "all_expected": matrix.get("all_expected") is True,
        "case_count": len(cases) if isinstance(cases, list) else 0,
        "summary": dict(matrix.get("summary", {}))
        if isinstance(matrix.get("summary"), Mapping)
        else {},
    }


def replay_capsule(extracted: Path) -> dict[str, object]:
    """Replay the capsule using current checkers, not stored terminal verdicts."""

    if not extracted.is_dir():
        raise ReproductionError("REPLAY_ROOT_INVALID")

    from .context_runtime import validate_context_runtime
    from .ebrc import check_certificate
    from .ebrc_adapters import compile_stock_linux_v1_bundle, compile_stock_r_v2_bundle
    from .ebrc_context import make_stock_r_context_documents
    from .ebrc_context_mutations import run_context_hostile_mutation_matrix
    from .ebrc_mutations import run_hostile_mutation_matrix

    v1_documents = compile_stock_linux_v1_bundle(
        _repository_root() / "stock-linux-r-proof"
    )
    v1_result = check_certificate(
        v1_documents["graph"],
        v1_documents["claim"],
        v1_documents["proof"],
    )

    v2_documents = compile_stock_r_v2_bundle(extracted / "v2")
    v2_result = check_certificate(
        v2_documents["graph"],
        v2_documents["claim"],
        v2_documents["proof"],
    )
    v2_hostile = (
        run_hostile_mutation_matrix(
            v2_documents["graph"],
            v2_documents["claim"],
            v2_documents["proof"],
        )
        if v2_result.get("status") == "CERTIFIED"
        else None
    )

    contexts: list[dict[str, object]] = []
    for context_root in _sorted_context_roots(extracted):
        identity = _read_json_source(context_root, "target/identity.json")
        metadata = _read_json_source(context_root, "context/transform-metadata.json")
        runtime = _read_json_source(context_root, "target/raw/runtime.json")
        runtime_validation = validate_context_runtime(
            runtime,
            identity,
            {
                "object": context_root / "target" / "build" / "rac_v2_contextual.bpf.o",
                "btf": extracted / "v2" / "build" / "btf-vmlinux",
                "xlated": context_root
                / "target"
                / "raw"
                / "xlated-rac_v2_contextual.txt",
            },
        )
        documents = make_stock_r_context_documents(
            v2_documents["graph"],
            v2_documents["claim"],
            v2_documents["proof"],
            dict(identity),
            dict(metadata),
        )
        result = check_certificate(
            documents["graph"],
            documents["claim"],
            documents["proof"],
        )
        hostile = (
            run_context_hostile_mutation_matrix(
                documents["graph"],
                documents["claim"],
                documents["proof"],
            )
            if result.get("status") == "CERTIFIED"
            else None
        )
        contexts.append(
            {
                "root": context_root.name,
                "identity": dict(identity),
                "metadata": dict(metadata),
                "runtime_validation": runtime_validation,
                "documents": documents,
                "result": result,
                "hostile_matrix": hostile,
            }
        )

    return {
        "schema": RAW_REPLAY_SCHEMA,
        "v1": {"documents": v1_documents, "result": v1_result},
        "v2": {
            "documents": v2_documents,
            "result": v2_result,
            "hostile_matrix": v2_hostile,
        },
        "contexts": contexts,
    }


def _claim_field(result: Mapping[str, object], path: tuple[str, ...]) -> object:
    current: object = result.get("claim")
    for field in path:
        if not isinstance(current, Mapping):
            return None
        current = current.get(field)
    return current


def _v2_scope(result: Mapping[str, object]) -> str:
    if (
        _claim_field(result, ("quantifier",)) == "AT"
        and _claim_field(result, ("evidence_grade",)) == "OUTCOME_FREE_PRECOMMITTED"
        and _claim_field(result, ("scope", "report_authority"))
        == "OPERATIONAL_OBSERVATION"
    ):
        return "EXACT_STOCK_R_V2_QUERY"
    return "PROMOTED_OR_UNKNOWN"


def _context_scope(metadata: Mapping[str, object]) -> str:
    boundary = metadata.get("claim_boundary")
    return str(boundary) if isinstance(boundary, str) and boundary else "UNKNOWN"


def normalize_reproduction_result(raw: Mapping[str, object]) -> dict[str, object]:
    """Reduce raw replay output to a stable reviewer-facing oracle summary."""

    if raw.get("schema") != RAW_REPLAY_SCHEMA:
        raise ReproductionError("RAW_REPLAY_MALFORMED")
    v1 = raw.get("v1", {})
    v2 = raw.get("v2", {})
    if not isinstance(v1, Mapping) or not isinstance(v2, Mapping):
        raise ReproductionError("RAW_REPLAY_MALFORMED")
    v1_result = v1.get("result", {})
    v2_result = v2.get("result", {})
    if not isinstance(v1_result, Mapping) or not isinstance(v2_result, Mapping):
        raise ReproductionError("RAW_REPLAY_MALFORMED")

    v2_hostile = _hostile_summary(
        v2.get("hostile_matrix") if isinstance(v2, Mapping) else None
    )
    context_summaries: list[dict[str, object]] = []
    for raw_context in raw.get("contexts", []):
        if not isinstance(raw_context, Mapping):
            raise ReproductionError("RAW_CONTEXT_MALFORMED")
        result = raw_context.get("result", {})
        identity = raw_context.get("identity", {})
        metadata = raw_context.get("metadata", {})
        validation = raw_context.get("runtime_validation", {})
        if (
            not isinstance(result, Mapping)
            or not isinstance(identity, Mapping)
            or not isinstance(metadata, Mapping)
            or not isinstance(validation, Mapping)
        ):
            raise ReproductionError("RAW_CONTEXT_MALFORMED")
        context_summaries.append(
            {
                "root": raw_context.get("root"),
                "case_id": metadata.get("case_id", metadata.get("variant_id")),
                "status": result.get("status"),
                "assessment": result.get("assessment"),
                "scope": _context_scope(metadata),
                "quantifier": _claim_field(result, ("quantifier",)),
                "report_authority": _claim_field(result, ("scope", "report_authority")),
                "evidence_grade": _claim_field(result, ("evidence_grade",)),
                "object_sha256": identity.get("object_sha256"),
                "xlated_sha256": identity.get("xlated_sha256"),
                "certificate": result.get("certificate"),
                "runtime_validation": {
                    "status": validation.get("status"),
                    "trial_count": validation.get("trial_count"),
                },
                "hostile": _hostile_summary(raw_context.get("hostile_matrix")),
            }
        )

    unexpected = 0
    if v1_result.get("status") != "BLOCKED" or "MUST_OUTCOME_PROOF" not in set(
        v1_result.get("missing_obligations", [])
    ):
        unexpected += 1
    if (
        v2_result.get("status") != "CERTIFIED"
        or v2_result.get("assessment") != "NONFACTORING"
        or _v2_scope(v2_result) != "EXACT_STOCK_R_V2_QUERY"
        or v2_hostile["all_expected"] is not True
    ):
        unexpected += 1
    for context in context_summaries:
        if (
            context.get("status") != "CERTIFIED"
            or context.get("assessment") != "NONFACTORING"
            or context.get("scope") != "EXACT_TARGET_ONLY"
            or context.get("runtime_validation", {}).get("status") != "VERIFIED"
            or context.get("hostile", {}).get("all_expected") is not True
        ):
            unexpected += 1

    return {
        "schema": SUMMARY_SCHEMA,
        "v1": {
            "status": v1_result.get("status"),
            "unknown_kind": v1_result.get("unknown_kind"),
            "missing_obligations": sorted(
                str(item) for item in v1_result.get("missing_obligations", [])
            ),
        },
        "v2": {
            "status": v2_result.get("status"),
            "assessment": v2_result.get("assessment"),
            "scope": _v2_scope(v2_result),
            "quantifier": _claim_field(v2_result, ("quantifier",)),
            "report_authority": _claim_field(v2_result, ("scope", "report_authority")),
            "evidence_grade": _claim_field(v2_result, ("evidence_grade",)),
            "certificate": v2_result.get("certificate"),
        },
        "hostile": {"v2": v2_hostile},
        "contexts": context_summaries,
        "unexpected_results": unexpected,
    }


def _walk_expected(
    observed: object,
    expected: object,
    prefix: str,
    mismatches: list[str],
) -> None:
    if isinstance(expected, Mapping):
        if not isinstance(observed, Mapping):
            mismatches.append(prefix)
            return
        for key in sorted(expected):
            child = f"{prefix}.{key}" if prefix else str(key)
            if key not in observed:
                mismatches.append(child)
            else:
                _walk_expected(observed[key], expected[key], child, mismatches)
        return
    if isinstance(expected, list):
        if not isinstance(observed, list) or len(observed) != len(expected):
            mismatches.append(prefix)
            return
        for index, expected_item in enumerate(expected):
            child = f"{prefix}.{index}" if prefix else str(index)
            _walk_expected(observed[index], expected_item, child, mismatches)
        return
    if observed != expected:
        mismatches.append(prefix)


def _value_at(document: object, dotted_path: str) -> object:
    current = document
    for part in dotted_path.split("."):
        if isinstance(current, Mapping):
            current = current.get(part)
        elif isinstance(current, list) and part.isdigit() and int(part) < len(current):
            current = current[int(part)]
        else:
            return None
    return current


def _promotion_mismatches(observed: Mapping[str, object]) -> list[str]:
    mismatches: list[str] = []
    for path, expected in (
        ("v2.scope", "EXACT_STOCK_R_V2_QUERY"),
        ("v2.quantifier", "AT"),
        ("v2.report_authority", "OPERATIONAL_OBSERVATION"),
    ):
        value = _value_at(observed, path)
        if value is not None and value != expected:
            mismatches.append(path)

    contexts = observed.get("contexts")
    if isinstance(contexts, list):
        for index, context in enumerate(contexts):
            if not isinstance(context, Mapping):
                continue
            for key, expected in (
                ("scope", "EXACT_TARGET_ONLY"),
                ("quantifier", "AT"),
                ("report_authority", "OPERATIONAL_OBSERVATION"),
            ):
                value = context.get(key)
                if value is not None and value != expected:
                    mismatches.append(f"contexts.{index}.{key}")
    return mismatches


def compare_reproduction_summary(
    observed: Mapping[str, object],
    expected: Mapping[str, object],
) -> dict[str, object]:
    """Compare observed replay output against the frozen expected oracle."""

    mismatches: list[str] = []
    _walk_expected(observed, expected, "", mismatches)
    mismatches.extend(_promotion_mismatches(observed))
    unique = sorted(set(item for item in mismatches if item))
    return {"all_expected": not unique, "mismatches": unique}
