#!/usr/bin/env python3
"""Fail-closed source release promotion for a full platform deployment.

The helper intentionally manages only the governed source tree. Runtime data,
databases, and the canonical secret source are never copied into a release or
rollback bundle.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
from typing import Any


ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{7,127}")
MANIFEST_NAME = "source-manifest.json"
STATE_NAME = "current-release.json"
API_VERSION = "paperclip-agent-platform/v1alpha1"
SUPPORTED_API_VERSIONS = {API_VERSION, "micro-task-engine/v1alpha1"}


class TransactionError(RuntimeError):
    pass


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def safe_id(value: str, label: str) -> str:
    if not ID_PATTERN.fullmatch(value):
        raise TransactionError(f"invalid {label}")
    return value


def atomic_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_suffix(path.suffix + ".tmp")
    encoded = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode()
    with temporary.open("wb") as handle:
        handle.write(encoded)
        handle.flush()
        os.fsync(handle.fileno())
    temporary.chmod(0o600)
    temporary.replace(path)
    fsync_directory(path.parent)
    path.chmod(0o600)
    if os.geteuid() == 0:
        os.chown(path.parent, 0, 0)
        os.chown(path, 0, 0)


def fsync_directory(path: Path) -> None:
    """Persist directory entry changes when the filesystem supports it."""

    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError:
        return
    try:
        os.fsync(descriptor)
    except OSError:
        # Some filesystems do not implement directory fsync. The atomic rename
        # still provides process-crash consistency there, but not a power-loss
        # durability guarantee.
        pass
    finally:
        os.close(descriptor)


def load_object(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise TransactionError(f"invalid transaction document: {path}") from exc
    if not isinstance(value, dict):
        raise TransactionError(f"transaction document is not an object: {path}")
    return value


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def manifest_source_sha(files: list[dict[str, Any]]) -> str:
    canonical = [
        {
            "mode": int(row["mode"]),
            "path": str(row["path"]),
            "sha256": str(row["sha256"]),
        }
        for row in sorted(files, key=lambda item: str(item["path"]))
    ]
    encoded = json.dumps(canonical, separators=(",", ":"), sort_keys=True).encode()
    return hashlib.sha256(encoded).hexdigest()


def iter_files(source: Path) -> list[Path]:
    result: list[Path] = []
    for path in sorted(source.rglob("*")):
        if path.is_symlink():
            raise TransactionError(f"symlink is forbidden in governed source: {path}")
        relative = path.relative_to(source)
        if "__pycache__" in relative.parts or (
            path.is_file() and path.suffix == ".pyc"
        ):
            continue
        if path.is_file():
            result.append(path)
    return result


def build_manifest(source: Path, promotion_paths: list[str]) -> dict[str, Any]:
    if not source.is_dir():
        raise TransactionError("governed source directory is missing")
    clean_paths: list[str] = []
    for raw in promotion_paths:
        rel = Path(raw)
        if rel.is_absolute() or ".." in rel.parts or str(rel) in {"", "."}:
            raise TransactionError("invalid promotion path")
        clean_paths.append(rel.as_posix())
    if len(clean_paths) != len(set(clean_paths)):
        raise TransactionError("duplicate promotion path")
    files = [
        {
            "path": path.relative_to(source).as_posix(),
            "sha256": file_sha256(path),
            "mode": path.stat().st_mode & 0o777,
        }
        for path in iter_files(source)
    ]
    if not files:
        raise TransactionError("governed source release is empty")
    for rel in clean_paths:
        if not (source / rel).exists():
            raise TransactionError(f"promotion path is absent from source: {rel}")
    return {
        "apiVersion": API_VERSION,
        "kind": "GovernedSourceManifest",
        "sourceSha256": manifest_source_sha(files),
        "promotionPaths": clean_paths,
        "files": files,
    }


def validate_manifest(manifest: dict[str, Any]) -> None:
    if (
        manifest.get("apiVersion") not in SUPPORTED_API_VERSIONS
        or manifest.get("kind") != "GovernedSourceManifest"
    ):
        raise TransactionError("source manifest identity is invalid")
    files = manifest.get("files")
    paths = manifest.get("promotionPaths")
    if not isinstance(files, list) or not files or not isinstance(paths, list):
        raise TransactionError("source manifest inventory is invalid")
    if manifest.get("sourceSha256") != manifest_source_sha(files):
        raise TransactionError("source manifest hash is invalid")


def verify_tree(root: Path, manifest: dict[str, Any]) -> dict[str, Any]:
    validate_manifest(manifest)
    expected = {str(row["path"]): row for row in manifest["files"]}
    actual: dict[str, Path] = {}
    for raw in manifest["promotionPaths"]:
        rel = Path(str(raw))
        target = root / rel
        if not target.exists():
            raise TransactionError(f"governed path is missing: {rel.as_posix()}")
        candidates = [target] if target.is_file() else iter_files(target)
        for path in candidates:
            if path.is_symlink():
                raise TransactionError("governed source contains a symlink")
            actual[path.relative_to(root).as_posix()] = path
    if set(actual) != set(expected):
        raise TransactionError("governed source inventory drift")
    for rel, row in expected.items():
        path = actual[rel]
        if os.geteuid() == 0 and (path.stat().st_uid != 0 or path.stat().st_gid != 0):
            raise TransactionError(f"governed source owner drift: {rel}")
        if file_sha256(path) != row.get("sha256"):
            raise TransactionError(f"governed source content drift: {rel}")
        if path.stat().st_mode & 0o777 != int(row.get("mode", -1)):
            raise TransactionError(f"governed source mode drift: {rel}")
    return {
        "ok": True,
        "sourceSha256": manifest["sourceSha256"],
        "fileCount": len(expected),
    }


def release_paths(root: Path, release_id: str) -> tuple[Path, Path]:
    deploy = root / ".deploy"
    return deploy / "releases" / release_id, deploy / STATE_NAME


def verify_release(root: Path, release_id: str) -> dict[str, Any]:
    release, _ = release_paths(root, safe_id(release_id, "release ID"))
    manifest = load_object(release / MANIFEST_NAME)
    return verify_tree(release / "source", manifest)


def seal(root: Path, upload: Path, release_id: str) -> dict[str, Any]:
    release_id = safe_id(release_id, "release ID")
    release, _ = release_paths(root, release_id)
    manifest = load_object(upload / MANIFEST_NAME)
    proof = verify_tree(upload / "source", manifest)
    release.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if release.exists():
        current = verify_release(root, release_id)
        if current["sourceSha256"] != proof["sourceSha256"]:
            raise TransactionError("release ID already exists with another source")
        shutil.rmtree(upload)
        return {"action": "existing", **current}
    durable_replace(upload, release)
    return {"action": "sealed", **verify_release(root, release_id)}


def load_optional_object(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    return load_object(path)


def durable_replace(source: Path, destination: Path) -> None:
    """Atomically move a path and persist both affected directory entries."""

    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    source_parent = source.parent
    os.replace(source, destination)
    fsync_directory(destination.parent)
    if source_parent != destination.parent:
        fsync_directory(source_parent)


def move_if_present(source: Path, destination: Path) -> bool:
    if not source.exists():
        return False
    durable_replace(source, destination)
    return True


def transaction_path(root: Path, activation_id: str) -> Path:
    return root / ".deploy" / "transactions" / f"{activation_id}.json"


def transaction_manifest(
    root: Path, journal: dict[str, Any]
) -> tuple[str, str, dict[str, Any]]:
    activation_id = safe_id(str(journal.get("activationId") or ""), "activation ID")
    release_id = safe_id(str(journal.get("releaseId") or ""), "release ID")
    manifest = load_object(root / ".deploy" / "releases" / release_id / MANIFEST_NAME)
    validate_manifest(manifest)
    return activation_id, release_id, manifest


def activation_state(
    root: Path,
    journal: dict[str, Any],
    proof: dict[str, Any],
) -> dict[str, Any]:
    activation_id, release_id, _ = transaction_manifest(root, journal)
    source_sha256 = str(journal.get("sourceSha256") or "")
    if proof.get("sourceSha256") != source_sha256:
        raise TransactionError("promotion journal source hash mismatch")
    return {
        "apiVersion": API_VERSION,
        "kind": "GovernedSourceActivation",
        "status": "active",
        "runId": safe_id(str(journal.get("runId") or ""), "run ID"),
        "releaseId": release_id,
        "activationId": activation_id,
        "sourceSha256": source_sha256,
        "fileCount": proof["fileCount"],
        "backupPath": str(root / ".deploy" / "backups" / activation_id),
        "promotedAt": str(journal.get("promotedAt") or utcnow()),
        "recoveredIncompleteActivations": list(
            journal.get("recoveredIncompleteActivations") or []
        ),
    }


def commit_transaction(
    root: Path, journal_path: Path, journal: dict[str, Any]
) -> dict[str, Any]:
    """Finish a durable commit decision; safe to repeat after process loss."""

    activation_id, _, manifest = transaction_manifest(root, journal)
    if journal.get("status") not in {"committing", "active"}:
        raise TransactionError("transaction has no commit decision")
    proof = verify_tree(root, manifest)
    state_path = root / ".deploy" / STATE_NAME
    current = load_optional_object(state_path)
    if current is not None and current.get("activationId") not in {
        activation_id,
        (journal.get("previousState") or {}).get("activationId"),
    }:
        raise TransactionError("a newer source activation is already current")
    state = activation_state(root, journal, proof)
    # The current pointer is durable before the journal advertises active.
    # Thus an active journal always has a reconstructable current pointer, and
    # a committing journal can always be completed by recovery.
    atomic_json(state_path, state)
    journal.update(
        {
            "status": "active",
            "promotedAt": state["promotedAt"],
            "fileCount": proof["fileCount"],
        }
    )
    atomic_json(journal_path, journal)
    return state


def rollback_paths(
    root: Path, journal: dict[str, Any], manifest: dict[str, Any]
) -> None:
    """Restore pre-promotion paths using filesystem state as a write-ahead log.

    For every governed path, the staged release, live destination, backup and
    failed copy form an unambiguous state machine. In particular, an existing
    failed copy proves the new path was already quarantined, so a retry must
    never move the restored destination a second time.
    """

    activation_id = safe_id(str(journal.get("activationId") or ""), "activation ID")
    deploy = root / ".deploy"
    staged_root = deploy / "activations" / activation_id / "source"
    backup = deploy / "backups" / activation_id
    failed = deploy / "failed" / activation_id
    for raw in reversed(manifest["promotionPaths"]):
        rel = Path(str(raw))
        staged = staged_root / rel
        destination = root / rel
        previous = backup / rel
        rejected = failed / rel

        if rejected.exists():
            if previous.exists():
                if destination.exists():
                    raise TransactionError(
                        f"ambiguous rollback destination state: {rel.as_posix()}"
                    )
                durable_replace(previous, destination)
            continue

        # A consumed staged path proves the new release was installed. Move it
        # aside exactly once before restoring the backup.
        if not staged.exists():
            if not destination.exists():
                raise TransactionError(
                    f"ambiguous installed path during rollback: {rel.as_posix()}"
                )
            durable_replace(destination, rejected)

        if previous.exists():
            if destination.exists():
                raise TransactionError(
                    f"refusing to overwrite rollback destination: {rel.as_posix()}"
                )
            durable_replace(previous, destination)


def finalize_rollback_state(root: Path, journal: dict[str, Any]) -> None:
    activation_id = safe_id(str(journal.get("activationId") or ""), "activation ID")
    state_path = root / ".deploy" / STATE_NAME
    current = load_optional_object(state_path)
    previous = journal.get("previousState")
    if isinstance(previous, dict) and previous.get("status") == "active":
        previous_id = safe_id(
            str(previous.get("activationId") or ""), "previous activation ID"
        )
        if current is not None and current.get("activationId") not in {
            activation_id,
            previous_id,
        }:
            raise TransactionError("a newer source activation is already current")
        atomic_json(state_path, previous)
        return

    if current is not None and current.get("activationId") != activation_id:
        # A failed promotion never replaced an older current pointer. Preserve
        # that authoritative previous activation.
        return
    rolled_back = {
        "apiVersion": API_VERSION,
        "kind": "GovernedSourceActivation",
        "status": "rolledBack",
        "runId": journal.get("runId"),
        "releaseId": journal.get("releaseId"),
        "activationId": activation_id,
        "sourceSha256": journal.get("sourceSha256"),
        "rolledBackAt": utcnow(),
    }
    atomic_json(state_path, rolled_back)


def rollback_transaction(
    root: Path,
    journal_path: Path,
    journal: dict[str, Any],
    *,
    recovered: bool,
) -> dict[str, Any]:
    """Record and finish an idempotent rollback decision."""

    activation_id, _, manifest = transaction_manifest(root, journal)
    if journal.get("status") == "rolledBack":
        return {
            "status": "rolledBack",
            "activationId": activation_id,
            "sourceSha256": journal.get("sourceSha256"),
        }
    if journal.get("status") != "rollingBack":
        journal.update({"status": "rollingBack", "rollbackStartedAt": utcnow()})
        atomic_json(journal_path, journal)
    rollback_paths(root, journal, manifest)
    finalize_rollback_state(root, journal)
    journal.update({"status": "rolledBack", "rolledBackAt": utcnow()})
    if recovered:
        journal["recoveredAt"] = utcnow()
    atomic_json(journal_path, journal)
    return {
        "status": "rolledBack",
        "activationId": activation_id,
        "sourceSha256": journal.get("sourceSha256"),
    }


def recover_incomplete(root: Path) -> list[str]:
    deploy = root / ".deploy"
    journals = deploy / "transactions"
    recovered: list[str] = []
    if not journals.is_dir():
        return recovered

    # Pending decisions are resolved before any legacy active-journal repair.
    # This prevents an older active journal from being compared against the
    # tree of a newer transaction that already decided to commit.
    documents = [(path, load_object(path)) for path in sorted(journals.glob("*.json"))]
    for path, journal in documents:
        status = journal.get("status")
        if status in {"promoting", "rollingBack"}:
            activation_id = safe_id(
                str(journal.get("activationId") or ""), "activation ID"
            )
            rollback_transaction(root, path, journal, recovered=True)
            recovered.append(activation_id)
        elif status == "committing":
            activation_id = safe_id(
                str(journal.get("activationId") or ""), "activation ID"
            )
            commit_transaction(root, path, journal)
            recovered.append(activation_id)

    # Backward-compatible repair for journals produced by the old ordering,
    # which advertised active immediately before writing current-release.json.
    state_path = deploy / STATE_NAME
    if not state_path.is_file():
        candidates: list[tuple[str, Path, dict[str, Any]]] = []
        for path, original in documents:
            journal = load_object(path)
            if journal.get("status") != "active":
                continue
            try:
                _, _, manifest = transaction_manifest(root, journal)
                verify_tree(root, manifest)
            except TransactionError:
                continue
            candidates.append((str(journal.get("promotedAt") or ""), path, journal))
        if candidates:
            _, path, journal = max(candidates, key=lambda row: row[0])
            activation_id = safe_id(
                str(journal.get("activationId") or ""), "activation ID"
            )
            commit_transaction(root, path, journal)
            recovered.append(activation_id)
    return recovered


def promote(
    root: Path, release_id: str, run_id: str, activation_id: str
) -> dict[str, Any]:
    release_id = safe_id(release_id, "release ID")
    run_id = safe_id(run_id, "run ID")
    activation_id = safe_id(activation_id, "activation ID")
    recovered = recover_incomplete(root)
    release, state_path = release_paths(root, release_id)
    manifest = load_object(release / MANIFEST_NAME)
    release_proof = verify_tree(release / "source", manifest)
    deploy = root / ".deploy"
    activation = deploy / "activations" / activation_id
    backup = deploy / "backups" / activation_id
    failed = deploy / "failed" / activation_id
    for path in (activation, backup, failed):
        if path.exists():
            raise TransactionError("activation path already exists")
    activation.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    shutil.copytree(
        release / "source", activation / "source", copy_function=shutil.copy2
    )
    journal_path = deploy / "transactions" / f"{activation_id}.json"
    journal = {
        "apiVersion": API_VERSION,
        "kind": "GovernedSourcePromotionJournal",
        "status": "promoting",
        "runId": run_id,
        "releaseId": release_id,
        "activationId": activation_id,
        "sourceSha256": release_proof["sourceSha256"],
        "startedAt": utcnow(),
    }
    previous_state = load_optional_object(state_path)
    if previous_state is not None and previous_state.get("status") == "active":
        journal["previousState"] = previous_state
    atomic_json(journal_path, journal)
    try:
        for raw in manifest["promotionPaths"]:
            rel = Path(str(raw))
            source = activation / "source" / rel
            destination = root / rel
            move_if_present(destination, backup / rel)
            destination.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
            durable_replace(source, destination)
        current_proof = verify_tree(root, manifest)
    except Exception:
        rollback_transaction(root, journal_path, journal, recovered=False)
        raise
    journal.update(
        {
            "status": "committing",
            "commitStartedAt": utcnow(),
            "promotedAt": utcnow(),
            "fileCount": current_proof["fileCount"],
            "recoveredIncompleteActivations": recovered,
        }
    )
    atomic_json(journal_path, journal)
    return commit_transaction(root, journal_path, journal)


def verify_current(root: Path, release_id: str, activation_id: str) -> dict[str, Any]:
    release_id = safe_id(release_id, "release ID")
    activation_id = safe_id(activation_id, "activation ID")
    release, state_path = release_paths(root, release_id)
    state = load_object(state_path)
    if (
        state.get("status") != "active"
        or state.get("releaseId") != release_id
        or state.get("activationId") != activation_id
    ):
        raise TransactionError("current source activation identity mismatch")
    manifest = load_object(release / MANIFEST_NAME)
    proof = verify_tree(root, manifest)
    if proof["sourceSha256"] != state.get("sourceSha256"):
        raise TransactionError("current source activation hash mismatch")
    return {"status": "active", **proof}


def rollback(root: Path, activation_id: str) -> dict[str, Any]:
    activation_id = safe_id(activation_id, "activation ID")
    recover_incomplete(root)
    deploy = root / ".deploy"
    state_path = deploy / STATE_NAME
    state = load_optional_object(state_path)
    journal_path = transaction_path(root, activation_id)
    journal = load_object(journal_path)
    if journal.get("status") == "rolledBack":
        return {
            "status": "rolledBack",
            "activationId": activation_id,
            "sourceSha256": journal.get("sourceSha256"),
        }
    if (
        state is None
        or state.get("activationId") != activation_id
        or state.get("status") != "active"
    ):
        raise TransactionError("refusing rollback of a non-current activation")
    return rollback_transaction(root, journal_path, journal, recovered=False)


def inspect_activation(root: Path, activation_id: str) -> dict[str, Any]:
    activation_id = safe_id(activation_id, "activation ID")
    state = load_optional_object(root / ".deploy" / STATE_NAME)
    journal = load_optional_object(transaction_path(root, activation_id))
    current_id = state.get("activationId") if state is not None else None
    current = current_id == activation_id and state.get("status") == "active"
    return {
        "status": "current" if current else "notCurrent",
        "activationId": activation_id,
        "current": current,
        "currentActivationId": current_id,
        "currentStatus": state.get("status") if state is not None else None,
        "journalStatus": journal.get("status") if journal is not None else None,
        "releaseId": journal.get("releaseId") if journal is not None else None,
        "sourceSha256": journal.get("sourceSha256") if journal is not None else None,
    }


def rollback_if_current(root: Path, activation_id: str) -> dict[str, Any]:
    activation_id = safe_id(activation_id, "activation ID")
    recovered = recover_incomplete(root)
    inspected = inspect_activation(root, activation_id)
    if inspected["current"]:
        return {"action": "rolledBack", **rollback(root, activation_id)}
    if inspected["journalStatus"] == "rolledBack":
        return {
            "action": "alreadyRolledBack",
            "status": "rolledBack",
            "activationId": activation_id,
            "sourceSha256": inspected["sourceSha256"],
            "recoveredIncompleteActivations": recovered,
        }
    return {
        "action": "notCurrent",
        **inspected,
        "recoveredIncompleteActivations": recovered,
    }


def checkpoint(
    root: Path,
    *,
    run_id: str,
    release_id: str,
    activation_id: str,
    source_sha256: str,
    status: str,
    step: str,
    next_step: str,
    attempt: int,
) -> dict[str, Any]:
    safe_id(run_id, "run ID")
    safe_id(release_id, "release ID")
    safe_id(activation_id, "activation ID")
    if not re.fullmatch(r"[0-9a-f]{64}", source_sha256):
        raise TransactionError("invalid source hash")
    if status not in {"running", "failed", "completed"}:
        raise TransactionError("invalid checkpoint status")
    payload = {
        "apiVersion": API_VERSION,
        "kind": "PlatformDeployCheckpoint",
        "runId": run_id,
        "releaseId": release_id,
        "activationId": activation_id,
        "sourceSha256": source_sha256,
        "status": status,
        "completedStep": step or None,
        "nextStep": next_step or None,
        "attempt": attempt,
        "updatedAt": utcnow(),
    }
    path = root / ".deploy" / "runs" / f"{run_id}.json"
    atomic_json(path, payload)
    return {"status": status, "checkpoint": str(path)}


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    result.add_argument("--root", type=Path, required=True)
    subs = result.add_subparsers(dest="command", required=True)
    seal_parser = subs.add_parser("seal")
    seal_parser.add_argument("--upload", type=Path, required=True)
    seal_parser.add_argument("--release-id", required=True)
    verify_release_parser = subs.add_parser("verify-release")
    verify_release_parser.add_argument("--release-id", required=True)
    promote_parser = subs.add_parser("promote")
    promote_parser.add_argument("--release-id", required=True)
    promote_parser.add_argument("--run-id", required=True)
    promote_parser.add_argument("--activation-id", required=True)
    verify_parser = subs.add_parser("verify-current")
    verify_parser.add_argument("--release-id", required=True)
    verify_parser.add_argument("--activation-id", required=True)
    inspect_parser = subs.add_parser("inspect-activation")
    inspect_parser.add_argument("--activation-id", required=True)
    rollback_parser = subs.add_parser("rollback")
    rollback_parser.add_argument("--activation-id", required=True)
    rollback_if_current_parser = subs.add_parser("rollback-if-current")
    rollback_if_current_parser.add_argument("--activation-id", required=True)
    checkpoint_parser = subs.add_parser("checkpoint")
    checkpoint_parser.add_argument("--run-id", required=True)
    checkpoint_parser.add_argument("--release-id", required=True)
    checkpoint_parser.add_argument("--activation-id", required=True)
    checkpoint_parser.add_argument("--source-sha256", required=True)
    checkpoint_parser.add_argument(
        "--status", choices=("running", "failed", "completed"), required=True
    )
    checkpoint_parser.add_argument("--step", default="")
    checkpoint_parser.add_argument("--next-step", default="")
    checkpoint_parser.add_argument("--attempt", type=int, required=True)
    return result


def main() -> int:
    args = parser().parse_args()
    try:
        if args.command == "seal":
            value = seal(args.root, args.upload, args.release_id)
        elif args.command == "verify-release":
            value = verify_release(args.root, args.release_id)
        elif args.command == "promote":
            value = promote(args.root, args.release_id, args.run_id, args.activation_id)
        elif args.command == "verify-current":
            value = verify_current(args.root, args.release_id, args.activation_id)
        elif args.command == "inspect-activation":
            value = inspect_activation(args.root, args.activation_id)
        elif args.command == "rollback":
            value = rollback(args.root, args.activation_id)
        elif args.command == "rollback-if-current":
            value = rollback_if_current(args.root, args.activation_id)
        elif args.command == "checkpoint":
            value = checkpoint(
                args.root,
                run_id=args.run_id,
                release_id=args.release_id,
                activation_id=args.activation_id,
                source_sha256=args.source_sha256,
                status=args.status,
                step=args.step,
                next_step=args.next_step,
                attempt=args.attempt,
            )
        else:  # pragma: no cover - argparse rejects unknown commands.
            raise TransactionError("unsupported transaction command")
    except (OSError, KeyError, TransactionError, ValueError) as exc:
        print(json.dumps({"ok": False, "errorType": type(exc).__name__}))
        return 1
    print(json.dumps({"ok": True, **value}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
