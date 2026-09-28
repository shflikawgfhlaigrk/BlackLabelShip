#!/usr/bin/env python3
"""Encrypted, independently readable R2 copy of one BlackLabel-Team source rescue.

The source-rescue namespace and latest pointer are separate from database backups.
Only encrypted parts, manifest, and pointer leave this machine.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import tempfile
import uuid

if __package__:
    from . import encrypted_snapshot as base
else:
    import encrypted_snapshot as base


SCHEMA = "blacklabel.encrypted-source-rescue.v1"
NAMES = frozenset({
    "team-local-257-commits.bundle",
    "team-working-tree.patch.gz",
    "team-untracked.tar.gz",
    "SHA256SUMS",
    "RESCUE-RECEIPT.json",
})
PREFIX = r"source-rescue-v1/[0-9]{4}-[0-9]{2}-[0-9]{2}/[a-f0-9]{32}"
LATEST = "source-rescue-v1/LATEST.gpg"


def inspect(directory: Path) -> dict:
    directory = directory.resolve(strict=True)
    if not re.fullmatch(r"source-rescue-[0-9]{4}-[0-9]{2}-[0-9]{2}", directory.name):
        raise base.BackupError("Source rescue directory name is invalid")
    expected = {}
    for line in (directory / "SHA256SUMS").read_text("ascii").splitlines():
        match = re.fullmatch(r"([a-f0-9]{64})  (team-local-257-commits\.bundle|team-working-tree\.patch\.gz|team-untracked\.tar\.gz)", line)
        if not match or match[2] in expected:
            raise base.BackupError("Source rescue checksum manifest is invalid")
        expected[match[2]] = match[1]
    if set(expected) != NAMES - {"SHA256SUMS", "RESCUE-RECEIPT.json"}:
        raise base.BackupError("Source rescue checksum manifest is incomplete")
    receipt = json.loads((directory / "RESCUE-RECEIPT.json").read_text())
    if receipt.get("artifacts_sha256") != expected or receipt.get("source_repo") != "BlackLabel-Team":
        raise base.BackupError("Source rescue receipt does not bind the checksum manifest")
    rows = []
    for name in sorted(NAMES):
        path = directory / name
        identity = base.source_identity(path)
        sha = expected.get(name) or base.digest(path)
        rows.append({"name": name, "sha256": sha, "source_identity": identity})
    return {"directory": str(directory), "date": directory.name[-10:], "rows": rows,
            "manifest_sha256": base.digest(directory / "SHA256SUMS")}


def _validate_manifest(manifest: dict, prefix: str) -> dict:
    if manifest.get("schema") != SCHEMA or manifest.get("prefix") != prefix or not re.fullmatch(PREFIX, prefix):
        raise base.BackupError("Encrypted source rescue manifest identity is invalid")
    files = manifest.get("files")
    if not isinstance(files, list) or {f.get("name") for f in files if isinstance(f, dict)} != NAMES or len(files) != len(NAMES):
        raise base.BackupError("Encrypted source rescue file set is incomplete")
    for entry in files:
        if not isinstance(entry.get("bytes"), int) or entry["bytes"] <= 0 or not re.fullmatch(base.HASH, entry.get("sha256", "")):
            raise base.BackupError("Encrypted source rescue file metadata is invalid")
        parts = entry.get("parts")
        if not isinstance(parts, list) or not parts:
            raise base.BackupError("Encrypted source rescue has a file without parts")
        for number, part in enumerate(parts):
            if part.get("key") != f"{prefix}/artifacts/{entry['name']}/{number:06d}.gpg":
                raise base.BackupError("Encrypted source rescue part key is invalid")
            if not 0 < part.get("bytes", 0) <= base.CHUNK_BYTES or not re.fullmatch(base.HASH, part.get("sha256", "")):
                raise base.BackupError("Encrypted source rescue part metadata is invalid")
    return manifest


def load_manifest(store, crypto, work: Path, prefix: str | None = None) -> dict:
    pointer = None
    if prefix is None:
        cipher = work / "pointer.gpg"
        store.get(LATEST, cipher, base.MAX_MANIFEST_BYTES)
        pointer = crypto.decrypt_json(cipher)
        prefix = pointer.get("prefix")
        if pointer.get("schema") != SCHEMA + ".pointer" or not isinstance(prefix, str) or not re.fullmatch(PREFIX, prefix):
            raise base.BackupError("Encrypted source rescue pointer is invalid")
    elif not re.fullmatch(PREFIX, prefix):
        raise base.BackupError("Encrypted source rescue prefix is invalid")
    cipher = work / "manifest.gpg"
    store.get(prefix + "/manifest.json.gpg", cipher, base.MAX_MANIFEST_BYTES)
    if pointer:
        meta = pointer.get("manifest", {})
        if meta.get("key") != prefix + "/manifest.json.gpg" or meta.get("cipher_sha256") != base.digest(cipher) or meta.get("cipher_bytes") != cipher.stat().st_size:
            raise base.BackupError("Encrypted source rescue pointer binding is invalid")
    return _validate_manifest(crypto.decrypt_json(cipher), prefix)


def upload(snapshot: dict, store, crypto, work: Path, state: Path, chunk_bytes: int) -> dict:
    if not 1 <= chunk_bytes <= base.CHUNK_BYTES:
        raise base.BackupError("Source rescue chunk size is invalid")
    binding = {"snapshot": snapshot, "store": store.identity, "chunk_bytes": chunk_bytes}
    journal = state / (hashlib.sha256(base.encode(binding)).hexdigest() + ".json")
    with base.journal_lock(journal):
        if journal.exists():
            base.secret_file(journal)
            progress = json.loads(journal.read_text())
            if progress.get("binding") != binding:
                raise base.BackupError("Source rescue journal binding changed")
        else:
            progress = {"binding": binding, "prefix": f"source-rescue-v1/{snapshot['date']}/{uuid.uuid4().hex}",
                        "started_at": base.utc(), "parts": {}, "status": "running"}
            base.save_json(journal, progress)
        prefix = progress["prefix"]
        if not re.fullmatch(PREFIX, prefix):
            raise base.BackupError("Source rescue journal prefix is invalid")
        if progress["status"] == "complete":
            report = verify(store, crypto, work)
            if report["prefix"] != prefix:
                raise base.BackupError("Source rescue latest pointer changed")
            return report
        cipher = work / "upload.gpg"
        files = []
        try:
            for row in snapshot["rows"]:
                path = Path(snapshot["directory"]) / row["name"]
                if base.source_identity(path) != row["source_identity"]:
                    raise base.BackupError("Source rescue file changed before upload")
                digest, size, parts = hashlib.sha256(), 0, []
                with path.open("rb") as source:
                    for number, data in enumerate(iter(lambda: source.read(chunk_bytes), b"")):
                        digest.update(data)
                        size += len(data)
                        expected = {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
                        key = f"{prefix}/artifacts/{row['name']}/{number:06d}.gpg"
                        part = progress["parts"].get(key)
                        if part:
                            if any(part.get(k) != v for k, v in expected.items()):
                                raise base.BackupError("Resumed source rescue part differs")
                            base.fetch_part(store, part, crypto, work)
                        else:
                            crypto.encrypt(data, cipher)
                            part = base.verified_put(store, key, cipher, crypto, work, expected)
                            progress["parts"][key] = part
                            base.save_json(journal, progress)
                        parts.append(part)
                        cipher.unlink(missing_ok=True)
                        print(json.dumps({"event": "part_verified", "file": row["name"], "part": number,
                                          "verified_parts": len(progress["parts"]), "at": base.utc()}), flush=True)
                if base.source_identity(path) != row["source_identity"] or digest.hexdigest() != row["sha256"] or size != row["source_identity"][2]:
                    raise base.BackupError("Whole source rescue file differs from manifest")
                files.append({"name": row["name"], "bytes": size, "sha256": row["sha256"], "parts": parts})
            manifest = _validate_manifest({"schema": SCHEMA, "prefix": prefix, "files": files,
                                           "source_manifest_sha256": snapshot["manifest_sha256"],
                                           "started_at": progress["started_at"], "verified_at": base.utc()}, prefix)
            raw = base.encode(manifest)
            if len(raw) > base.MAX_MANIFEST_BYTES:
                raise base.BackupError("Source rescue encrypted manifest exceeds bound")
            meta = progress.get("manifest")
            if meta:
                previous = load_manifest(store, crypto, work, prefix)
                if previous["files"] != files or previous["source_manifest_sha256"] != snapshot["manifest_sha256"]:
                    raise base.BackupError("Published source rescue manifest differs from resumed source")
                base.fetch_part(store, meta, crypto, work)
            else:
                crypto.encrypt(raw, cipher)
                meta = base.verified_put(store, prefix + "/manifest.json.gpg", cipher, crypto, work,
                                         {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()})
                progress["manifest"] = meta
                base.save_json(journal, progress)
            pointer = base.encode({"schema": SCHEMA + ".pointer", "prefix": prefix, "manifest": meta})
            crypto.encrypt(pointer, cipher)
            base.verified_put(store, LATEST, cipher, crypto, work,
                              {"bytes": len(pointer), "sha256": hashlib.sha256(pointer).hexdigest()})
            progress.update({"status": "complete", "completed_at": base.utc(), "manifest": meta})
            base.save_json(journal, progress)
            report = verify(store, crypto, work)
            if report["prefix"] != prefix:
                raise base.BackupError("Source rescue latest pointer changed")
            return report
        except Exception:
            progress.update({"status": "incomplete", "last_failure_at": base.utc()})
            base.save_json(journal, progress)
            raise
        finally:
            cipher.unlink(missing_ok=True)


def verify(store, crypto, work: Path, prefix: str | None = None, destination: Path | None = None) -> dict:
    manifest = load_manifest(store, crypto, work, prefix)
    destination = destination.absolute() if destination else None
    if destination and (destination.exists() or destination.is_symlink()):
        raise base.BackupError("Source rescue restore destination exists")
    parent = destination.parent if destination else work
    stage = Path(tempfile.mkdtemp(prefix=".source-rescue-restore-", dir=parent))
    try:
        result = []
        for entry in manifest["files"]:
            target = stage / entry["name"]
            with target.open("xb") as sink:
                for part in entry["parts"]:
                    base.fetch_part(store, part, crypto, work, sink)
            if target.stat().st_size != entry["bytes"] or base.digest(target) != entry["sha256"]:
                raise base.BackupError("Restored source rescue file checksum differs")
            result.append({"name": entry["name"], "bytes": entry["bytes"], "sha256": entry["sha256"]})
        report = {"status": "passed", "operation": "restore" if destination else "verify",
                  "prefix": manifest["prefix"], "store": store.identity,
                  "files": result, "verified_parts": sum(len(f["parts"]) for f in manifest["files"]),
                  "finished_at": base.utc()}
        if destination:
            base.save_json(stage / "OFFSITE-RESTORE-RECEIPT.json", report)
            base.publish_restored_directory(stage, destination)
        return report
    finally:
        if stage.exists():
            shutil.rmtree(stage)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("upload", "verify", "restore", "inspect"))
    parser.add_argument("--source-dir", type=Path)
    parser.add_argument("--prefix")
    parser.add_argument("--destination", type=Path)
    parser.add_argument("--state-dir", type=Path, required=True)
    parser.add_argument("--key-file", type=Path, default=Path.home() / ".utah/secrets/backup-key.txt")
    parser.add_argument("--credential-file", type=Path, default=Path.home() / ".wrangler/config/default.toml")
    parser.add_argument("--account", default="a0703c8cbbf2d56af47d05d5817b8c5b")
    parser.add_argument("--bucket", default="blacklabel-backups")
    parser.add_argument("--local-store", type=Path)
    parser.add_argument("--chunk-bytes", type=int, default=64 * 1024 * 1024)
    parser.add_argument("--receipt", type=Path)
    args = parser.parse_args(argv)
    os.umask(0o077)
    try:
        if args.operation == "inspect":
            if not args.source_dir:
                parser.error("--source-dir is required")
            report = inspect(args.source_dir)
        else:
            state = base.private_dir(args.state_dir)
            with tempfile.TemporaryDirectory(prefix="source-rescue-", dir=state) as scratch:
                work = Path(scratch)
                crypto = base.GPG(args.key_file, work)
                store = base.LocalStore(args.local_store) if args.local_store else base.R2Store(args.account, args.bucket, args.credential_file)
                if args.operation == "upload":
                    if not args.source_dir:
                        parser.error("--source-dir is required")
                    report = upload(inspect(args.source_dir), store, crypto, work, state, args.chunk_bytes)
                else:
                    report = verify(store, crypto, work, args.prefix, args.destination if args.operation == "restore" else None)
        if args.receipt:
            base.save_json(args.receipt, report)
        print(json.dumps(report, sort_keys=True), flush=True)
        return 0
    except Exception as error:
        report = {"status": "failed", "operation": args.operation, "error_type": type(error).__name__,
                  "error": str(error) if isinstance(error, base.BackupError) else "Inspect local inputs and connectivity",
                  "finished_at": base.utc()}
        if args.receipt:
            base.save_json(args.receipt, report)
        print(json.dumps(report, sort_keys=True), flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
