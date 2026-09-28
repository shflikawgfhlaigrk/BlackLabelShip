#!/usr/bin/env python3
"""Bounded, authenticated, encrypted R2 snapshots with verified readback.

Only ciphertext leaves the machine. Each part is OpenPGP AES-256 with an MDC;
the encrypted manifest binds ordering, names, sizes and plaintext/cipher hashes.
No latest pointer is published until every remote part has been decrypted and
matched to its source. Restores are staged privately and published atomically.
"""
import argparse
import contextlib
import ctypes
import datetime as dt
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

SCHEMA = "blacklabel.encrypted-snapshot.v1"
CHUNK_BYTES = 290 * 1024 * 1024
MAX_PART_BYTES = 300 * 1024 * 1024
MAX_MANIFEST_BYTES = 8 * 1024 * 1024
STAMP = r"[0-9]{8}T[0-9]{6}Z"
HASH = r"[a-f0-9]{64}"
PREFIX = rf"encrypted-(?:canary-)?v1/[0-9]{{4}}-[0-9]{{2}}-[0-9]{{2}}/{STAMP}/[a-f0-9]{{32}}"
REQUEST_SECONDS = 180
OAUTH_MARGIN_SECONDS = 30
OAUTH_WAIT_SECONDS = REQUEST_SECONDS + OAUTH_MARGIN_SECONDS + 2


class BackupError(Exception):
    pass


def utc():
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def digest(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as source:
        for data in iter(lambda: source.read(1024 * 1024), b""):
            h.update(data)
    return h.hexdigest()


def encode(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def private_dir(path):
    path = Path(path)
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise BackupError("Working directory must be owner-only and not a symlink")
    return path


def save_json(path, value):
    path = Path(path)
    fd, tmp = tempfile.mkstemp(prefix=".receipt-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as output:
            output.write(encode(value))
            output.flush()
            os.fsync(output.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def secret_file(path):
    path = Path(path)
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise BackupError("Credential file must be a regular owner-only file")
    return path


def source_identity(path):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_size == 0:
        raise BackupError("Snapshot member must be a nonempty regular file")
    return [info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns]


def read_snapshot(directory, manifest=None):
    directory = Path(directory).resolve(strict=True)
    if manifest is None:
        manifests = sorted(directory.glob("SHA256SUMS.*"))
        if not manifests:
            raise BackupError("No completed snapshot manifest")
        manifest = manifests[-1].name
    match = re.fullmatch(rf"SHA256SUMS\.({STAMP})", manifest)
    if not match:
        raise BackupError("Invalid snapshot manifest identity")
    stamp = match[1]
    date = dt.datetime.strptime(stamp, "%Y%m%dT%H%M%SZ").strftime("%Y-%m-%d")
    if directory.name != date:
        raise BackupError("Snapshot directory and stamp dates differ")
    path = directory / manifest
    source_identity(path)
    if path.stat().st_size > 4096:
        raise BackupError("Oversized snapshot manifest")
    raw = path.read_bytes()
    expected = {f"blacklabel-{stamp}.dump", f"utah-{stamp}.dump", f"brain-state-{stamp}.tar.gz"}
    rows = []
    for line in raw.decode("ascii").splitlines():
        row = re.fullmatch(rf"({HASH})\s+\*?(?:\./)?([^/]+)", line)
        if not row or row[2] not in expected:
            raise BackupError("Invalid snapshot checksum member")
        rows.append({"name": row[2], "sha256": row[1], "source_identity": source_identity(directory / row[2])})
    if len(rows) != 3 or {row["name"] for row in rows} != expected:
        raise BackupError("Incomplete or duplicate snapshot checksum members")
    return {"stamp": stamp, "date": date, "manifest_sha256": hashlib.sha256(raw).hexdigest(),
            "rows": sorted(rows, key=lambda row: row["name"]), "directory": str(directory)}


class GPG:
    def __init__(self, keyfile, work, binary=None):
        self.keyfile = secret_file(keyfile)
        lines = self.keyfile.read_bytes().splitlines()
        if not lines or not 16 <= len(lines[0]) <= 1024:
            raise BackupError("Backup passphrase length is outside the supported range")
        self.home = private_dir(Path(work) / "gnupg")
        if binary is None:
            binary = next((path for path in ("/opt/homebrew/bin/gpg", "/usr/bin/gpg")
                           if os.path.isfile(path) and os.access(path, os.X_OK)), None)
        if binary is None:
            raise BackupError("GPG executable is unavailable")
        self.binary = str(binary)

    def command(self):
        secret_file(self.keyfile)
        return [self.binary, "--no-options", "--homedir", str(self.home), "--batch", "--no-tty",
                "--no-autostart", "--pinentry-mode", "loopback", "--no-symkey-cache",
                "--passphrase-file", str(self.keyfile), "--status-fd", "2"]

    def encrypt(self, data, output):
        # Ciphertext is the only on-disk part produced by upload.
        with Path(output).open("wb") as target:
            result = subprocess.run(self.command() + ["--symmetric", "--cipher-algo", "AES256",
                "--force-mdc", "--compress-algo", "none", "--s2k-digest-algo", "SHA256",
                "--s2k-mode", "3", "--s2k-count", "65011712", "--output", "-"],
                input=data, stdout=target, stderr=subprocess.PIPE, timeout=300)
        if result.returncode or b"[GNUPG:] END_ENCRYPTION" not in result.stderr:
            raise BackupError("GPG encryption failed; no plaintext fallback")
        if Path(output).stat().st_size > MAX_PART_BYTES:
            raise BackupError("Encrypted part exceeds the R2 single-object limit")

    def decrypt(self, cipher, sink=None, limit=CHUNK_BYTES):
        # Plaintext may enter a private restore staging file, but is never
        # published until GOODMDC, every part hash and the whole-file hash pass.
        h, size = hashlib.sha256(), 0
        with tempfile.TemporaryFile(dir=self.home.parent) as status:
            process = subprocess.Popen(self.command() + ["--decrypt", str(cipher)],
                                       stdout=subprocess.PIPE, stderr=status)
            try:
                for data in iter(lambda: process.stdout.read(1024 * 1024), b""):
                    size += len(data)
                    if size > limit:
                        raise BackupError("Decrypted data exceeds its bound")
                    h.update(data)
                    if sink is not None:
                        sink.write(data)
                process.stdout.close()
                code = process.wait(timeout=300)
            finally:
                if process.poll() is None:
                    # This is exactly the GPG child created above, never shared infrastructure.
                    process.kill()
                    process.wait()
                if process.stdout:
                    process.stdout.close()
            status.seek(0)
            messages = status.read()
        if code or b"[GNUPG:] DECRYPTION_OKAY" not in messages or b"[GNUPG:] GOODMDC" not in messages:
            raise BackupError("Encrypted data failed authentication/decryption")
        return {"bytes": size, "sha256": h.hexdigest()}

    def decrypt_json(self, cipher):
        import io
        target = io.BytesIO()
        self.decrypt(cipher, target, MAX_MANIFEST_BYTES)
        return json.loads(target.getvalue())


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise BackupError("Refused an authenticated API redirect")


def require_request_runner():
    """Reject unsupported callers before credential reads, waits or refreshes."""
    if threading.current_thread() is not threading.main_thread():
        raise BackupError("R2 requests require the bounded main-thread runner")
    if signal.getitimer(signal.ITIMER_REAL) != (0.0, 0.0):
        raise BackupError("Existing alarm prevents an independent R2 deadline")


@contextlib.contextmanager
def request_deadline():
    """Bound connection, upload and the entire response body on this CLI thread."""
    require_request_runner()
    previous = signal.getsignal(signal.SIGALRM)
    def expired(_signum, _frame):
        raise BackupError("R2 request wall deadline exceeded")
    signal.signal(signal.SIGALRM, expired)
    try:
        signal.setitimer(signal.ITIMER_REAL, REQUEST_SECONDS)
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


class R2Store:
    def __init__(self, account, bucket, credential_file):
        if not re.fullmatch(r"[a-f0-9]{32}", account) or not re.fullmatch(r"[a-z0-9-]{3,63}", bucket):
            raise BackupError("Invalid R2 destination")
        self.account, self.bucket = account, bucket
        self.credential_file = secret_file(credential_file)
        self.identity = f"r2://{account}/{bucket}"
        self.opener = urllib.request.build_opener(NoRedirect())

    def refresh_oauth(self):
        if self.credential_file != Path.home() / ".wrangler/config/default.toml":
            raise BackupError("Automatic OAuth refresh is limited to the current Wrangler login")
        npx = shutil.which("npx") or "/opt/homebrew/bin/npx"
        environment = {k: v for k, v in os.environ.items() if k not in
                       {"CLOUDFLARE_API_TOKEN", "CF_API_TOKEN", "CLOUDFLARE_API_KEY", "CF_API_KEY", "CLOUDFLARE_EMAIL", "CF_EMAIL"}}
        environment["WRANGLER_SEND_METRICS"] = "false"
        # Use normal provider refresh; never an archived login or a new UI login.
        try:
            result = subprocess.run([npx, "--yes", "wrangler@4.131.1", "whoami"],
                                    cwd=Path.home(), env=environment, stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL, timeout=120)
        except (subprocess.TimeoutExpired, OSError):
            raise BackupError("Current Wrangler OAuth refresh did not finish") from None
        if result.returncode:
            raise BackupError("Current Wrangler OAuth refresh failed")

    def token(self):
        # Supports a dedicated token file, or the current protected Wrangler OAuth file.
        raw = secret_file(self.credential_file).read_text().strip()
        if self.credential_file.suffix == ".toml":
            deadline = time.monotonic() + OAUTH_WAIT_SECONDS
            refreshed = False
            while True:
                expiry = re.search(r'^expiration_time\s*=\s*"([^"\r\n]+)"', raw, re.M)
                match = re.search(r'^oauth_token\s*=\s*"([^"\r\n]+)"', raw, re.M)
                if not expiry or not match:
                    raise BackupError("Wrangler OAuth credential or expiry is absent")
                try:
                    expires = dt.datetime.fromisoformat(expiry[1].replace("Z", "+00:00"))
                    if expires.tzinfo is None:
                        raise ValueError()
                except ValueError:
                    raise BackupError("Wrangler OAuth expiry is invalid") from None
                remaining = (expires - dt.datetime.now(dt.timezone.utc)).total_seconds()
                if remaining >= REQUEST_SECONDS + OAUTH_MARGIN_SECONDS:
                    return match[1]
                if refreshed:
                    raise BackupError("Wrangler OAuth has insufficient lifetime after normal refresh")
                if remaining <= 0:
                    self.refresh_oauth()
                    refreshed = True
                else:
                    # Wrangler only refreshes expired tokens. Wait, re-reading for
                    # concurrent normal refresh, without altering credential metadata.
                    budget = deadline - time.monotonic()
                    if budget <= 0:
                        raise BackupError("Wrangler OAuth validity wait deadline exceeded")
                    time.sleep(min(5, remaining + 0.1, budget))
                raw = secret_file(self.credential_file).read_text().strip()
        if not raw or "\n" in raw:
            raise BackupError("Invalid dedicated R2 token file")
        return raw

    @contextlib.contextmanager
    def request(self, key, method, source=None):
        require_request_runner()
        if not re.fullmatch(r"[A-Za-z0-9._/-]+", key) or ".." in key.split("/"):
            raise BackupError("Invalid R2 object key")
        url = (f"https://api.cloudflare.com/client/v4/accounts/{self.account}/r2/buckets/"
               f"{self.bucket}/objects/" + urllib.parse.quote(key, safe="/"))
        headers = {"Authorization": "Bearer " + self.token(), "Cache-Control": "no-cache, no-store",
                   "User-Agent": "BlackLabelEncryptedBackup/1", "Accept-Encoding": "identity"}
        if source is not None:
            headers.update({"Content-Type": "application/octet-stream", "Content-Length": str(os.fstat(source.fileno()).st_size)})
        with request_deadline():
            with self.opener.open(urllib.request.Request(url, data=source, method=method, headers=headers), timeout=REQUEST_SECONDS) as response:
                yield response

    def put(self, key, path):
        for attempt in range(3):
            try:
                with Path(path).open("rb") as data, self.request(key, "PUT", data) as reply:
                    raw = reply.read(1024 * 1024)
                    if raw:
                        value = json.loads(raw)
                        if value.get("success") is not True:
                            raise BackupError("R2 PUT did not report success")
                    return
            except urllib.error.HTTPError as error:
                if error.code not in (408, 429, 500, 502, 503, 504) or attempt == 2:
                    raise BackupError(f"R2 PUT HTTP {error.code}") from None
            except (urllib.error.URLError, TimeoutError, OSError):
                if attempt == 2:
                    raise BackupError("R2 PUT transport failed") from None
            except BackupError as error:
                if str(error) != "R2 request wall deadline exceeded" or attempt == 2:
                    raise
            time.sleep(2 ** attempt)

    def get(self, key, path, limit):
        for attempt in range(3):
            try:
                with self.request(key, "GET") as response, Path(path).open("wb") as target:
                    length = response.headers.get("Content-Length")
                    if length and int(length) > limit:
                        raise BackupError("Remote object exceeds its bound")
                    size = 0
                    for data in iter(lambda: response.read(1024 * 1024), b""):
                        size += len(data)
                        if size > limit:
                            raise BackupError("Remote object exceeds its bound")
                        target.write(data)
                return
            except urllib.error.HTTPError as error:
                if error.code not in (408, 429, 500, 502, 503, 504) or attempt == 2:
                    raise BackupError(f"R2 GET HTTP {error.code}") from None
            except (urllib.error.URLError, TimeoutError, OSError):
                if attempt == 2:
                    raise BackupError("R2 GET transport failed") from None
            except BackupError as error:
                if str(error) != "R2 request wall deadline exceeded" or attempt == 2:
                    raise
            time.sleep(2 ** attempt)


class LocalStore:
    """Explicit offline test/DR store; never selected by production defaults."""
    def __init__(self, root):
        self.root = private_dir(root)
        self.identity = "local:" + str(self.root.resolve())

    def path(self, key):
        path = self.root / key
        if not path.resolve().is_relative_to(self.root.resolve()):
            raise BackupError("Object path escapes the store")
        return path

    def put(self, key, path):
        dest = self.path(key)
        dest.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        shutil.copyfile(path, dest)

    def get(self, key, path, limit):
        source = self.path(key)
        if source.stat().st_size > limit:
            raise BackupError("Remote object exceeds its bound")
        shutil.copyfile(source, path)


def verified_put(store, key, cipher, crypto, work, expected):
    remote = Path(work) / "readback.gpg"
    cipher_hash, cipher_size = digest(cipher), Path(cipher).stat().st_size
    store.put(key, cipher)
    try:
        store.get(key, remote, cipher_size)
        if remote.stat().st_size != cipher_size or digest(remote) != cipher_hash:
            raise BackupError("Remote ciphertext readback mismatch")
        if crypto.decrypt(remote, limit=expected["bytes"]) != expected:
            raise BackupError("Remote plaintext readback mismatch")
    finally:
        remote.unlink(missing_ok=True)
    return {"key": key, "cipher_bytes": cipher_size, "cipher_sha256": cipher_hash,
            **expected, "verified_at": utc()}


def fetch_part(store, part, crypto, work, sink=None):
    remote = Path(work) / "readback.gpg"
    try:
        store.get(part["key"], remote, part["cipher_bytes"])
        if remote.stat().st_size != part["cipher_bytes"] or digest(remote) != part["cipher_sha256"]:
            raise BackupError("Remote ciphertext readback mismatch")
        if crypto.decrypt(remote, sink, part["bytes"]) != {"bytes": part["bytes"], "sha256": part["sha256"]}:
            raise BackupError("Remote plaintext readback mismatch")
    finally:
        remote.unlink(missing_ok=True)


def validate_manifest(value, prefix):
    if not re.fullmatch(PREFIX, prefix) or value.get("schema") != SCHEMA or value.get("prefix") != prefix:
        raise BackupError("Encrypted manifest identity mismatch")
    stamp = prefix.split("/")[2]
    if value.get("stamp") != stamp:
        raise BackupError("Manifest stamp mismatch")
    expected = {f"blacklabel-{stamp}.dump", f"utah-{stamp}.dump", f"brain-state-{stamp}.tar.gz"}
    files = value.get("files", [])
    if len(files) != 3 or {f.get("name") for f in files} != expected:
        raise BackupError("Incomplete encrypted manifest or unsafe restore name")
    if not re.fullmatch(HASH, value.get("source_manifest_sha256", "")):
        raise BackupError("Invalid source manifest hash")
    for index, entry in enumerate(files):
        if not re.fullmatch(HASH, entry.get("sha256", "")) or not isinstance(entry.get("bytes"), int) or entry["bytes"] <= 0:
            raise BackupError("Invalid manifest file metadata")
        parts = entry.get("parts", [])
        if not parts or len(parts) > 100000:
            raise BackupError("Invalid part count")
        for number, part in enumerate(parts):
            key = f"{prefix}/artifacts/{index:03d}/{number:06d}.gpg"
            if part.get("key") != key:
                raise BackupError("Manifest part ordering or path mismatch")
            if any(not re.fullmatch(HASH, part.get(field, "")) for field in ("sha256", "cipher_sha256")):
                raise BackupError("Invalid part digest")
            if not isinstance(part.get("bytes"), int) or not 0 < part["bytes"] <= CHUNK_BYTES:
                raise BackupError("Invalid plaintext part size")
            if not isinstance(part.get("cipher_bytes"), int) or not 0 < part["cipher_bytes"] <= MAX_PART_BYTES:
                raise BackupError("Invalid ciphertext part size")
        if sum(p["bytes"] for p in parts) != entry["bytes"]:
            raise BackupError("Manifest part sizes do not sum to file size")
    return value


@contextlib.contextmanager
def journal_lock(journal):
    fd = os.open(str(journal) + ".lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise BackupError("This snapshot already has an active uploader") from None
        yield
    finally:
        os.close(fd)


def upload(snapshot, store, crypto, work, journal, chunk_bytes=CHUNK_BYTES,
           namespace="encrypted-v1", publish_latest=True, progress=None):
    if namespace not in ("encrypted-v1", "encrypted-canary-v1") or not 1 <= chunk_bytes <= CHUNK_BYTES:
        raise BackupError("Invalid namespace or chunk size")
    if namespace == "encrypted-canary-v1" and publish_latest:
        raise BackupError("Canary runs must not publish the production latest pointer")
    binding = {"snapshot": snapshot, "store": store.identity, "chunk_bytes": chunk_bytes, "namespace": namespace}
    journal = Path(journal)
    with journal_lock(journal):
        if journal.exists():
            secret_file(journal)
            state = json.loads(journal.read_text())
            if state.get("binding") != binding:
                raise BackupError("Resume journal does not match the exact source and destination")
        else:
            state = {"binding": binding, "prefix": f"{namespace}/{snapshot['date']}/{snapshot['stamp']}/{uuid.uuid4().hex}",
                     "started_at": utc(), "parts": {}, "status": "running"}
            save_json(journal, state)
        prefix = state["prefix"]
        if not re.fullmatch(PREFIX, prefix):
            raise BackupError("Unsafe resume prefix")
        if state.get("status") == "complete":
            return verify(store, crypto, work, prefix)
        files = []
        cipher = Path(work) / "upload.gpg"
        try:
            for index, row in enumerate(snapshot["rows"]):
                path = Path(snapshot["directory"]) / row["name"]
                if source_identity(path) != row["source_identity"]:
                    raise BackupError("Snapshot source changed before upload")
                h, size, parts = hashlib.sha256(), 0, []
                with path.open("rb") as source:
                    for number, data in enumerate(iter(lambda: source.read(chunk_bytes), b"")):
                        h.update(data)
                        size += len(data)
                        expected = {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
                        key = f"{prefix}/artifacts/{index:03d}/{number:06d}.gpg"
                        part = state["parts"].get(key)
                        if part:
                            if {k: part[k] for k in expected} != expected or part.get("key") != key:
                                raise BackupError("Resumed source part mismatch")
                            fetch_part(store, part, crypto, work)
                        else:
                            crypto.encrypt(data, cipher)
                            part = verified_put(store, key, cipher, crypto, work, expected)
                            state["parts"][key] = part
                            save_json(journal, state)
                        parts.append(part)
                        cipher.unlink(missing_ok=True)
                        if progress:
                            progress({"event": "part_verified", "prefix": prefix, "file": row["name"],
                                      "part": number, "file_bytes_verified": size,
                                      "source_bytes_total": sum(r["source_identity"][2] for r in snapshot["rows"]),
                                      "verified_parts": len(state["parts"]), "at": utc()})
                if source_identity(path) != row["source_identity"] or h.hexdigest() != row["sha256"] or size != row["source_identity"][2]:
                    raise BackupError("Whole snapshot artifact checksum/identity mismatch")
                files.append({"name": row["name"], "bytes": size, "sha256": h.hexdigest(), "parts": parts})
            manifest = {"schema": SCHEMA, "prefix": prefix, "stamp": snapshot["stamp"],
                        "source_manifest_sha256": snapshot["manifest_sha256"], "files": files,
                        "started_at": state["started_at"], "verified_at": utc(),
                        "encryption": "OpenPGP AES256 with MDC; iterated salted SHA256 S2K"}
            validate_manifest(manifest, prefix)
            raw = encode(manifest)
            if len(raw) > MAX_MANIFEST_BYTES:
                raise BackupError("Encrypted manifest exceeds its bound")
            meta = state.get("manifest")
            if meta:
                # Once published, the manifest stays immutable even if a later
                # pointer upload/readback fails and this run is resumed.
                existing = load_manifest(store, crypto, work, prefix)
                if existing["files"] != files:
                    raise BackupError("Published manifest differs from resumed source")
                fetch_part(store, meta, crypto, work)
            else:
                crypto.encrypt(raw, cipher)
                meta = verified_put(store, prefix + "/manifest.json.gpg", cipher, crypto, work,
                                    {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()})
                state["manifest"] = meta
                save_json(journal, state)
            if publish_latest:
                pointer = encode({"schema": SCHEMA + ".pointer", "prefix": prefix, "manifest": meta})
                crypto.encrypt(pointer, cipher)
                verified_put(store, namespace + "/LATEST.gpg", cipher, crypto, work,
                             {"bytes": len(pointer), "sha256": hashlib.sha256(pointer).hexdigest()})
            state.update({"status": "complete", "completed_at": utc(), "manifest": meta,
                          "files": [{k: f[k] for k in ("name", "bytes", "sha256")} for f in files],
                          "latest_published": publish_latest})
            save_json(journal, state)
            return {"status": "passed", "operation": "upload", "prefix": prefix, "store": store.identity,
                    "files": state["files"], "verified_parts": len(state["parts"]),
                    "latest_published": publish_latest, "finished_at": utc()}
        except Exception:
            state.update({"status": "incomplete", "last_failure_at": utc()})
            save_json(journal, state)
            raise
        finally:
            cipher.unlink(missing_ok=True)


def load_manifest(store, crypto, work, prefix=None):
    cipher = Path(work) / "manifest.gpg"
    try:
        pointer = None
        if prefix is None:
            store.get("encrypted-v1/LATEST.gpg", cipher, MAX_MANIFEST_BYTES)
            pointer = crypto.decrypt_json(cipher)
            if pointer.get("schema") != SCHEMA + ".pointer":
                raise BackupError("Invalid latest pointer")
            prefix = pointer.get("prefix", "")
        if not re.fullmatch(PREFIX, prefix):
            raise BackupError("Unsafe snapshot prefix")
        store.get(prefix + "/manifest.json.gpg", cipher, MAX_MANIFEST_BYTES)
        if pointer:
            meta = pointer["manifest"]
            if meta["key"] != prefix + "/manifest.json.gpg" or digest(cipher) != meta["cipher_sha256"] or cipher.stat().st_size != meta["cipher_bytes"]:
                raise BackupError("Latest pointer manifest binding mismatch")
        return validate_manifest(crypto.decrypt_json(cipher), prefix)
    finally:
        cipher.unlink(missing_ok=True)


def publish_restored_directory(stage, destination):
    """Atomically publish a restore without replacing a concurrent destination."""
    libc = ctypes.CDLL(None, use_errno=True)
    source_bytes, destination_bytes = os.fsencode(stage), os.fsencode(destination)
    if sys.platform == "darwin":
        # renamex_np with RENAME_EXCL refuses an existing path or symlink.
        operation = getattr(libc, "renamex_np", None)
        if operation is None:
            raise BackupError("Atomic no-overwrite directory publication is unavailable")
        operation.argtypes = (ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint)
        result = operation(source_bytes, destination_bytes, 4)
    elif sys.platform.startswith("linux"):
        # renameat2 with RENAME_NOREPLACE closes the check/publish race.
        operation = getattr(libc, "renameat2", None)
        if operation is None:
            raise BackupError("Atomic no-overwrite directory publication is unavailable")
        operation.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int,
                              ctypes.c_char_p, ctypes.c_uint)
        result = operation(-100, source_bytes, -100, destination_bytes, 1)
    else:
        raise BackupError("Atomic no-overwrite directory publication is unavailable")
    if result != 0:
        raise OSError(ctypes.get_errno(), "Atomic no-overwrite restore publication failed")


def verify(store, crypto, work, prefix=None, destination=None):
    manifest = load_manifest(store, crypto, work, prefix)
    destination = Path(destination).absolute() if destination is not None else None
    if destination is not None and (destination.exists() or destination.is_symlink()):
        raise BackupError("Restore destination already exists; refusing overwrite")
    parent = destination.parent if destination else Path(work)
    stage = Path(tempfile.mkdtemp(prefix=".encrypted-restore-", dir=parent))
    try:
        files = []
        for entry in manifest["files"]:
            h, size = hashlib.sha256(), 0

            class Sink:
                def write(self, data):
                    nonlocal size
                    h.update(data)
                    size += len(data)
                    if target is not None:
                        target.write(data)

            with (stage / entry["name"]).open("xb") if destination else contextlib.nullcontext(None) as target:
                for part in entry["parts"]:
                    fetch_part(store, part, crypto, work, Sink())
            if h.hexdigest() != entry["sha256"] or size != entry["bytes"]:
                raise BackupError("Restored whole-file checksum mismatch")
            files.append({"name": entry["name"], "sha256": h.hexdigest(), "bytes": size})
        report = {"status": "passed", "operation": "restore" if destination else "verify", "store": store.identity,
                  "prefix": manifest["prefix"], "files": files, "finished_at": utc(),
                  "verified_parts": sum(len(f["parts"]) for f in manifest["files"])}
        if destination:
            sums = "".join(f"{f['sha256']}  ./{f['name']}\n" for f in files)
            (stage / ("SHA256SUMS." + manifest["stamp"])).write_text(sums)
            save_json(stage / "ENCRYPTED-RESTORE-RECEIPT.json", report)
            publish_restored_directory(stage, destination)
        return report
    finally:
        if stage.exists():
            shutil.rmtree(stage)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("upload", "verify", "restore", "inspect"))
    parser.add_argument("--snapshot-dir", type=Path)
    parser.add_argument("--manifest")
    parser.add_argument("--prefix")
    parser.add_argument("--destination", type=Path)
    parser.add_argument("--key-file", type=Path, default=Path.home() / ".utah/secrets/backup-key.txt")
    parser.add_argument("--credential-file", type=Path, default=Path.home() / ".wrangler/config/default.toml")
    parser.add_argument("--account", default="a0703c8cbbf2d56af47d05d5817b8c5b")
    parser.add_argument("--bucket", default="blacklabel-backups")
    parser.add_argument("--local-store", type=Path, help="Explicit offline test/DR store")
    parser.add_argument("--state-dir", type=Path, default=Path.home() / ".utah/run/encrypted-backups")
    parser.add_argument("--namespace", choices=("encrypted-v1", "encrypted-canary-v1"), default="encrypted-v1")
    parser.add_argument("--no-latest", action="store_true")
    parser.add_argument("--chunk-bytes", type=int, default=CHUNK_BYTES)
    parser.add_argument("--receipt", type=Path)
    args = parser.parse_args(argv)
    os.umask(0o077)
    try:
        if args.operation == "inspect":
            if args.snapshot_dir is None:
                parser.error("--snapshot-dir is required")
            print(json.dumps(read_snapshot(args.snapshot_dir, args.manifest), sort_keys=True))
            return 0
        state = private_dir(args.state_dir)
        with tempfile.TemporaryDirectory(prefix="work-", dir=state) as work:
            crypto = GPG(args.key_file, work)
            store = LocalStore(args.local_store) if args.local_store else R2Store(args.account, args.bucket, args.credential_file)
            if args.operation == "upload":
                if args.snapshot_dir is None:
                    parser.error("--snapshot-dir is required")
                snapshot = read_snapshot(args.snapshot_dir, args.manifest)
                legacy_binding = {"snapshot": snapshot, "store": store.identity, "namespace": args.namespace}
                legacy_identity = hashlib.sha256(encode(legacy_binding)).hexdigest()
                legacy_journal = state / (legacy_identity + ".json")
                binding = dict(legacy_binding, chunk_bytes=args.chunk_bytes)
                identity = hashlib.sha256(encode(binding)).hexdigest()
                journal = state / (identity + ".json")
                if legacy_journal.exists():
                    secret_file(legacy_journal)
                    old_state = json.loads(legacy_journal.read_text())
                    if old_state.get("binding", {}).get("chunk_bytes") == args.chunk_bytes:
                        journal = legacy_journal
                report = upload(snapshot, store, crypto, work, journal, args.chunk_bytes,
                                args.namespace, not args.no_latest, lambda value: print(json.dumps(value), flush=True))
            else:
                if args.operation == "restore" and args.destination is None:
                    parser.error("--destination is required")
                report = verify(store, crypto, work, args.prefix, args.destination if args.operation == "restore" else None)
        if args.receipt:
            save_json(args.receipt, report)
        print(json.dumps(report, sort_keys=True), flush=True)
        return 0
    except Exception as error:
        # No provider bodies, credential values or GPG diagnostics in durable logs.
        report = {"status": "failed", "operation": args.operation, "error_type": type(error).__name__,
                  "error": str(error) if isinstance(error, BackupError) else "See local inputs and connectivity; no completion published",
                  "finished_at": utc()}
        if args.receipt:
            save_json(args.receipt, report)
        print(json.dumps(report, sort_keys=True), flush=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())
