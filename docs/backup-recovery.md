# Full snapshot backup and recovery

The scheduled local producer is `~/BlackLabel-Team/bin/backup.sh`. A complete set has one `brain-state-<stamp>.tar.gz`, one `blacklabel-<stamp>.dump`, one `utah-<stamp>.dump`, and `SHA256SUMS.<stamp>` in the same dated directory. A partial archive or a running process is not a completed backup.

`backup_offsite.sh` uploads the small encrypted state bundle, then calls `backup_offsite_snapshot.sh` for the complete three-artifact set. The aggregate job exits unsuccessfully if the full snapshot lane fails. `backup_offsite_snapshot.sh` selects the newest dated local snapshot only after `encrypted_snapshot.py inspect` accepts its exact manifest.

For an event-driven or manual upload of a particular completed set, pass `SNAPSHOT_DIR` and `SNAPSHOT_MANIFEST` to `backup_offsite_snapshot.sh`. This binds the producer's checksum sentinel to the offsite upload even when another snapshot is being written in the same dated directory. A scheduler should pass these two values from a successful local completion receipt, instead of relying on a time offset. The wrapper requires an upload receipt with `status: passed`, `operation: upload`, and `latest_published: true` before reporting offsite completion.

## Upload contract

- Full-set objects are encrypted before upload to `r2://blacklabel-backups/encrypted-v1/`.
- The uploader downloads, decrypts, and hash-checks each part before recording progress. It publishes `manifest.json.gpg` and then `encrypted-v1/LATEST.gpg` only after all three artifacts pass.
- New uploads use 64 MiB parts by default (`SNAP_CHUNK_BYTES=67108864`). This stays below the three-minute per-request wall deadline on links where the former 290 MiB parts timed out. `SNAP_CHUNK_BYTES` accepts 1 through 304087040 bytes; use a stable value for a resumed set.
- The journal binds the exact snapshot, store, namespace, and chunk size. Existing legacy journals resume when their requested chunk size matches. A different chunk size starts a separate journal and prefix; old partial objects remain for a reviewed retention decision.
- `last-upload.json` must say `status: passed`, name the prefix, and report `latest_published: true`. That is an upload/byte-verification receipt, not a database or application restore receipt.

### Concurrent and resumed uploads

The latest pointer is compared by the snapshot's original UTC stamp, never by
upload completion time. It is written with `If-None-Match: *` for the first
pointer, or `If-Match` with the ETag from the authenticated pointer read. A
conflict causes a bounded read-and-compare retry, without a blind-write fallback.
An unreadable, corrupt or unversioned pointer stops publication. Completed
journals reverify their own immutable prefix and the current pointer without
writing it again.

An older snapshot may finish uploading after a newer one. Its receipt then
contains `latest_published: false`, `latest_status: retained_newer`, and the
newer's `latest_prefix`; its own `prefix` remains available for explicit restore.
Equal timestamps retain the current pointer (`retained_same_version`). Source
rescue snapshots have only a date, so equal dates also retain the existing
pointer rather than assuming which snapshot was created later. The scheduled
wrapper still requires its chosen snapshot to be the latest before it reports
the whole job complete.

Local-store tests implement the same compare-and-swap contract with an atomic
file replacement and an interprocess lock. That proves local behavior only.
Before installing this change into the production uploader, verify conditional
write rejection and readback on an isolated key through the actual R2 REST
endpoint; S3/Workers documentation and local fixtures alone do not establish
that endpoint's behavior. Never use a production `LATEST.gpg` for that probe.

## Recovery drill

Work from a separate machine/account or isolated target with sufficient scratch space. Obtain the encryption key through the separately maintained recovery channel. Keep it out of Git, logs, and the restored payload directory.

1. Inspect the remote encrypted manifest and bytes:

   ```sh
   /usr/bin/python3 tools/encrypted_snapshot.py verify \
     --key-file "$BACKUP_KEYFILE" \
     --credential-file "$BACKUP_R2_CREDENTIAL_FILE" \
     --receipt "$RECOVERY_EVIDENCE/remote-verify.json"
   ```

2. Restore the exact remote set into a new private directory:

   ```sh
   /usr/bin/python3 tools/encrypted_snapshot.py restore \
     --key-file "$BACKUP_KEYFILE" \
     --credential-file "$BACKUP_R2_CREDENTIAL_FILE" \
     --destination "$RECOVERY_SCRATCH/snapshot" \
     --receipt "$RECOVERY_EVIDENCE/remote-restore.json"
   ```

3. Restore both databases into a disposable, socket-only PostgreSQL cluster, then extract and hash-check the company-state archive in private scratch:

   ```sh
   /usr/bin/python3 "$HOME/BlackLabel-Team/bin/restore-snapshot.py" \
     --snapshot-dir "$RECOVERY_SCRATCH/snapshot" \
     --database both --max-wall-seconds 14400 \
     --receipt "$RECOVERY_EVIDENCE/database-restore.json"

   /usr/bin/python3 "$HOME/BlackLabel-Team/bin/restore-brain-snapshot.py" \
     --snapshot-dir "$RECOVERY_SCRATCH/snapshot" \
     --max-wall-seconds 7200 \
     --receipt "$RECOVERY_EVIDENCE/brain-restore.json"
   ```

   Keep both receipts. These scripts test data restoration; a separate service startup and buyer-path check is required for full application recovery.

4. Compare the restored counts, schema, and relevant service behavior to the source receipt. Record achieved recovery-point and recovery-time results. Only then mark the set recoverable.

Do not infer recoverability from a bucket listing, a `LATEST.gpg` object by itself, a successful scheduler exit, or a structural `pg_restore --list` result. If the key cannot be recovered independently of the source Mac, the offsite set does not meet the machine-loss recovery requirement.
