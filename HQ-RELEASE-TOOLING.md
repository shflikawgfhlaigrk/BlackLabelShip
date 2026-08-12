# HQ release source and candidate installation

Build HQ from a clean detached worktree without changing `apps/hq.toml`:

```sh
python3 ship.py hq --repo /absolute/path/to/clean-hq-worktree --dry-run
```

`--repo` is invocation-scoped. Ship resolves it to a worktree root, requires
that it shares the configured HQ repository's Git common directory, retains
the dirty-tree hard gate, and records the canonical source path plus full
commit and tree IDs in `work/hq-stage/provenance.json`.

Resume a staged dry-run against the same source identity with:

```sh
python3 ship.py --publish-staged hq \
  --notary-id SUBMISSION_ID \
  --repo /absolute/path/to/clean-hq-worktree \
  --dry-run
```

Install the already-built staged candidate into a non-production test root:

```sh
python3 ship.py --install-candidate hq \
  --destination '/private/tmp/HQ Applications/Black Label HQ.app'
```

The test-root form requires an exact destination app path. It never writes
under `/Applications`. The separate production command is deliberately
explicit:

```sh
python3 ship.py --install-hq-candidate
```

The installer never rebuilds. It verifies executable and whole-bundle hashes
against provenance, source commit/tree, bundle ID/build/version, Developer ID
team, stapling, and Gatekeeper before changing the destination. It copies into
a same-filesystem staging directory, repeats the gates, keeps the prior app as
an explicit timestamped backup, atomically renames the candidate into place,
then verifies the installed bytes and trust again. Any failed post-mutation
gate restores the previous app. Machine-readable receipts are written beneath
`evidence/installs/`.
