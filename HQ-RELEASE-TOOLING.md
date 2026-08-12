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
against provenance, resolves the recorded source worktree into the configured
HQ repository family, proves the recorded commit exists, derives and compares
its Git tree, and checks bundle ID/build/version, Developer ID team, stapling,
and Gatekeeper before changing the destination. It copies into a
same-filesystem staging directory and repeats the gates. Existing production
installs are replaced with macOS `renameatx_np(RENAME_SWAP)`, so the live path
is continuously populated across a crash or power loss; production refuses to
replace when atomic exchange is unavailable. The previous app is retained as
an explicit timestamped backup with pre-install bundle and executable hashes.
Any caught post-exchange failure or interruption atomically restores it.
Machine-readable receipts are written beneath `evidence/installs/`.

The custom `--destination` lane may use a caught two-rename fallback on a
platform without atomic exchange. That fallback is test/non-production only;
the `/Applications` command never uses it.
