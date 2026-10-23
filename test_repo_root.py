"""Release preflights must use the configured repository, not an ancestor."""
import contextlib
import io
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

import ship


class ExactRootTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "parent"
        self.root.mkdir()
        self.child = self.root / "plain-product-directory"
        self.child.mkdir()
        subprocess.run(["git", "init", "-q", str(self.root)], check=True)
        subprocess.run(["git", "-C", str(self.root), "config", "user.name", "Fixture"], check=True)
        subprocess.run(["git", "-C", str(self.root), "config", "user.email", "fixture@example.invalid"], check=True)
        (self.root / "tracked.txt").write_text("original\n")
        subprocess.run(["git", "-C", str(self.root), "add", "tracked.txt"], check=True)
        subprocess.run(["git", "-C", str(self.root), "commit", "-qm", "fixture"], check=True)

    def test_plain_child_is_rejected_before_release_preflights(self):
        with mock.patch.object(ship, "APPS_DIR", self.temp.name), \
             contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(SystemExit):
                ship.stage_preflight({"repo": str(self.child)}, "fixture")
            with self.assertRaises(SystemExit):
                ship.win_preflight({"repo": str(self.child)}, "fixture")
            with mock.patch.object(ship, "expand", return_value=str(self.child)), \
                 self.assertRaises(SystemExit):
                ship.cmd_site(dry_run=True)

    def test_clean_exact_root_and_worktree_are_accepted(self):
        with mock.patch.object(ship, "APPS_DIR", self.temp.name), \
             contextlib.redirect_stdout(io.StringIO()):
            head = ship.stage_preflight({"repo": str(self.root)}, "fixture")
            self.assertEqual(head, ship.win_preflight({"repo": str(self.root)}, "fixture"))
            worktree = Path(self.temp.name) / "linked-worktree"
            subprocess.run(["git", "-C", str(self.root), "worktree", "add", "-qb", "fixture-worktree", str(worktree)], check=True)
            self.assertEqual(ship.win_preflight({"repo": str(worktree)}, "fixture"), head)

    def test_windows_preflight_rejects_dirty_exact_root(self):
        (self.root / "tracked.txt").write_text("changed\n")
        with mock.patch.object(ship, "APPS_DIR", self.temp.name), \
             contextlib.redirect_stdout(io.StringIO()), \
             self.assertRaises(SystemExit):
            ship.win_preflight({"repo": str(self.root)}, "fixture")


if __name__ == "__main__":
    unittest.main()
