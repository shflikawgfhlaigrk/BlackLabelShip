#!/usr/bin/env bash
# provision-windows-rig.sh — Phase W0.1 rig provisioning (STAGED, fail-closed).
#
# Contract: windows-w0-rig-20260720 (construction-engineer).
# Plan of record: ~/BlackLabel-Team/PLANS/expansion-20260707/01-windows-downloads.md §W0 step 1.
#
# WHAT THIS DOES (the moment a hypervisor exists): boots ~/Parallels/"Windows 11.pvm",
# waits for Parallels Tools, installs the builder toolchain (Python 3.12, Node LTS,
# the Windows SDK signtool, git + a shell toolchain) inside the guest via `prlctl exec`,
# then creates the two snapshots the gauntlet needs — `builder` (toolchain present) and
# `clean-buyer` (a virgin restore point, captured BEFORE the toolchain so it stays a
# clean buyer machine). It prints the scriptable `prlctl exec` / SSH access recipe.
#
# WHY IT IS STAGED / FAIL-CLOSED (mirrors the sign_windows law): there is NO Windows
# hypervisor on this Mac. Parallels Desktop is uninstalled — /usr/local/bin/prlctl is a
# DANGLING symlink to a removed /Applications/Parallels Desktop.app. Re-establishing a
# hypervisor (reinstall Parallels = paid/licensed, or stand up a free UTM/QEMU guest) is a
# FOUNDER money/decision gate (CHARTER §3, §5.5). So this script REFUSES to run — changes
# nothing — until that gate is cleared. It never installs a hypervisor and never spends.
# See STATE/reports/windows-rig-20260720.md for the honest current state + options.
#
# USAGE (after a hypervisor is restored):
#   tools/provision-windows-rig.sh            # full provision (preflight refuses if no rig)
#   tools/provision-windows-rig.sh --preflight-only   # just report rig readiness, change nothing
set -euo pipefail
export PATH="/usr/local/bin:/opt/homebrew/bin:$PATH"

VM_NAME="Windows 11"
VM_PVM="$HOME/Parallels/Windows 11.pvm"
PRLCTL="/usr/local/bin/prlctl"

say()  { printf '  %s\n' "$*"; }
die()  { printf 'FAIL: %s\n' "$*" >&2; exit 1; }

# --- THE HYPERVISOR GATE (fail-closed) --------------------------------------
# A functioning rig requires: the Parallels app bundle present (symlink target
# exists), prlctl actually executable, and the VM registered/listable. Any miss
# is a hard STOP with the founder-gate message — nothing on disk is touched.
preflight() {
  local target ok=1
  say "rig-preflight: checking for a Windows hypervisor on this Mac…"
  target="$(readlink "$PRLCTL" 2>/dev/null || true)"
  if [ -z "$target" ] || [ ! -e "$target" ]; then
    say "  prlctl -> ${target:-<none>} : MISSING (dangling symlink — Parallels app removed)"
    ok=0
  fi
  if [ "$ok" = 1 ] && ! "$PRLCTL" list -a >/dev/null 2>&1; then
    say "  prlctl list -a : FAILED (no running Parallels service)"
    ok=0
  fi
  [ -d "$VM_PVM" ] && say "  VM disk image  : present ($VM_PVM)" \
                    || say "  VM disk image  : MISSING ($VM_PVM)"
  if [ "$ok" = 0 ]; then
    cat >&2 <<'GATE'
FAIL: rig-preflight: no Windows hypervisor — STAGED, fail-closed.
  Parallels Desktop is uninstalled on this Mac (prlctl is a dangling symlink).
  Re-establishing a hypervisor is a FOUNDER GATE (paid Parallels license OR a
  free UTM/QEMU rebuild — both are spend/decision calls, CHARTER §3/§5.5).
  This script changed NOTHING. Clear the gate, then re-run.
  Options + evidence: STATE/reports/windows-rig-20260720.md
GATE
    exit 2
  fi
  say "rig-preflight: hypervisor OK."
}

# --- boot + wait for guest agent --------------------------------------------
boot_vm() {
  say "boot: starting '$VM_NAME'…"
  "$PRLCTL" start "$VM_NAME"
  say "boot: waiting for Parallels Tools (guest exec channel)…"
  local i
  for i in $(seq 1 60); do
    if "$PRLCTL" exec "$VM_NAME" cmd /c "echo ready" >/dev/null 2>&1; then
      say "boot: guest exec channel up."; return 0
    fi
    sleep 5
  done
  die "boot: guest exec channel never came up (Parallels Tools not responding)"
}

# --- clean-buyer snapshot FIRST (virgin, pre-toolchain) ---------------------
snapshot_clean_buyer() {
  say "snapshot: creating 'clean-buyer' (virgin guest, NO toolchain — the gauntlet target)…"
  "$PRLCTL" snapshot "$VM_NAME" --name "clean-buyer" \
    --description "Virgin Windows 11 buyer machine — no build toolchain. Restore target for every Windows-ship gauntlet (contract windows-w0-rig)."
}

# --- install the builder toolchain inside the guest -------------------------
install_toolchain() {
  say "toolchain: installing Python 3.12 + Node LTS + Git + Windows SDK signtool via winget…"
  # winget ships on Win 11; --silent + accept agreements for unattended install.
  local WG='winget install --disable-interactivity --accept-package-agreements --accept-source-agreements -e --id'
  "$PRLCTL" exec "$VM_NAME" cmd /c "$WG Python.Python.3.12"                 || die "toolchain: Python 3.12 install failed"
  "$PRLCTL" exec "$VM_NAME" cmd /c "$WG OpenJS.NodeJS.LTS"                  || die "toolchain: Node LTS install failed"
  "$PRLCTL" exec "$VM_NAME" cmd /c "$WG Git.Git"                           || die "toolchain: Git install failed"
  # signtool ships in the Windows SDK signing components.
  "$PRLCTL" exec "$VM_NAME" cmd /c "$WG Microsoft.WindowsSDK"              || die "toolchain: Windows SDK (signtool) install failed"
  say "toolchain: verifying inside guest…"
  "$PRLCTL" exec "$VM_NAME" cmd /c "python --version && node --version && git --version" \
    || die "toolchain: post-install verification failed"
  say "toolchain: signtool presence…"
  "$PRLCTL" exec "$VM_NAME" cmd /c "where signtool || dir \"C:\\Program Files (x86)\\Windows Kits\\10\\bin\" /s /b | findstr signtool.exe" \
    || say "toolchain: signtool not on PATH yet (SDK lays it under Windows Kits\\10\\bin\\<ver>\\x64) — record the abs path in the app sign_cmd"
}

# --- builder snapshot (toolchain present) -----------------------------------
snapshot_builder() {
  say "snapshot: creating 'builder' (toolchain installed — the build target)…"
  "$PRLCTL" snapshot "$VM_NAME" --name "builder" \
    --description "Windows 11 + Python 3.12 + Node LTS + Git + Windows SDK signtool. bl-ship --build-mode rig target (contract windows-w0-rig)."
}

# --- scriptable access recipe (prlctl exec + SSH) ---------------------------
print_access_doc() {
  cat <<DOC

== SCRIPTABLE ACCESS FROM macOS (record in STATE/reports/windows-rig-*.md) ==
  Run a guest command:      prlctl exec "$VM_NAME" cmd /c "<command>"
  Run PowerShell:           prlctl exec "$VM_NAME" powershell -Command "<ps>"
  Run a build script:       prlctl exec "$VM_NAME" powershell -File C:\\build\\<app>\\build.ps1
  Copy a file IN:           prlcopy "<mac-path>" "$VM_NAME:C:\\build\\<dest>"
  Copy a file OUT:          prlcopy "$VM_NAME:C:\\build\\out\\app.exe" "<mac-path>"
  Snapshots:                prlctl snapshot-list "$VM_NAME"
  Restore clean-buyer:      prlctl snapshot-switch "$VM_NAME" --name clean-buyer   # every gauntlet
  Suspend when idle:        prlctl suspend "$VM_NAME"

  SSH alternative (if OpenSSH Server is enabled in the guest + host-only IP known):
    ssh builder@<guest-ip>            # set up a key; prlctl exec is the default road (no net dep)

  bl-ship rig build (once this rig exists): ship.py --windows <app> --build-mode rig
DOC
}

main() {
  [ "${1:-}" = "--preflight-only" ] && { preflight; exit 0; }
  preflight              # fail-closed: exits 2 here today (no hypervisor)
  boot_vm
  snapshot_clean_buyer   # virgin restore point BEFORE toolchain
  install_toolchain
  snapshot_builder       # toolchain restore point
  print_access_doc
  say "provision: DONE — snapshots 'clean-buyer' + 'builder' created."
}
main "$@"
