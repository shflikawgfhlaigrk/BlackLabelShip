#!/usr/bin/env bash
# Shared App Store submission guard. Apple is rejecting binaries built on the
# current macOS 27 beta host, so fail before producing or uploading another bad IPA.

appstore_select_xcode() {
  local developer_dir="${APPSTORE_DEVELOPER_DIR:-/Applications/Xcode.app/Contents/Developer}"
  if [ ! -d "$developer_dir" ]; then
    echo "App Store guard: missing release Xcode at $developer_dir" >&2
    exit 65
  fi

  export DEVELOPER_DIR="$developer_dir"

  local xcode_version
  xcode_version="$(xcodebuild -version 2>/dev/null | tr '\n' ' ')"
  case "$developer_dir" in
    *Xcode-beta.app/*|*Xcode-beta.app)
      echo "App Store guard: refusing beta Xcode at $developer_dir for App Store upload." >&2
      exit 65
      ;;
  esac

  case "$xcode_version" in
    *"Xcode 27."*)
      echo "App Store guard: refusing Xcode 27 beta for App Store upload ($xcode_version)" >&2
      exit 65
      ;;
    *"17F113"*)
      echo "App Store guard: refusing known-rejected Xcode beta build for App Store upload ($xcode_version)" >&2
      exit 65
      ;;
  esac

  local macos_version os_build
  macos_version="$(sw_vers -productVersion 2>/dev/null || true)"
  os_build="$(sw_vers -buildVersion 2>/dev/null || true)"
  case "$macos_version:$os_build" in
    27.*:*|*:26A*)
      echo "App Store guard: refusing macOS $macos_version ($os_build); Apple is rejecting binaries built on this OS." >&2
      echo "Build/upload from an Apple-accepted macOS release host instead." >&2
      exit 65
      ;;
  esac
}

appstore_check_ipa() {
  local ipa="${1:?usage: appstore_check_ipa <ipa>}"
  local build_machine dt_xcode dt_xcode_build
  build_machine="$(unzip -p "$ipa" 'Payload/*.app/Info.plist' 2>/dev/null | plutil -extract BuildMachineOSBuild raw -o - - 2>/dev/null || true)"
  dt_xcode="$(unzip -p "$ipa" 'Payload/*.app/Info.plist' 2>/dev/null | plutil -extract DTXcode raw -o - - 2>/dev/null || true)"
  dt_xcode_build="$(unzip -p "$ipa" 'Payload/*.app/Info.plist' 2>/dev/null | plutil -extract DTXcodeBuild raw -o - - 2>/dev/null || true)"

  case "$build_machine" in
    26A*)
      echo "App Store guard: refusing $ipa; BuildMachineOSBuild=$build_machine is the macOS 27 beta build Apple rejected." >&2
      exit 65
      ;;
  esac

  if [ -n "$dt_xcode" ] && [ "$dt_xcode" -ge 2700 ] 2>/dev/null; then
    echo "App Store guard: refusing $ipa; DTXcode=$dt_xcode indicates Xcode 27 beta." >&2
    exit 65
  fi

  case "$dt_xcode_build" in
    17F113)
      echo "App Store guard: refusing $ipa; DTXcodeBuild=$dt_xcode_build is the known-rejected Xcode beta build." >&2
      exit 65
      ;;
  esac
}
