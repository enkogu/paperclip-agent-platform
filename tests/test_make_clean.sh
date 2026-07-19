#!/usr/bin/env bash
# Verify `make clean` removes repository Python artifacts without touching
# runtime or virtual-environment content.
set -Eeuo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
temporary=$(mktemp -d "${TMPDIR:-/tmp}/make-clean.XXXXXX")
trap 'rm -rf "$temporary"' EXIT

fixture=$temporary/repository
mkdir -p "$fixture"
protected_directories=()

create_python_artifacts() {
  local directory=$1
  mkdir -p "$directory/__pycache__" "$directory/package.egg-info"
  touch \
    "$directory/__pycache__/module.cpython-311.pyc" \
    "$directory/module.pyc" \
    "$directory/module.pyo" \
    "$directory/package.egg-info/PKG-INFO"
}

assert_exists() {
  local path=$1
  [[ -e "$path" ]] || {
    printf 'expected preserved artifact: %s\n' "$path" >&2
    exit 1
  }
}

assert_missing() {
  local path=$1
  [[ ! -e "$path" ]] || {
    printf 'expected removed artifact: %s\n' "$path" >&2
    exit 1
  }
}

for directory in deployment tools tests; do
  create_python_artifacts "$fixture/$directory/owned"
done
for environment in .venv .runtime; do
  protected_directories+=("$fixture/$environment/protected")
  protected_directories+=("$fixture/deployment/owned/$environment/protected")
  protected_directories+=("$fixture/tools/owned/$environment/protected")
done
for directory in "${protected_directories[@]}"; do
  create_python_artifacts "$directory"
done

make --no-print-directory -C "$fixture" -f "$ROOT/Makefile" clean

for directory in deployment tools tests; do
  assert_missing "$fixture/$directory/owned/__pycache__"
  assert_missing "$fixture/$directory/owned/module.pyc"
  assert_missing "$fixture/$directory/owned/module.pyo"
  assert_missing "$fixture/$directory/owned/package.egg-info"
done
for directory in "${protected_directories[@]}"; do
  assert_exists "$directory/__pycache__/module.cpython-311.pyc"
  assert_exists "$directory/module.pyc"
  assert_exists "$directory/module.pyo"
  assert_exists "$directory/package.egg-info/PKG-INFO"
done
