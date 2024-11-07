#!/usr/bin/env bash
# Runs linting scripts and type checking
# ruff - sorts import statements, lints and finds mistakes, formats the code
# mypy - checks type annotations

set -e

files=(
  "perf"
  "src"
  "tests"
)

# Print out the commands being run
set -x

# Catch any common programming mistakes in Python code.
# --quiet suppresses the update check.
ruff check --quiet --fix "${files[@]}"

# Reformat Python code.
ruff format --quiet "${files[@]}"

# Type-check the code.
mypy "${files[@]}"
