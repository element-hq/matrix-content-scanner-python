#!/usr/bin/env bash
# Runs linting scripts and type checking
# isort - sorts import statements
# black - opinionated code formatter
# flake8 - lints and finds mistakes
# mypy - checks type annotations

set -e

files=(
  "matrix_content_scanner"
  "tests"
)

# Print out the commands being run
set -x

isort "${files[@]}"
python3 -m black "${files[@]}"
flake8 "${files[@]}"
mypy "${files[@]}"
