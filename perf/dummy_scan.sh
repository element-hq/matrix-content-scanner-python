#!/usr/bin/env bash
sleep 1
# Roughly a 5% change to fail, assuming a uniform distribution of $RANDOM.
if [ $((RANDOM % 20)) = 0 ]; then
  echo "I don't like the look of $1" > /dev/stderr
  exit 1
fi