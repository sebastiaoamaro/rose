#!/usr/bin/env sh
set -eu

VAGRANTFILE="../Vagrantfile"

if [ ! -f "$VAGRANTFILE" ]; then
  echo "Error: Vagrantfile not found at: $VAGRANTFILE" >&2
  exit 1
fi

# Update only within the `config.vm.define "test1"` block, and only the `v.cpus = ...` line.
# This assumes the block ends at the matching `end` aligned like in the current file.
# It will replace any existing integer with 2.
tmp="$(mktemp)"

awk '
  BEGIN { in_test1=0 }
  /config\.vm\.define[[:space:]]+"test1"/ { in_test1=1 }
  in_test1 && /^[[:space:]]*v\.cpus[[:space:]]*=/ {
    sub(/v\.cpus[[:space:]]*=[[:space:]]*[0-9]+/, "v.cpus = 2")
  }
  in_test1 && /^[[:space:]]*end[[:space:]]*$/ { in_test1=0 }
  { print }
' "$VAGRANTFILE" > "$tmp"

mv "$tmp" "$VAGRANTFILE"

echo "Updated test1 v.cpus to $1 in $VAGRANTFILE"
echo "Note: you typically need 'vagrant reload test1' (or halt/up) for CPU changes to apply."
