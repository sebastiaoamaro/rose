#!/usr/bin/env sh
set -eu

if [ "${1-}" = "" ]; then
  echo "Usage: $0 <num_cores>" >&2
  exit 2
fi

CORES="$1"
case "$CORES" in
  ''|*[!0-9]*)
    echo "Error: num_cores must be an integer, got: '$CORES'" >&2
    exit 2
    ;;
  0)
    echo "Error: num_cores must be >= 1, got: '$CORES'" >&2
    exit 2
    ;;
esac

VAGRANTFILE="../Vagrantfile"
if [ ! -f "$VAGRANTFILE" ]; then
  echo "Error: Vagrantfile not found at: $VAGRANTFILE" >&2
  exit 1
fi

tmp="$(mktemp)"

awk -v cores="$CORES" '
  BEGIN { in_test1=0 }
  /config\.vm\.define[[:space:]]+"test1"/ { in_test1=1 }
  in_test1 && /^[[:space:]]*v\.cpus[[:space:]]*=/ {
    sub(/v\.cpus[[:space:]]*=[[:space:]]*[0-9]+/, "v.cpus = " cores)
  }
  in_test1 && /^[[:space:]]*end[[:space:]]*$/ { in_test1=0 }
  { print }
' "$VAGRANTFILE" > "$tmp"

mv "$tmp" "$VAGRANTFILE"

echo "Updated test1 v.cpus to $CORES in $VAGRANTFILE"
echo "Note: you typically need 'vagrant reload test1' (or halt/up) for CPU changes to apply."
