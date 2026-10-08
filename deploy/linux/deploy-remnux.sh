#!/bin/sh
# Offline root-local deployment; see README for the pinned carrier and arguments.
set -eu
exec /usr/bin/python3 -I -B "$(dirname -- "$0")/deploy_remnux.py" "$@"
