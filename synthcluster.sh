#! /bin/bash

THISDIR="$( cd $(dirname $0); pwd)"
SCRIPT="$THISDIR/$(basename $0)"

N="$1"
if [ -z "$N" ]; then
    echo "Usage: $0 NODE_NUMBER" >&2
    exit 1
fi
pushd "$THISDIR" > /dev/null
twistd -n --pidfile "twsitd-${N}.pid" synthproxy -c "./synthproxy-${N}.cfg"
popd > /dev/null
