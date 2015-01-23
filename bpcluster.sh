#! /bin/bash

THISDIR="$( cd $(dirname $0); pwd)"
SCRIPT="$THISDIR/$(basename $0)"

N="$1"
if [ -z "$N" ]; then
    echo "Usage: $0 NODE_NUMBER" >&2
    exit 1
fi
pushd "$THISDIR" > /dev/null
shift
twistd -n --pidfile "twsitd-${N}.pid" bindproxy -c "./bindproxy-${N}.cfg" $@
popd > /dev/null
