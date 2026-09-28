#!/bin/sh
# Call the udev rule syntax checker on all rules that we ship
#
# (C) 2010 Canonical Ltd.
# Author: Martin Pitt <martin.pitt@ubuntu.com>

[ -n "$builddir" ] || builddir=`dirname $0`/..

# skip if we don't have python 3; 77 tells automake that the test was skipped
python=
for p in python3 python; do
        if command -v "$p" >/dev/null 2>&1 &&
           "$p" -c 'import sys; sys.exit(sys.version_info[0] < 3)' >/dev/null 2>&1; then
                python=$p
                break
        fi
done
if [ -z "$python" ]; then
        echo "$0: No python 3 installed, skipping udev rule syntax check"
        exit 77
fi

"$python" `dirname $0`/rule-syntax-check.py `find $builddir/rules -name '*.rules'`
