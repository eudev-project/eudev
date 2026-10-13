#!/bin/sh
# Call the udev rule syntax checker on all rules that we ship
#
# (C) 2010 Canonical Ltd.
# Author: Martin Pitt <martin.pitt@ubuntu.com>

# The rules of the source tree, and the ones that the build generates from a .in file
# (64-btrfs.rules), which a VPATH build writes only to the build tree; make check passes that in
# $abs_top_builddir.
[ -n "$top_srcdir" ] || top_srcdir=`dirname $0`/..

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

rules=`find $top_srcdir/rules -name '*.rules'`
if [ -n "$abs_top_builddir" ] && [ -d "$abs_top_builddir/rules" ] &&
   [ "`cd "$abs_top_builddir/rules" && pwd -P`" != "`cd "$top_srcdir/rules" && pwd -P`" ]; then
        built=`find "$abs_top_builddir/rules" -name '*.rules'`
        echo "rules of the build tree: "$built
        rules="$rules $built"
fi

"$python" `dirname $0`/rule-syntax-check.py $rules
