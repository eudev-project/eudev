#!/bin/sh
# Call the udev rule syntax checker on all rules that we ship
#
# (C) 2010 Canonical Ltd.
# Author: Martin Pitt <martin.pitt@ubuntu.com>

# The rules of the source tree, in rules/ and rule_generator/, and the ones that the build generates
# from a .in file in rules/ (64-btrfs.rules), which a VPATH build writes only to the build tree; make
# check passes that in $abs_top_builddir, else it is taken to be the source tree. A generated rules
# file that is missing, e.g. as rules/ was not made yet, is an error: it is not left out.
[ -n "$top_srcdir" ] || top_srcdir=`dirname $0`/..
[ -n "$abs_top_builddir" ] || abs_top_builddir=$top_srcdir

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

rules=`find $top_srcdir/rules $top_srcdir/rule_generator -name '*.rules'`
vpath=yes
[ "`cd "$abs_top_builddir/rules" 2>/dev/null && pwd -P`" = "`cd "$top_srcdir/rules" && pwd -P`" ] && vpath=no
for src in $top_srcdir/rules/*.rules.in; do
        [ -f "$src" ] || continue
        f=`basename "$src" .in`
        if [ ! -f "$abs_top_builddir/rules/$f" ]; then
                # 99 tells automake that the test could not run as it should
                echo "$0: rules/$f, which the build generates from rules/$f.in, is missing in"
                echo "$abs_top_builddir/rules: make it first (make -C rules $f in the build tree), or set"
                echo "abs_top_builddir to the build tree"
                exit 99
        fi
        echo "checking the generated $abs_top_builddir/rules/$f"
        # in the source tree, find has it already
        if [ $vpath = yes ]; then
                rules="$rules $abs_top_builddir/rules/$f"
        fi
done

"$python" `dirname $0`/rule-syntax-check.py $rules
