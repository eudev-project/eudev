#!/bin/bash

# check that all key names in keymaps/* are known in <linux/input.h>
# and that all key maps listed in the rules are valid and present in
# Makefile.am

SRCDIR=${1:-../..}
KEYLIST=${2:-${SRCDIR}/src/keymap/keys.txt}

[ -e "$KEYLIST" ] || {
        echo "need $KEYLIST please build first" >&2
        exit 1
}

KEYMAPS_DIR=${SRCDIR}/keymaps
KEYMAPS_LIST=$(ls ${KEYMAPS_DIR}/* | grep -v Makefile)
RULES=${SRCDIR}/rules/95-keymap.rules

missing=$(join -v 2 <(awk '{print tolower(substr($1,5))}' $KEYLIST | sort -u) \
                    <(grep -hv '^#' ${KEYMAPS_LIST}| awk '{print $2}' | sort -u))
[ -z "$missing" ] || {
        echo "ERROR: unknown key names in keymaps/*:" >&2
        echo "$missing" >&2
        exit 1
}

# check that all maps referred to in $RULES exist
maps=$(sed -rn '/keymap \$name/ { s/^.*\$name ([^"[:space:]]+).*$/\1/; p }' $RULES)
for m in $maps; do
        # ignore inline mappings
        [ "$m" = "${m#0x}" ] || continue

        [ -e ${KEYMAPS_DIR}/$m ] || {
                echo "ERROR: unknown map name in $RULES: $m" >&2
                exit 1
        }
        grep -q "$m\>" ${SRCDIR}/keymaps/Makefile.am || {
                echo "ERROR: map file $m is not added to Makefile.am" >&2
                exit 1
        }
done
