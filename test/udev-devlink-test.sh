#!/bin/bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Tests the handling of device node symlinks claimed by several devices ("devlink stacks"),
# with events processed concurrently, as by the workers of udevd.
#
# The test runs as an unprivileged user: it re-executes itself in a new user and mount namespace,
# where tmpfs is mounted on /dev, /sys, /run/udev and the directories with udev rules and
# configuration. A fake sysfs describes up to 7 character devices of the subsystem "fake", whose
# device numbers are the ones of host device nodes (null, zero, full, random, urandom, tty, ptmx).
# mknod() is not permitted in a user namespace, so their device nodes /dev/fakeN are bind mounts of
# the host device nodes. These bind mounts, and the one on /dev/null, are read-only: the event
# processors update the timestamps of a device node on every event, which the host's nodes used
# here, writable for everyone, would otherwise allow, and the host's nodes must stay as they are.
# All fake devices claim the symlink /dev/test/a with a priority set by the rules. Each event is
# processed by test-udev-devlink, several of them at once where concurrency is tested. Some
# scenarios also check the handling of the device node itself, the parsing of link_priority= and
# "udevadm info --cleanup-db".
#
# Environment:
#   TEST_UDEV_DEVLINK  the event processor (default: ./test-udev-devlink)
#   TEST_UDEVADM       udevadm, for the cleanup_db scenario (default: ../src/udev/udevadm next to the
#                      event processor; the scenario is skipped if it is missing)
#   DL_OLD_DRIVER      an event processor built from an older eudev, used to create the stack
#                      entries of the upgrade scenario (default: the old format is written directly)
#   DL_ITER, DL_ROUNDS number of iterations of the race scenarios and rounds of the churn scenario
#   DL_DEBUG           let the event processor log at debug level (to the log in DL_KEEP_LOG)
#   DL_KEEP_LOG        copy the log of the event processors to this file
#   DL_ALLOW_ROOT      run even as root (skipped otherwise); as an unprivileged user, the event
#                      processors cannot change the host's device nodes
# Arguments: the scenarios to run, default: all.
#
# Exit status: 0 on success, 1 if a check failed, 77 if the test cannot run here.

set -u

if [ -z "${DL_IN_NS:-}" ]; then
        # The device nodes are bind mounts of the host's device nodes, and handling them as root, e.g.
        # applying the default SELinux or SMACK label, would change the host's device nodes.
        if [ "$(id -u)" = 0 ] && [ -z "${DL_ALLOW_ROOT:-}" ]; then
                echo "running as root would touch the host's device nodes, skipping (DL_ALLOW_ROOT=1 runs it anyway)"
                exit 77
        fi
        DRIVER=$(realpath "${TEST_UDEV_DEVLINK:-./test-udev-devlink}" 2>/dev/null)
        if [ ! -x "$DRIVER" ]; then
                echo "test-udev-devlink not found, skipping"
                exit 77
        fi
        if ! unshare --user --map-root-user --mount true 2>/dev/null; then
                echo "user and mount namespaces are not available, skipping"
                exit 77
        fi
        UDEVADM=$(realpath "${TEST_UDEVADM:-$(dirname "$DRIVER")/../src/udev/udevadm}" 2>/dev/null)
        # /sys is a tmpfs here, which libudev refuses as sysfs by default
        export DL_IN_NS=1 DRIVER UDEVADM UDEV_DEVICE_VERIFY_SYSFS=0
        [ -n "${DL_OLD_DRIVER:-}" ] && DL_OLD_DRIVER=$(realpath "$DL_OLD_DRIVER") && export DL_OLD_DRIVER
        exec unshare --user --map-root-user --mount --propagation private "$0" "$@"
fi

SCENARIOS="${*:-add_race remove_race remove_all_race prio_change missing_node old_links node_perms remove_owner repair upgrade churn dir_race symlink_values link_priority cleanup_db}"
ITER=${DL_ITER:-10}
ROUNDS=${DL_ROUNDS:-20}

NODES=(null zero full random urandom tty ptmx)
NUMS=(1:3 1:5 1:7 1:8 1:9 5:0 5:2)
N=${#NODES[@]}

for n in "${NODES[@]}"; do
        if [ ! -c "/dev/$n" ]; then
                echo "/dev/$n is missing, skipping"
                exit 77
        fi
done

# mount_opts PATH -- the options of the topmost mount on PATH, from /proc/self/mountinfo, which
# escapes space, tab, newline and backslash in the mount point
mount_opts() {
        local m=${1//\\/\\134}
        m=${m// /\\040}; m=${m//$'\t'/\\011}; m=${m//$'\n'/\\012}
        M=$m awk '$5 == ENVIRON["M"] { o = $6 } END { print o }' /proc/self/mountinfo
}

# make_ro PATH -- make the mount on PATH read-only, and check that it is
make_ro() {
        mount -o remount,bind,ro "$1" 2>/dev/null
        case $(mount_opts "$1") in
                ro|ro,*) return 0 ;;
        esac
        return 1
}

# bind_node NAME PATH -- bind mount the host's device node /dev/NAME on PATH, read-only, so that
# nothing here can change it, not even its timestamps
bind_node() {
        if touch "$2" && mount --bind "$HOSTDEV/$1" "$2"; then
                make_ro "$2" && return 0
                umount "$2"
        fi
        echo "cannot bind mount the host's /dev/$1 read-only on $2"
        return 1
}

W=$(mktemp -d "${TMPDIR:-/tmp}/udev-devlink-test.XXXXXX") || exit 1
HOSTDEV=$W/hostdev
mkdir "$HOSTDEV" || exit 1
mount --rbind /dev "$HOSTDEV" || exit 77
# only the device nodes of the host are used, and only read-only; the mounts below /dev, e.g.
# /dev/pts, are not used, and stay as they are
if ! make_ro "$HOSTDEV"; then
        echo "cannot make the bind mount of /dev read-only, skipping"
        exit 77
fi
mount -t tmpfs -o mode=0755 tmpfs /dev || exit 77
bind_node null /dev/null || exit 77
mount -t tmpfs -o mode=0755 tmpfs /sys || exit 77
mkdir -p /run/udev 2>/dev/null
mount -t tmpfs -o mode=0755 tmpfs /run/udev || exit 77
for d in /etc/udev /usr/etc/udev /lib/udev /usr/lib/udev /usr/local/lib/udev; do
        [ -d "$d" ] && mount -t tmpfs -o mode=0755 tmpfs "$d"
done

if [ -n "${DL_DEBUG:-}" ]; then
        export DL_DEBUG
fi

for i in $(seq 0 $((N-1))); do
        p=/sys/devices/virtual/fake/fake$i
        mkdir -p "$p" /sys/class/fake /sys/dev/char
        printf 'MAJOR=%s\nMINOR=%s\nDEVNAME=fake%s\n' "${NUMS[$i]%:*}" "${NUMS[$i]#*:}" "$i" > "$p/uevent"
        echo "${NUMS[$i]}" > "$p/dev"
        ln -s ../../../../class/fake "$p/subsystem"
        ln -s ../../devices/virtual/fake/fake$i /sys/class/fake/fake$i
done

declare -a PRIO
FAILS=0
EXTRA_LINKS=""
stackdir=/run/udev/links/'test\x2fa'
# the name of the stack directory in eudev 3.2.15 and older
oldstackdir=/run/udev/links/'\x2ftest\x2fa'

write_rules() {
        local i
        mkdir -p /run/udev/rules.d
        {
                echo "SUBSYSTEM==\"fake\", SYMLINK+=\"test/a\""
                for i in $(seq 0 $((N-1))); do
                        # keep owner, group and mode of the node, it cannot be changed here
                        echo "KERNEL==\"fake$i\", $(stat -L -c 'OWNER="%u", GROUP="%g", MODE="0%a"' "$HOSTDEV/${NODES[$i]}")"
                        [ -n "${PRIO[$i]:-}" ] && echo "KERNEL==\"fake$i\", OPTIONS+=\"link_priority=${PRIO[$i]}\""
                done
                [ -n "$EXTRA_LINKS" ] && echo "$EXTRA_LINKS"
        } > /run/udev/rules.d/50-test.rules
}

# "plug" a device: its device node and its /sys/dev/char/ link appear
node_add() {
        [ -e /sys/dev/char/${NUMS[$1]} ] || ln -s ../../devices/virtual/fake/fake$1 /sys/dev/char/${NUMS[$1]}
        [ -e /dev/fake$1 ] && return
        bind_node "${NODES[$1]}" /dev/fake$1 || exit 1
}

# only the device node disappears, the device is still there
node_only_del() {
        [ -e /dev/fake$1 ] || return
        umount /dev/fake$1
        rm -f /dev/fake$1
}

# "unplug" a device, as the kernel does before udevd sees the remove event; the device directory
# itself stays, so that the remove event can still be built from it
node_del() {
        node_only_del $1
        rm -f /sys/dev/char/${NUMS[$1]}
}

reset_state() {
        local i
        for i in $(seq 0 $((N-1))); do node_del $i; done
        rm -rf /dev/test /dev/t[0-9]* /dev/regfile /dev/char /dev/.#* /run/udev/data /run/udev/links \
                /run/udev/links.lock /run/udev/tags /run/udev/watch /run/udev/rules.d
        EXTRA_LINKS=""
}

# The event processor blocks all signals, as a worker of udevd does, so only SIGKILL stops a hung one.

# run_events DRIVER "action:N ..." -- process the events concurrently, released at the same moment
run_events() {
        local drv=$1 ev pids=() b=$W/barrier.$RANDOM$RANDOM
        shift
        for ev in "$@"; do
                DL_BARRIER=$b timeout -s KILL 60 "$drv" "${ev%%:*}" /devices/virtual/fake/fake${ev#*:} >>"$W/driver.log" 2>&1 &
                pids+=($!)
        done
        sleep 0.05
        touch "$b"
        wait "${pids[@]}"
        rm -f "$b"
}

# run_seq DRIVER "action:N ..." -- process the events one after another
run_seq() {
        local drv=$1 ev
        shift
        for ev in "$@"; do
                timeout -s KILL 60 "$drv" "${ev%%:*}" /devices/virtual/fake/fake${ev#*:} >>"$W/driver.log" 2>&1
        done
}

# run_debug "action:N ..." -- process the events one after another, with the debug log in $W/debug.log
run_debug() {
        local ev
        : > "$W/debug.log"
        for ev in "$@"; do
                DL_DEBUG=1 timeout -s KILL 60 "$DRIVER" "${ev%%:*}" /devices/virtual/fake/fake${ev#*:} >>"$W/debug.log" 2>&1
        done
        cat "$W/debug.log" >> "$W/driver.log"
}

# check_log WHAT PATTERN -- the debug log of run_debug must not contain the pattern
check_log_missing() {
        if grep -q -e "$2" "$W/debug.log"; then
                echo "  FAIL $1: the log contains '$(grep -m1 -e "$2" "$W/debug.log")'"
                FAILS=$((FAILS+1))
        fi
}

check_log() {
        if ! grep -q -e "$2" "$W/debug.log"; then
                echo "  FAIL $1: the log does not contain '$2'"
                FAILS=$((FAILS+1))
        fi
}

# the expected target of /dev/test/a: the present device with the highest priority
expected() {
        local best="" bp="" i
        for i in "$@"; do
                [ -e /dev/fake$i ] || continue
                if [ -z "$best" ] || [ "${PRIO[$i]}" -gt "$bp" ]; then
                        best=$i; bp=${PRIO[$i]}
                fi
        done
        [ -n "$best" ] && echo "../fake$best"
}

current() {
        readlink /dev/test/a 2>/dev/null
}

check() {
        local what=$1 exp=$2 cur
        cur=$(current)
        if [ "$cur" != "$exp" ]; then
                echo "  FAIL $what: /dev/test/a -> '${cur}', expected '${exp}'"
                FAILS=$((FAILS+1))
                return 1
        fi
        return 0
}

check_exists() {
        if [ ! -L "$1" ]; then
                echo "  FAIL $2: $1 is missing"
                FAILS=$((FAILS+1))
        fi
}

check_missing() {
        if [ -e "$1" ] || [ -L "$1" ]; then
                echo "  FAIL $2: $1 exists"
                FAILS=$((FAILS+1))
        fi
}

# describe_stack [DIR] -- list the entries of the stack directory of /dev/test/a
describe_stack() {
        local f d=${1:-$stackdir}
        [ -d "$d" ] || { echo "    (no stack directory ${d##*/})"; return; }
        for f in "$d"/* "$d"/.[!.]*; do
                [ -e "$f" ] || [ -L "$f" ] || continue
                if [ -L "$f" ]; then echo "    ${f##*/} -> $(readlink "$f")"; else echo "    ${f##*/} (regular file)"; fi
        done
}

scenario_add_race() {
        local it bad=0 i
        echo "== add_race: $N devices with distinct priorities are added concurrently, $ITER iterations"
        for it in $(seq 1 $ITER); do
                reset_state
                PRIO=(0 10 5 -3 7 2 9)
                write_rules
                for i in $(seq 0 $((N-1))); do node_add $i; done
                run_events "$DRIVER" $(for i in $(seq 0 $((N-1))); do echo add:$i; done)
                check "iteration $it" "$(expected $(seq 0 $((N-1))))" || bad=$((bad+1))
        done
        echo "  add_race: $bad/$ITER wrong"
}

scenario_remove_race() {
        local it bad=0 i
        echo "== remove_race: the 3 devices with the highest priority are removed concurrently, $ITER iterations"
        for it in $(seq 1 $ITER); do
                reset_state
                PRIO=(0 10 5 -3 7 2 9)
                write_rules
                for i in $(seq 0 $((N-1))); do node_add $i; done
                run_seq "$DRIVER" $(for i in $(seq 0 $((N-1))); do echo add:$i; done)
                check "setup $it" "$(expected $(seq 0 $((N-1))))" || { bad=$((bad+1)); continue; }
                for i in 1 6 4; do node_del $i; done
                run_events "$DRIVER" remove:1 remove:6 remove:4 change:0 change:3
                check "iteration $it" "$(expected 0 2 3 5)" || bad=$((bad+1))
        done
        echo "  remove_race: $bad/$ITER wrong"
}

scenario_remove_all_race() {
        local it bad=0 leftover=0 i
        echo "== remove_all_race: all devices are removed concurrently, $ITER iterations"
        for it in $(seq 1 $ITER); do
                reset_state
                PRIO=(0 10 5 -3 7 2 9)
                write_rules
                for i in $(seq 0 $((N-1))); do node_add $i; done
                run_seq "$DRIVER" $(for i in $(seq 0 $((N-1))); do echo add:$i; done)
                for i in $(seq 0 $((N-1))); do node_del $i; done
                run_events "$DRIVER" $(for i in $(seq 0 $((N-1))); do echo remove:$i; done)
                if [ -e /dev/test/a ] || [ -L /dev/test/a ]; then
                        echo "  FAIL iteration $it: /dev/test/a still exists -> $(current)"
                        FAILS=$((FAILS+1)); bad=$((bad+1))
                fi
                if [ -e "$stackdir" ] || [ -e "$oldstackdir" ] || [ -n "$(ls -A /run/udev/links.lock 2>/dev/null)" ]; then
                        leftover=$((leftover+1))
                fi
        done
        echo "  remove_all_race: $bad/$ITER wrong, $leftover/$ITER left a stack directory or lock file behind"
}

scenario_prio_change() {
        local i
        echo "== prio_change: the priority of devices is raised and lowered with change events"
        reset_state
        PRIO=(0 10 5 -3 7 2 9)
        write_rules
        for i in $(seq 0 $((N-1))); do node_add $i; done
        run_seq "$DRIVER" $(for i in $(seq 0 $((N-1))); do echo add:$i; done)
        check "initial" ../fake1
        PRIO[2]=20; write_rules; run_seq "$DRIVER" change:2
        check "fake2 raised to 20" ../fake2
        PRIO[2]=-10; write_rules; run_seq "$DRIVER" change:2
        check "fake2 lowered to -10" ../fake1
        PRIO[1]=1; write_rules; run_seq "$DRIVER" change:1
        check "the owner fake1 lowered to 1" ../fake6
        PRIO[0]=30; PRIO[6]=-1; PRIO[4]=8; write_rules
        run_events "$DRIVER" change:0 change:6 change:4
        check "fake0 raised to 30, fake6 lowered to -1, fake4 raised to 8, concurrently" ../fake0
        PRIO[0]=-20; write_rules; run_events "$DRIVER" change:0 change:3
        check "fake0 lowered to -20" ../fake4
        PRIO[5]=8; write_rules; run_seq "$DRIVER" change:5
        check "fake5 raised to the priority of the owner fake4, the newer device wins" ../fake5
}

scenario_missing_node() {
        local i
        echo "== missing_node: the claimant with the highest priority has lost its device node"
        reset_state
        PRIO=(0 10 5 -3 7 2 9)
        write_rules
        for i in $(seq 0 $((N-1))); do node_add $i; done
        run_seq "$DRIVER" $(for i in $(seq 0 $((N-1))); do echo add:$i; done)
        check "initial" ../fake1
        node_only_del 1
        run_seq "$DRIVER" change:2
        check "change of fake2 while the node of the owner fake1 is missing" "$(expected 0 2 3 4 5 6)"
        node_only_del 6
        PRIO[3]=8; write_rules
        run_seq "$DRIVER" change:3
        check "fake3 raised to 8 while the nodes of fake1 and fake6 are missing" "$(expected 0 2 3 4 5)"
        reset_state
        PRIO=(0 10 5); write_rules
        node_add 0; node_add 1
        run_seq "$DRIVER" add:0 add:1
        check "initial" ../fake1
        node_only_del 1
        node_add 2
        run_seq "$DRIVER" add:2
        check "fake2 added while the node of the owner fake1 is missing" ../fake2
}

scenario_old_links() {
        echo "== old_links: devlinks the rules no longer assign are removed, also when the device node is missing"
        reset_state
        PRIO=(0)
        EXTRA_LINKS='KERNEL=="fake0", SYMLINK+="t4/x"'
        write_rules
        node_add 0
        run_seq "$DRIVER" add:0
        check_exists /dev/t4/x "t4/x assigned on add"
        EXTRA_LINKS='KERNEL=="fake0", SYMLINK+="t4/y"'
        write_rules
        run_seq "$DRIVER" change:0
        check_missing /dev/t4/x "t4/x no longer assigned"
        check_exists /dev/t4/y "t4/y assigned on change"
        node_only_del 0
        EXTRA_LINKS=""
        write_rules
        run_seq "$DRIVER" change:0
        check_missing /dev/t4/y "t4/y no longer assigned while the device node is missing"
}

# write the stack entries of the given devices as eudev 3.2.15 and older did: empty regular files
# named after the device ID in the stack directory named after the path below /dev including its
# leading slash, with the priority in the udev database, and set the devlink to the device with the
# highest priority among the entries of that directory, as that eudev did
write_old_format() {
        local i id f best="" bp=""
        mkdir -p "$oldstackdir" /run/udev/data /dev/test
        for i in "$@"; do
                id=c${NUMS[$i]}
                printf 'S:test/a\nL:%s\nI:1\n' "${PRIO[$i]}" > /run/udev/data/$id
                : > "$oldstackdir/$id"
                chmod 0444 "$oldstackdir/$id"
        done
        for f in "$oldstackdir"/*; do
                for i in $(seq 0 $((N-1))); do
                        [ "${f##*/}" = "c${NUMS[$i]}" ] || continue
                        [ -e /dev/fake$i ] || continue
                        if [ -z "$best" ] || [ "${PRIO[$i]}" -gt "$bp" ]; then
                                best=$i; bp=${PRIO[$i]}
                        fi
                done
        done
        [ -n "$best" ] && ln -sfn ../fake$best /dev/test/a
}

# add devices with an older eudev, which is still running during an upgrade
old_add() {
        if [ -n "${DL_OLD_DRIVER:-}" ]; then
                run_seq "$DL_OLD_DRIVER" $(for i in "$@"; do echo add:$i; done)
        else
                write_old_format "$@"
        fi
}

scenario_upgrade() {
        local i
        echo "== upgrade: stack entries of an older eudev, which is still running during the upgrade"
        reset_state
        PRIO=(0 10 5 7 -1 3); write_rules
        for i in 0 1 2 4; do node_add $i; done
        old_add 0 1 2 4
        check "old eudev, initial" ../fake1
        echo "  stack directory of the old eudev:"; describe_stack "$oldstackdir"
        # fake4 disappears while udevd is restarted: node and sysfs entry gone, no remove event
        node_del 4
        node_add 3
        run_debug add:3
        check "fake3 (7) added below the owner fake1 (10), which has an old format entry" ../fake1
        check_missing "$oldstackdir" "the old stack directory is taken over by the first event"
        check_log_missing "the entry of the vanished fake4 is ignored quietly" "Failed to read 'c${NUMS[4]}'"
        echo "  stack directory after the first event:"; describe_stack
        # the older eudev is still running and handles an event: it sees only its own directory
        node_add 5
        old_add 5
        check "fake5 (3) added by the older eudev, which only sees its own entry" ../fake5
        run_seq "$DRIVER" change:2
        check "the next event takes over the new entry of the older eudev" ../fake1
        check_missing "$oldstackdir" "the old stack directory is taken over again"
        echo "  stack directory now:"; describe_stack
        node_del 1
        run_seq "$DRIVER" remove:1
        check "fake1 with an old format entry removed" ../fake3
        node_del 3
        run_seq "$DRIVER" remove:3
        check "fake3 removed, fake2 (5) with an old format entry wins" ../fake2
        PRIO[0]=6; write_rules
        run_seq "$DRIVER" change:0
        check "fake0 with an old format entry raised to 6" ../fake0
        PRIO[0]=0; write_rules
        run_seq "$DRIVER" change:0
        check "fake0 lowered to 0, fake2 (5) with an old format entry wins" ../fake2
        node_del 2
        run_seq "$DRIVER" remove:2
        check "fake2 with an old format entry removed" ../fake5
        node_del 5
        run_seq "$DRIVER" remove:5
        node_del 0
        run_seq "$DRIVER" remove:0
        check "all removed" ""
        check_missing "$oldstackdir" "no old stack directory at the end"
        echo "  stack directory at the end, the entry of fake4 stays:"; describe_stack
}

scenario_churn() {
        local r i j act dup present=() evs exp bad=0
        echo "== churn: $ROUNDS rounds of concurrent add, remove and change events with random priorities"
        reset_state
        RANDOM=4242
        PRIO=()
        for i in $(seq 0 $((N-1))); do PRIO[$i]=$((RANDOM % 100 - 50)); present[$i]=0; done
        for r in $(seq 1 $ROUNDS); do
                evs=()
                for i in $(seq 0 $((N-1))); do
                        [ $((RANDOM % 3)) -eq 0 ] && continue
                        if [ "${present[$i]}" = 0 ]; then
                                act=add
                        elif [ $((RANDOM % 2)) -eq 0 ]; then
                                act=remove
                        else
                                act=change
                        fi
                        if [ $act != remove ]; then
                                # keep the priorities distinct
                                while :; do
                                        PRIO[$i]=$((RANDOM % 100 - 50))
                                        dup=0
                                        for j in $(seq 0 $((N-1))); do
                                                [ $j -ne $i ] && [ "${PRIO[$j]}" = "${PRIO[$i]}" ] && dup=1
                                        done
                                        [ $dup = 0 ] && break
                                done
                        fi
                        case $act in
                                add) node_add $i; present[$i]=1 ;;
                                remove) node_del $i; present[$i]=0 ;;
                        esac
                        evs+=($act:$i)
                done
                [ ${#evs[@]} -eq 0 ] && continue
                write_rules
                run_events "$DRIVER" "${evs[@]}"
                exp=$(expected $(for i in $(seq 0 $((N-1))); do [ "${present[$i]}" = 1 ] && echo $i; done))
                check "round $r (${evs[*]})" "$exp" || bad=$((bad+1))
        done
        echo "  churn: $bad/$ROUNDS rounds wrong"
}

scenario_node_perms() {
        echo "== node_perms: devlinks are created also when the device node cannot be handled as asked"
        reset_state
        PRIO=(0 0)
        # changing the owner of a host device node fails here: EROFS, as it is mounted read-only
        EXTRA_LINKS='KERNEL=="fake0", OWNER="0", SYMLINK+="t6/perm"'
        write_rules
        node_add 0
        run_seq "$DRIVER" add:0
        check_exists /dev/t6/perm "the owner of the device node cannot be changed"
        # a device node with another device number: /dev/fake1 is the host's null instead of zero
        EXTRA_LINKS='KERNEL=="fake1", SYMLINK+="t6/other"'
        write_rules
        ln -s ../../devices/virtual/fake/fake1 /sys/dev/char/${NUMS[1]}
        bind_node null /dev/fake1 || exit 1
        run_seq "$DRIVER" add:1
        check_exists /dev/t6/other "the device node has another device number"
}

scenario_remove_owner() {
        echo "== remove_owner: on removal, the devlink is only searched again when the device owns it"
        reset_state
        PRIO=(0 10 5)
        write_rules
        node_add 0; node_add 1; node_add 2
        run_seq "$DRIVER" add:0 add:1 add:2
        check "initial" ../fake1
        node_del 0
        run_debug remove:0
        check "fake0, which does not own the devlink, removed" ../fake1
        check_log_missing "the devlink of another device is kept" "Symbolic link '/dev/test/a' points to"
        check_log_missing "the devlink of another device is kept" "No reference left"
        node_del 1
        run_debug remove:1
        check "the owner fake1 removed" ../fake2
        # a devlink changed by the user to point outside of /dev is updated
        node_add 0
        run_seq "$DRIVER" add:0
        ln -sfn /etc/hostname /dev/test/a
        node_del 0
        run_debug remove:0
        check "fake0 removed while the devlink points outside of /dev" ../fake2
        check_log "the devlink pointing outside of /dev is updated" "which is outside of '/dev/'"
}

scenario_repair() {
        echo "== repair: a broken devlink is repaired by an add or change event of a device claiming it"
        reset_state
        PRIO=(5 1)
        write_rules
        node_add 0
        run_seq "$DRIVER" add:0
        check "initial" ../fake0
        ln -sfn /etc/hostname /dev/test/a
        node_add 1
        run_seq "$DRIVER" add:1
        check "fake1 (1) added while the devlink points outside of /dev" ../fake0
        : > /dev/regfile
        ln -sfn /dev/regfile /dev/test/a
        run_seq "$DRIVER" change:1
        check "fake1 changed while the devlink points to a regular file" ../fake0
        ln -sfn a /dev/test/a
        run_seq "$DRIVER" change:1
        check "fake1 changed while the devlink points to itself" ../fake0
}

# every device has its own devlink t5/x/dN; the directories t5/x and t5 are removed with the last one
scenario_dir_race() {
        local r i present=() evs bad=0 missing
        echo "== dir_race: $ROUNDS rounds of devices with devlinks in the same directory added and removed concurrently"
        reset_state
        RANDOM=1717
        PRIO=()
        EXTRA_LINKS=$(for i in $(seq 0 $((N-1))); do echo "KERNEL==\"fake$i\", SYMLINK+=\"t5/x/d$i\""; done)
        write_rules
        for i in $(seq 0 $((N-1))); do present[$i]=0; done
        for r in $(seq 1 $ROUNDS); do
                evs=()
                for i in $(seq 0 $((N-1))); do
                        if [ "${present[$i]}" = 0 ]; then
                                [ $((RANDOM % 2)) -eq 0 ] && continue
                                node_add $i; present[$i]=1; evs+=(add:$i)
                        else
                                [ $((RANDOM % 4)) -eq 0 ] && continue
                                node_del $i; present[$i]=0; evs+=(remove:$i)
                        fi
                done
                [ ${#evs[@]} -eq 0 ] && continue
                run_events "$DRIVER" "${evs[@]}"
                missing=""
                for i in $(seq 0 $((N-1))); do
                        if [ "${present[$i]}" = 1 ] && [ "$(readlink /dev/t5/x/d$i)" != ../../fake$i ]; then
                                missing="$missing d$i"
                        elif [ "${present[$i]}" = 0 ] && [ -L /dev/t5/x/d$i ]; then
                                missing="$missing -d$i"
                        fi
                done
                if [ -n "$missing" ]; then
                        echo "  FAIL round $r (${evs[*]}): wrong devlinks:$missing"
                        FAILS=$((FAILS+1)); bad=$((bad+1))
                fi
        done
        echo "  dir_race: $bad/$ROUNDS rounds wrong"
}

scenario_symlink_values() {
        echo "== symlink_values: SYMLINK= values and devlinks of the old database are normalized"
        reset_state
        PRIO=(0)
        EXTRA_LINKS='KERNEL=="fake0", SYMLINK+="t2/foo/ t2//bar t2/./baz /dev/t2/abs t2/a/../b"'
        write_rules
        node_add 0
        run_seq "$DRIVER" add:0
        check_exists /dev/t2/foo "t2/foo/"
        check_exists /dev/t2/bar "t2//bar"
        check_exists /dev/t2/baz "t2/./baz"
        check_exists /dev/t2/abs "/dev/t2/abs"
        check_missing /dev/t2/b "t2/a/../b"
        check_missing /dev/t2/a "t2/a/../b"
        # a devlink with a trailing slash in the database, as eudev 3.2.14 and older wrote it
        node_add 1
        PRIO=(0 0)
        EXTRA_LINKS='KERNEL=="fake1", SYMLINK+="t3/old"'
        write_rules
        run_seq "$DRIVER" add:1
        check_exists /dev/t3/old "t3/old"
        sed -i 's|^S:t3/old$|S:t3/old/|' /run/udev/data/c${NUMS[1]}
        EXTRA_LINKS=""
        write_rules
        run_seq "$DRIVER" change:1
        check_missing /dev/t3/old "t3/old/ from the database, dropped by the rules"
}

scenario_link_priority() {
        echo "== link_priority: a rule line with an invalid value is dropped"
        reset_state
        PRIO=(5)
        EXTRA_LINKS='KERNEL=="fake1", OPTIONS+="link_priority=10x", SYMLINK+="test/bad"
KERNEL=="fake2", OPTIONS+="link_priority=3,string_escape=replace"'
        write_rules
        node_add 0; node_add 1; node_add 2
        run_debug add:0 add:1 add:2
        check "fake1 with link_priority=10x does not win over fake0 (5)" ../fake0
        check_missing /dev/test/bad "SYMLINK+= of the line with link_priority=10x"
        check_log "the invalid value is reported" "Failed to parse link priority '10x'"
        check_log_missing "a valid value followed by another option is accepted" "Failed to parse link priority '3"
        PRIO=(2)
        write_rules
        run_seq "$DRIVER" change:0
        check "fake2 (3) with another option in the same OPTIONS wins over fake0 (2)" ../fake2
}

scenario_cleanup_db() {
        local pid
        echo "== cleanup_db: udevadm info --cleanup-db removes lock files that are not held"
        if [ ! -x "${UDEVADM:-}" ]; then
                echo "  udevadm not found, skipping"
                return
        fi
        reset_state
        mkdir -p /run/udev/links.lock
        : > /run/udev/links.lock/stale
        : > /run/udev/links.lock/held
        # the subshell becomes sleep, which holds the lock until it is killed
        ( exec 9>/run/udev/links.lock/held && flock -x 9 && touch "$W/locked" && exec sleep 30 ) &
        pid=$!
        while [ ! -e "$W/locked" ]; do sleep 0.05; done
        "$UDEVADM" info --cleanup-db >>"$W/driver.log" 2>&1
        check_missing /run/udev/links.lock/stale "a lock file that is not held"
        if [ ! -e /run/udev/links.lock/held ]; then
                echo "  FAIL a lock file that is held: /run/udev/links.lock/held is missing"
                FAILS=$((FAILS+1))
        fi
        kill $pid 2>/dev/null
        wait $pid 2>/dev/null
        rm -f "$W/locked"
}

for s in $SCENARIOS; do
        scenario_$s
done

echo "TOTAL FAILURES: $FAILS"
if [ -n "${DL_KEEP_LOG:-}" ]; then cp "$W/driver.log" "$DL_KEEP_LOG"; fi
for i in $(seq 0 $((N-1))); do node_del $i; done
umount /dev/null
# never recurse into the bind mount of the host's /dev
if umount -l "$HOSTDEV" && rmdir "$HOSTDEV"; then
        rm -rf "$W"
fi
[ $FAILS -eq 0 ]
