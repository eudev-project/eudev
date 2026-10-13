ACLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS}

# ------------------------------------------------------------------------------
# rule_generator - persistent network rule generator
# ------------------------------------------------------------------------------
# generated from write_net_rules.in with the directories of the build, fully expanded, like
# 64-btrfs.rules in rules/, so not in the release tarball, which has write_net_rules.in
nodist_udevlibexec_SCRIPTS = \
        write_net_rules

EXTRA_DIST = \
        write_net_rules.in

CLEANFILES = \
        write_net_rules \
        write_net_rules.tmp

udevhomedir = $(udevlibexecdir)
dist_udevhome_DATA = rule_generator.functions

dist_udevrules_DATA = \
        75-persistent-net-generator.rules

do_subst = $(SED) \
	-e 's,[@]udevconfdir[@],$(udevconfdir),g' \
	-e 's,[@]udevlibexecdir[@],$(udevlibexecdir),g'

write_net_rules: $(srcdir)/write_net_rules.in Makefile
	$(AM_V_GEN)$(do_subst) $(srcdir)/write_net_rules.in > write_net_rules.tmp && \
		chmod +x write_net_rules.tmp && mv -f write_net_rules.tmp write_net_rules
