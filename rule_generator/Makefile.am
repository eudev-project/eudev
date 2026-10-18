ACLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS}

# ------------------------------------------------------------------------------
# rule_generator - persistent network rule generator
# ------------------------------------------------------------------------------
# generated from write_net_rules.in with the directories of the build, fully expanded, like
# 64-btrfs.rules in rules/, so not in the release tarball, which has write_net_rules.in
nodist_udevlibexec_SCRIPTS = \
        write_net_rules

EXTRA_DIST = \
        write_net_rules.in \
        rule_generator.functions.in \
        75-persistent-net-generator.rules

CLEANFILES = \
        write_net_rules \
        write_net_rules.tmp \
        rule_generator.functions \
        rule_generator.functions.tmp

# generated from rule_generator.functions.in with the rootrundir of the build, like write_net_rules
udevhomedir = $(udevlibexecdir)
nodist_udevhome_DATA = rule_generator.functions

# With --with-net-ifnames-default=no, 80-net-name-slot.rules is installed too, and renames the interfaces
# only with net.ifnames=1 on the kernel command line; then the generator must record no names. The variant
# for that build is generated from 75-persistent-net-generator.rules, with that check after the test of
# NAME, like 64-btrfs.rules, so not in the release tarball, and installed without the directory.
if NET_IFNAMES_DEFAULT_NO
nodist_udevrules_DATA = \
        net-ifnames-no/75-persistent-net-generator.rules
else
dist_udevrules_DATA = \
        75-persistent-net-generator.rules
endif

do_subst = $(SED) \
	-e 's,[@]udevconfdir[@],$(udevconfdir),g' \
	-e 's,[@]udevlibexecdir[@],$(udevlibexecdir),g' \
	-e 's,[@]rootrundir[@],$(rootrundir),g'

write_net_rules: $(srcdir)/write_net_rules.in Makefile
	$(AM_V_GEN)$(do_subst) $(srcdir)/write_net_rules.in > write_net_rules.tmp && \
		chmod +x write_net_rules.tmp && mv -f write_net_rules.tmp write_net_rules

rule_generator.functions: $(srcdir)/rule_generator.functions.in Makefile
	$(AM_V_GEN)$(do_subst) $(srcdir)/rule_generator.functions.in > rule_generator.functions.tmp && \
		mv -f rule_generator.functions.tmp rule_generator.functions

# the check goes after the line that ends the rules for interfaces that have a name already, which must be
# there once, else the build fails
net-ifnames-no/75-persistent-net-generator.rules: $(srcdir)/75-persistent-net-generator.rules Makefile
	$(AM_V_at)$(MKDIR_P) net-ifnames-no
	$(AM_V_GEN)$(AWK) '{ print } \
		/^NAME=="\?\*", GOTO="persistent_net_generator_end"$$/ { \
			n++; \
			print ""; \
			print "# eudev was built with --with-net-ifnames-default=no: not with net.ifnames=1, when"; \
			print "# 80-net-name-slot.rules renames the interfaces"; \
			print "IMPORT{cmdline}=\"net.ifnames\""; \
			print "ENV{net.ifnames}==\"1\", GOTO=\"persistent_net_generator_end\"" } \
		END { exit n != 1 }' $(srcdir)/75-persistent-net-generator.rules > $@.tmp && \
		mv -f $@.tmp $@

clean-local:
	rm -rf net-ifnames-no
