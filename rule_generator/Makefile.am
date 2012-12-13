ACLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS}

# ------------------------------------------------------------------------------
# rule_generator - persistent network and optical device rule generator
# ------------------------------------------------------------------------------
dist_udevlibexec_SCRIPTS = \
        write_cd_rules \
        write_net_rules

udevhomedir = $(udevlibexecdir)
dist_udevhome_DATA = rule_generator.functions

dist_udevrules_DATA = \
        75-cd-aliases-generator.rules \
        75-persistent-net-generator.rules
