ACLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS}

SUBDIRS = \
	src

if ENABLE_PROGRAMS
SUBDIRS += \
	rules \
	test
endif

if ENABLE_MANPAGES
SUBDIRS += \
	man
endif

if ENABLE_HWDB
SUBDIRS += \
	hwdb
endif

if ENABLE_RULE_GENERATOR
SUBDIRS += \
	rule_generator
endif

# ------------------------------------------------------------------------------
# shell completion of udevadm

bashcompletiondir = @bashcompletiondir@
zshcompletiondir = @zshcompletiondir@

EXTRA_DIST = \
	shell-completion/bash/udevadm \
	shell-completion/zsh/_udevadm

if ENABLE_PROGRAMS
if ENABLE_BASH_COMPLETION
dist_bashcompletion_DATA = \
	shell-completion/bash/udevadm
endif

if ENABLE_ZSH_COMPLETION
dist_zshcompletion_DATA = \
	shell-completion/zsh/_udevadm
endif
endif

# the default bash completion directory of bash-completion.pc is outside of the prefix
AM_DISTCHECK_CONFIGURE_FLAGS = \
	--with-bashcompletiondir=$$dc_install_base/share/bash-completion/completions \
	--with-zshcompletiondir=$$dc_install_base/share/zsh/site-functions
