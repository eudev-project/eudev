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
	hwdb.d
endif

if ENABLE_RULE_GENERATOR
SUBDIRS += \
	rule_generator
endif

# the targets that regenerate and check the hwdb files, see hwdb.d/README
regenerate-hwdb parse-hwdb:
	cd hwdb.d && $(MAKE) $(AM_MAKEFLAGS) $@

.PHONY: regenerate-hwdb parse-hwdb

# ------------------------------------------------------------------------------
# shell completion of udevadm

bashcompletiondir = @bashcompletiondir@
zshcompletiondir = @zshcompletiondir@

# with the files that tell how to build and work on eudev, and autogen.sh, which regenerates the build system
# and, with man/make.sh, the man pages
EXTRA_DIST = \
	autogen.sh \
	BUILD \
	CONTRIBUTING \
	LEGACY \
	NOTES \
	LICENSES/README.md \
	LICENSES/BSD-3-Clause.txt \
	LICENSES/CC0-1.0.txt \
	LICENSES/GPL-2.0-or-later.txt \
	LICENSES/LGPL-2.0-or-later.txt \
	LICENSES/LGPL-2.1-or-later.txt \
	LICENSES/Linux-syscall-note.txt \
	LICENSES/MIT.txt \
	LICENSES/murmurhash2-public-domain.txt \
	shell-completion/bash/udevadm \
	shell-completion/zsh/_udevadm \
	tools/gen-net-naming-rules.py

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

# the completions list the builtins of udevadm test-builtin, drop the ones that are not built
unbuilt_builtins =
if !HAVE_BLKID
unbuilt_builtins += blkid
endif
if !HAVE_KMOD
unbuilt_builtins += kmod
endif
if !ENABLE_TPM2
unbuilt_builtins += tpm2_id
endif

install-data-hook:
if ENABLE_PROGRAMS
if ENABLE_BASH_COMPLETION
	$(AM_V_at)for b in $(unbuilt_builtins); do \
		sed -i -e "s/\([( ]\)$$b /\1/" '$(DESTDIR)$(bashcompletiondir)/udevadm' || exit 1; \
	done
endif
if ENABLE_ZSH_COMPLETION
	$(AM_V_at)for b in $(unbuilt_builtins); do \
		sed -i -e "s/\([( ]\)$$b /\1/" '$(DESTDIR)$(zshcompletiondir)/_udevadm' || exit 1; \
	done
endif
endif

# the default bash completion directory of bash-completion.pc is outside of the prefix
AM_DISTCHECK_CONFIGURE_FLAGS = \
	--with-bashcompletiondir=$$dc_install_base/share/bash-completion/completions \
	--with-zshcompletiondir=$$dc_install_base/share/zsh/site-functions
