Building eudev
==============

The following instructions provide the steps needed to acquire and build the
eudev software on different Linux distributions. Similar instructions apply to
other distributions, not included here, though the package names and the syntax
of the package manager may vary.

Please note that command examples in this document use the following convention.
Commands prefixed by a "$" symbol are to be run as a regular, user. Commands
with a "#" prefix need to be run as the root user. If your user has sudo access
then sudo may be used instead of logging into the root account.


1. Installing dependencies
==========================

The first thing we need to do is install the dependencies required to build
eudev. This can be accomplished by running the following commands depending on
the Linux distribution:


1.1. Alpine
-----------

# apk --no-cache add \
      autoconf \
      automake \
      build-base \
      glib-dev \
      gobject-introspection-dev \
      gperf \
      kmod-dev \
      libxslt \
      linux-headers \
      perl \
      util-linux-dev


1.2. ArchLinux
--------------

# pacman -S --needed \
         autoconf \
         automake \
         gawk \
         gcc \
         glib2 \
         gperf \
         kmod \
         libxslt \
         libtool \
         linux-headers \
         m4 \
         make \
         sed \
         util-linux


1.3. Debian/Devuan/Ubuntu or other derivatives
----------------------------------------------

# apt-get update && apt-get install \
          autoconf \
          automake \
          build-essential \
          docbook-xml \
          docbook-xsl \
          gnu-efi \
          gobject-introspection \
          gperf \
          intltool \
          libacl1-dev \
          libblkid-dev \
          libcap-dev \
          libglib-object-introspection-perl \
          libkmod-dev \
          libselinux1-dev \
          libtool \
          m4 \
          pkg-config \
          xsltproc


1.4. Gentoo
-----------

# TODO


2. Downloading the source code
==============================

There are two common approaches to downloading the project's source code. The
first is to visit the eudev GitHub releases page

	https://github.com/eudev-project/eudev/releases

and downloading the latest eudev-*.tar.xz archive file. Then unpack the
downloaded archive. For example, if we downloaded eudev version 3.2.10 we could
unpack the archive using the following command:

$ tar xf eudev-3.2.10.tar.gz

Alternatively, we can download the latest source code by using git. This is
the recommended option for developers. Here we use the git source control
program and use it to download the latest eudev source code:

$ git clone https://github.com/eudev-project/eudev.git


3. Configuring and building eudev
=================================

To build the eudev source code, run the following commands:

$ cd eudev

$ ./autogen.sh

$ ./configure

Please note that, by default, the configure script will assume we want to place
eudev under the /usr directory. If this is not accurate, we can supply an
alternative location using the "--prefix" flag. For instance, to place eudev
under the /usr/local directory tree, run the following:

$ ./configure --prefix /usr/local

Once eudev has been configured we can then perform the build.

$ make


4. Install eudev
================

*** WARNING ****
Installing eudev manually can break your operating system.

Please note that, in most situations, people will not wish to install eudev
manually. This work is typically performed by your distribution's package
manager.

If you really wish to proceed and install eudev manually, you can do so by
running:

# make install


5. Removing eudev
=================

Please note that removing eudev can damage your system.

If you wish to remove eudev from yoru system you can do so by running the
following command:

# make uninstall
