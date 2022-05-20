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
          gperf \
          intltool \
          libacl1-dev \
          libblkid-dev \
          libcap-dev \
          libkmod-dev \
          libselinux1-dev \
          libtool \
          m4 \
          pkg-config \
          xsltproc


1.4. Gentoo
-----------

# emerge -u \
    docbook-xml-dtd \
    docbook-xml-dtd \
    docbook-xsl-stylesheets \
    gperf \
    kmod \
    libselinux \
    libxslt \
    linux-headers \
    make \
    perl \
    tree \
    util-linux \
    virtual/libcrypt \
    virtual/pkgconfig


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

Please note that building eudev requires a modern C compiler like gcc or clang.
Any other C compiler that conforms to the standards should work but that path
is not well tested and may require little tweaks to the code.

Please note that configure will install eudev under /usr by default. In case
that the desired installation directory is different that may be changed by
using the "--prefix" option as shown in the example below. To place eudev under
/usr/local, run the following:

$ ./configure --prefix /usr/local

Once eudev has been configured run make to build it:

$ make

Or alternatively, using more cores in parallel:

$ make -j 16


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
