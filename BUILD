Building eudev
===================

The following instructions provide the steps needed to acquire and build the eudev
software on the Debian, Devuan, and compatible Linux distributions.

Please note that command examples in this document use the following convention. Commands
prefixed by a "$" symbol are to be run as a regular, user. Commands with a "#" prefix
need to be run as the root user. If your user has sudo access then sudo may be
used instead of logging into the root account.


1. Installing dependencies
============================

The first thing we need to do is install the dependencies required to build eudev. 
This can be accomplished by running the following two commands:

# apt-get update

# apt-get install build-essential pkg-config docbook-xsl docbook-xml m4 automake autoconf intltool gperf gnu-efi libcap-dev libselinux1-dev libacl1-dev libkmod-dev libblkid-dev gobject-introspection libglib-object-introspection-perl xsltproc 



2. Downloading the source code
================================

There are two common approaches to downloading the project's source code. The first
is to visit the eudev GitHub releases page (https://github.com/eudev-project/eudev/releases)
and downloading the latest tar.gz archive file. Then unpack the downloaded archive. For
example, if we downloaded eudev version 3.2.10 we could unpack the archive using the
following command:

$ tar xf eudev-3.2.10.tar.gz


Alternatively, we can download the latest source code by using git. This is probably the
better option for developers. Here we install the git source control program and
use it to download the latest eudev source code:

# apt-get install git

$ git clone https://github.com/eudev-project/eudev.git


3. Configuring and building eudev
==================================

To build the eudev source code, run the following commands:

$ cd eudev

$ ./autogen.sh

$ ./configure

Please note that, by default, the configure script will assume we want to place
eudev under the /usr directory. If this is not accurate, we can supply an alternative
location using the "--prefix" flag. For instance, to place eudev under the /usr/local
directory tree, run the following:

$ ./configure --prefix /usr/local

Once eudev has been configured we can then perform the build.

$ make


4. Install eudev
=================

Please note that, in most situations, people will not wish to install eudev manually.
This work is typically performed by your distribution's package manager. Installing
eudev manually can break your operating system.

If you really wish to proceed and install eudev manually, you can do so by running:

# make install


5. Removing eudev
==================

Please note that removing eudev can damage your system.

If you wish to remove eudev from yoru system you can do so by running the
following command:

# make uninstall
