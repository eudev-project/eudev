ADOPTION NOTICE (2021-09-14)

Currently eudev is in the process of being adopted by a newly formed project by Alpine, Devuan and Gentoo contributors (a-z order). Some of the below links and/or contacts may be outdated until the process is complete and all the infra set up.

As of now we are hanging on [Libera.Chat](https://libera.chat/):  
ircs://irc.libera.chat:6697/#eudev  
https://web.libera.chat/#eudev

	Boian Bonev

==========

IMPORTANT DEPRECATION NOTICE (2021-08-20)

Currently eudev is no longer being supported.  Eudev was started, in
part because systemd did not build on musl-libc systems and a fork
of the udev portion of systemd was required.  Currently systemd can
be built on musl systems with patches from the openembedded team, and
the need to maintain a separate fork is no longer pressing.

Nonetheless, many distros have adopted eudev as their device manager
and so may want to continue using it.  Anyone interested in inheriting
the repo may contact me at blueness@gentoo.org.

	Anthony G. Basile

==========


This git repo is a fork of git://anongit.freedesktop.org/systemd/systemd
with the aim of isolating udev from any particular flavor of system
initialization.  In this case, the isolation is from systemd.

This is a project started by Gentoo developers and testing is currently being
done mostly on OpenRC.  We welcome contribution from others using a variety of
system initializations to ensure eudev remains system initialization and
distribution neutral.

Homepage: https://wiki.gentoo.org/wiki/Project:Eudev

Tarballs of releases: http://dev.gentoo.org/~blueness/eudev/

Contact: You can email us as a group below.

IRC: Freenode/#gentoo-udev

Committers (alphabetical order by last name):

    Luca Barbato        (lu_zero)           <lu_zero@gentoo.org>
    Anthony G. Basile   (blueness)          <blueness@gentoo.org>
    Francisco Izquierdo (klondike)          <klondike@gentoo.org>
    Ian Stakenvicius    (axs)               <axs@gentoo.org>
    Matthew Thode       (prometheanfire)    <prometheanfire@gentoo.org>
    Tony Vroon          (chainsaw)          <tony@linx.net>
    Richard Yao         (ryao)              <ryao@gentoo.org>

## Build status
[![Build Status](https://travis-ci.org/gentoo/eudev.svg?branch=master)](https://travis-ci.org/gentoo/eudev)
