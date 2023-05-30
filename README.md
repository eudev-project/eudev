**eudev** is a standalone dynamic and persistent device naming support (aka
userspace devfs) daemon that runs independently from the init system.
**eudev** strives to remain init system and linux distribution neutral. It is
currently used as the devfs manager for more than a dozen different linux
distributions.

This git repo is a fork of git://anongit.freedesktop.org/systemd/systemd with
the aim of isolating udev from any particular flavor of system initialization.
In this case, the isolation is from systemd.

This is a project started by Gentoo developers and testing was initially being
done mostly on OpenRC. We welcome contribution from others using a variety of
system initializations to ensure **eudev** remains system initialization and
distribution neutral. On 2021-08-20 Gentoo decided to abandon eudev and a new
project was established on 2021-09-14 by Alpine, Devuan and Gentoo
contributors (alphabetical order).

Homepage: https://github.com/eudev-project/eudev

Tarballs of releases: https://github.com/eudev-project/eudev/releases  
Old releases (archive): http://dev.gentoo.org/~blueness/eudev/

The eudev community gathers on [Libera.Chat](https://libera.chat/):  
ircs://irc.libera.chat:6697/#eudev  
https://web.libera.chat/#eudev

Active team members (alphabetical order by last name):

    Arsen Asenović      (Arsen)             <arsen@aarsen.me>
    Luca Barbato        (lu_zero)           <lu_zero@gentoo.org>
    Anthony G. Basile   (blueness)          <blueness@gentoo.org>
    Boian Bonev         (bb|hcb)            <boian@bonev.com>
    Ariadne Conill      (Ariadne)           <ariadne@dereferenced.org>

Emeritus team members (alphabetical order by last name):

    Francisco Izquierdo (klondike)          <klondike@gentoo.org>
    Ian Stakenvicius    (axs)               <axs@gentoo.org>
    Matthew Thode       (prometheanfire)    <prometheanfire@gentoo.org>
    Tony Vroon          (chainsaw)          <tony@linx.net>
    Richard Yao         (ryao)              <ryao@gentoo.org>

## Build status
[![Build Status](https://github.com/eudev-project/eudev/actions/workflows/build.yml/badge.svg)](https://github.com/eudev-project/eudev/actions)
