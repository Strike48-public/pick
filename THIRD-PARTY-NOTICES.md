# Third-Party Notices (bundled Linux shared libraries)

The Pick Linux release tarballs redistribute the shared libraries
listed below under lib/ (resolved via the $ORIGIN/lib rpath baked
into the binaries). The license texts reproduced here are taken
verbatim from the /usr/share/doc/*/copyright files of the Ubuntu
22.04 (jammy) runtime packages the libraries are bundled from —
the same packages the release pipeline installs and bundles.

Each library is redistributed in binary form; where a license
requires notice reproduction in binary distributions (BSD-3,
Apache-2.0, OpenSSL), the text is included in full below.

## libpcap0.8 1.10.1-4ubuntu1.22.04.2 — bundled: libpcap.so.0.8

Copyright/license source (verbatim): `/usr/share/doc/libpcap0.8/copyright` in the libpcap0.8 package.

```text
This package was debianized by Romain Francoise <rfrancoise@debian.org>
on Fri, 16 Apr 2004 18:41:39 +0200, based on work by:
 + Anand Kumria <wildfire@progsoc.org>
 + Torsten Landschoff <torsten@debian.org>

It was downloaded from http://tcpdump.org/release/libpcap-0.8.3.tar.gz

Upstream Authors: tcpdump-workers@tcpdump.org

Licensed under the 3-clause BSD license:

  Copyright (C) 1993-2008 The Regents of the University of California.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:

    1. Redistributions of source code must retain the above copyright
       notice, this list of conditions and the following disclaimer.
    2. Redistributions in binary form must reproduce the above copyright
       notice, this list of conditions and the following disclaimer in
       the documentation and/or other materials provided with the
       distribution.
    3. The names of the authors may not be used to endorse or promote
       products derived from this software without specific prior
       written permission.

  THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
  IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.

Current upstream maintainers:
	Bill Fenner			<fenner@research.att.com>
	Fulvio Risso			<risso@polito.it>
	Guy Harris	 		<guy@alum.mit.edu>
	Hannes Gredler			<hannes@juniper.net>
	Jun-ichiro itojun Hagino	<itojun@iijlab.net>
	Michael Richardson	 	<mcr@sandelman.ottawa.on.ca>

Additional people who have contributed patches:

	Alan Bawden			<Alan@LCS.MIT.EDU>
	Alexey Kuznetsov		<kuznet@ms2.inr.ac.ru>
	Albert Chin			<china@thewrittenword.com>
	Andrew Brown			<atatat@atatdot.net>
	Antti Kantee			<pooka@netbsd.org>
	Arkadiusz Miskiewicz		<misiek@pld.org.pl>
	Armando L. Caro Jr.		<acaro@mail.eecis.udel.edu>
	Assar Westerlund	 	<assar@sics.se>
	Brian Ginsbach			<ginsbach@cray.com>
	Charles M. Hannum		<mycroft@netbsd.org>
	Chris G. Demetriou		<cgd@netbsd.org>
	Chris Pepper			<pepper@mail.reppep.com>
	Darren Reed			<darrenr@reed.wattle.id.au>
	David Kaelbling			<drk@sgi.com>
	David Young			<dyoung@ojctech.com>
	Don Ebright			<Don.Ebright@compuware.com>
	Eric Anderson			<anderse@hpl.hp.com>
	Franz Schaefer			<schaefer@mond.at>
	Gianluca Varenni		<varenni@netgroup-serv.polito.it>
	Gisle Vanem			<giva@bgnett.no>
	Graeme Hewson			<ghewson@cix.compulink.co.uk>
	Greg Stark			<gsstark@mit.edu>
	Greg Troxel			<gdt@ir.bbn.com>
	Guillaume Pelat			<endymion_@users.sourceforge.net>
	Hyung Sik Yoon			<hsyn@kr.ibm.com>
	Igor Khristophorov		<igor@atdot.org>
	Jan-Philip Velders		<jpv@veldersjes.net>
	Jason R. Thorpe			<thorpej@netbsd.org>
	Javier Achirica			<achirica@ttd.net>
	Jean Tourrilhes			<jt@hpl.hp.com>
	Jefferson Ogata			<jogata@nodc.noaa.gov>
	Jesper Peterson			<jesper@endace.com>
	John Bankier			<jbankier@rainfinity.com>
	Jon Lindgren			<jonl@yubyub.net>
	Juergen Schoenwaelder		<schoenw@ibr.cs.tu-bs.de>
	Kazushi Sugyo			<sugyo@pb.jp.nec.com>
	Klaus Klein			<kleink@netbsd.org>
	Koryn Grant			<koryn@endace.com>
	Krzysztof Halasa		<khc@pm.waw.pl>
	Lorenzo Cavallaro		<sullivan@sikurezza.org>
	Loris Degioanni			<loris@netgroup-serv.polito.it>
	Love Hörnquist-Åstrand		<lha@stacken.kth.se>
	Maciej W. Rozycki		<macro@ds2.pg.gda.pl>
	Marcus Felipe Pereira		<marcus@task.com.br>
	Martin Husemann			<martin@netbsd.org>
	Mike Wiacek			<mike@iroot.net>
	Monroe Williams			<monroe@pobox.com>
	Octavian Cerna			<tavy@ylabs.com>
	Olaf Kirch			<okir@caldera.de>
	Onno van der Linden		<onno@simplex.nl>
	Paul Mundt			<lethal@linux-sh.org>
	Pavel Kankovsky			<kan@dcit.cz>
	Peter Fales			<peter@fales-lorenz.net>
	Peter Jeremy			<peter.jeremy@alcatel.com.au>
	Phil Wood			<cpw@lanl.gov>
	Rafal Maszkowski		<rzm@icm.edu.pl>
	Rick Jones			<raj@cup.hp.com>
	Scott Barron			<sb125499@ohiou.edu>
	Scott Gifford			<sgifford@tir.com>
	Sebastian Krahmer		<krahmer@cs.uni-potsdam.de>
	Shaun Clowes			<delius@progsoc.uts.edu.au>
	Solomon Peachy			<pizza@shaftnet.org>
	Stefan Hudson			<hudson@mbay.net>
	Takashi Yamamoto		<yamt@mwd.biglobe.ne.jp>
	Tony Li				<tli@procket.com>
	Torsten Landschoff	 	<torsten@debian.org>
	Uns Lider			<unslider@miranda.org>
	Uwe Girlich			<Uwe.Girlich@philosys.de>
	Xianjie Zhang			<xzhang@cup.hp.com>
	Yen Yen Lim
	Yoann Vandoorselaere		<yoann@prelude-ids.org>

The original LBL crew:
	Steve McCanne
	Craig Leres
	Van Jacobson
```

## libssl3 3.0.2-0ubuntu1.30 — bundled: libssl.so.3, libcrypto.so.3

Copyright/license source (verbatim): `/usr/share/doc/libssl3/copyright` in the libssl3 package.

```text
Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
Upstream-Name: OpenSSL
Source: https://www.openssl.org

Files: *
Copyright: 1995-2020, The OpenSSL Project Authors
	   1995-1998, Eric A. Young, Tim J. Hudson
	   2004-2014 Akamai Technologies.
	   2008 Andy Polyakov <appro@openssl.org>
	   2017 BaishanCloud.
	   2015 CloudFlare Inc.
	   2014-2016 Cryptography Research Inc.
	   2012-2014 Daniel J. Bernstein
	   2004 EdelKey Project.
	   2011 Google Inc.
	   2018-2019 IBM Corp.
	   2012,2014 Intel Corporation.
	   2012-2016 Jean-Philippe Aumasson
	   2007 KISA(Korea Information Security Agency).
	   2004 Kungliga Tekniska Högskolan
	   2017 National Security Research Institute.
	   2006 Network Resonance Inc.
	   2005,2007-2020 Nokia
	   2006 NTT (Nippon Telegraph and Telephone Corporation)
	   2002,2017-2020 Oracle and/or its affiliates.
	   1995 Patrick Powell
	   2019 Red Hat Inc.
	   2017 Ribose Inc.
	   2004,2018 Richard Levitte <richard@levitte.org>
	   2011 RTFM Inc.
	   2012 Samuel Neves <sneves@dei.uc.pt>
	   2015-2020 Siemens AG
	   2002 The OpenTSA Project.
	   2013-2014 Timo Teräs <timo.teras@gmail.com>
	   2016 Viktor Dukhovni <openssl-users@dukhovni.org>.
	   2016 VMS Software Inc.
License: Apache-2.0

License: Apache-2.0
 Licensed under the Apache License 2.0 (the "License").  You may not use
 this file except in compliance with the License.  You can obtain a copy
 in the file LICENSE in the source distribution or at
 https://www.openssl.org/source/license.html
 .
 On Debian systems, the complete text of the Apache 2.0 License
 can be found in `/usr/share/common-licenses/Apache-2.0'

Files: debian/*
Copyright: Christoph Martin, Kurt Roeckx, Sebastian Andrzej Siewior
License: Apache-2.0

Files: external/perl/Text-Template-1.56/*
Copyright: 2013, Mark Jason Dominus <mjd@cpan.org>.
License: Artistic or GPL-1+

License: Artistic
 This program is free software; you can redistribute it and/or modify
 it under the terms of the Artistic License, which comes with Perl.
 .
 On Debian systems, the complete text of the Artistic License can be
 found in `/usr/share/common-licenses/Artistic'.

License: GPL-1+
 This program is free software; you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation; either version 1, or (at your option)
 any later version.
 .
 On Debian systems, the complete text of version 1 of the GNU General
 Public License can be found in `/usr/share/common-licenses/GPL-1'.
```

## libxcb1 1.14-3ubuntu3 — bundled: libxcb.so.1

Copyright/license source (verbatim): `/usr/share/doc/libxcb1/copyright` in the libxcb1 package.

```text
This package was debianized by Jamey Sharp <sharpone@debian.org> on
Thu, 18 Mar 2004 00:48:42 -0800, and later updated by Josh Triplett
<josh@freedesktop.org>.  The package is co-maintained by the XCB developers
via the XCB mailing list <xcb@lists.freedesktop.org>.

It was downloaded from https://xcb.freedesktop.org/dist

Upstream Authors: Jamey Sharp <sharpone@debian.org>
                  Josh Triplett <josh@freedesktop.org>

Copyright:

Copyright (C) 2001-2006 Bart Massey, Jamey Sharp, and Josh Triplett.
All Rights Reserved.

Permission is hereby granted, free of charge, to any person
obtaining a copy of this software and associated
documentation files (the "Software"), to deal in the
Software without restriction, including without limitation
the rights to use, copy, modify, merge, publish, distribute,
sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall
be included in all copies or substantial portions of the
Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY
KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS
BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
OTHER DEALINGS IN THE SOFTWARE.

Except as contained in this notice, the names of the authors
or their institutions shall not be used in advertising or
otherwise to promote the sale, use or other dealings in this
Software without prior written authorization from the
authors.
```

## libxdo3 1:3.20160805.1-4 — bundled: libxdo.so.3

Copyright/license source (verbatim): `/usr/share/doc/libxdo3/copyright` in the libxdo3 package.

```text
Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
Upstream-Name: xdotool
Upstream-Contact: Jordan Sissel <jls@semicomplete.com>
Source: https://github.com/jordansissel/xdotool/

Files: *
Copyright: 2007-2014 Jordan Sissel <jls@semicomplete.com>,
 Lee Pumphret, Magnus Boman, Russel Harmon,
 Daniel Kahn Gillmor, Henning Bekel, Lukas Mai
License: BSD-3-clause

Files: debian/*
Copyright: 2007-2014 Daniel Kahn Gillmor <dkg@fifthhorseman.net>
License: BSD-3-clause

License: BSD-3-clause
 All rights reserved.
 .
 Redistribution and use in source and binary forms, with or without
 modification, are permitted provided that the following conditions are met:
    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.
    * Neither the name of the Jordan Sissel nor the names of its contributors
      may be used to endorse or promote products derived from this software
      without specific prior written permission.
 .
 THIS SOFTWARE IS PROVIDED BY JORDAN SISSEL ``AS IS'' AND ANY
 EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 DISCLAIMED. IN NO EVENT SHALL JORDAN SISSEL BE LIABLE FOR ANY
 DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```

## libdbus-1-3 1.12.20-2ubuntu4.1 — bundled: libdbus-1.so.3

Copyright/license source (verbatim): `/usr/share/doc/libdbus-1-3/copyright` in the libdbus-1-3 package.

```text
Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
Upstream-Name: D-Bus
Source: https://dbus.freedesktop.org/releases/dbus/
Comment:
 The effective license of the majority of the package, including the
 shared library, is "GPL-2+ or AFL-2.1". Certain utilities are
 "GPL-2+" only.

Files: *
Copyright:
 © 1994 A.M. Kuchling
 © 2002-2008 Red Hat, Inc
 © 2002-2003 CodeFactory AB
 © 2002 Michael Meeks
 © 2004 Imendio HB
 © 2005 Lennart Poettering
 © 2005 Novell, Inc
 © 2005 David A. Wheeler
 © 2006-2013 Ralf Habacker
 © 2006 Mandriva
 © 2006 Peter Kümmel
 © 2006 Christian Ehrlicher
 © 2006 Thiago Macieira
 © 2008 Colin Walters
 © 2009 Klaralvdalens Datakonsult AB, a KDAB Group company
 © 2011-2012 Nokia Corporation
 © 2012-2018 Collabora Ltd.
 © 2013 Intel Corporation
 © 2017 Laurent Bigonville
 © 2018 KPIT Technologies Ltd.
 © 2018 Manish Narang
 "modified code from libassuan, (C) FSF"
License: GPL-2+ or AFL-2.1

Files:
 doc/dbus-test-tool.1.xml.in
 tools/dbus-cleanup-sockets.c
 tools/dbus-monitor.c
 tools/dbus-send.c
 tools/dbus-print-message.?
 tools/dbus-uuidgen.c
 tools/test-tool.c
 tools/tool-common.?
Copyright:
 © 2002 Michael Meeks
 © 2003-2006 Red Hat, Inc.
 © 2003 Philip Blundell
 © 2011 Nokia Corporation
 © 2014-2017 Collabora Ltd.
License: GPL-2+

Files:
 dbus/dbus-server-launchd.?
 doc/dbus-update-activation-environment.1.xml.in
 test/test-apparmor-activation.sh
 test/corrupt.c
 test/data/dbus-installed-tests.aaprofile.in
 test/dbus-daemon-eavesdrop.c
 test/dbus-daemon.c
 test/fdpass.c
 test/internals/printf.c
 test/internals/refs.c
 test/internals/syslog.c
 test/loopback.c
 test/manual-authz.c
 test/marshal.c
 test/monitor.c
 test/relay.c
 test/sd-activation.c
 test/syntax.c
 test/uid-permissions.c
 test/test-utils-glib.?
 tools/dbus-update-activation-environment.c
Copyright:
 © 2007 Tanner Lovelace
 © 2008-2009 Benjamin Reed
 © 2008 Colin Walters
 © 2009 Jonas Bähr
 © 2008-2012 Nokia Corporation
 © 2008-2018 Collabora Ltd
 © 2013 Intel Corporation
 © 2017 Shin-ichi MORITA
License: Expat

Files: tools/strto*ll.c
Copyright: © 1991-1993 The Regents of the University of California
License: BSD-3-clause

Files:
 cmake/modules/FindGLib2.cmake
 cmake/modules/FindGObject.cmake
Copyright:
 © 2008 Laurent Montel
 © 2011 Raphael Kubo da Costa
 © 2013 Ralf Habacker
License: BSD-3-clause-generic
Comment:
 BSD-3-clause with more generic terms for the authors and copyright holders

Files:
 dbus/dbus-hash.c
Copyright:
 © 1991-1993 The Regents of the University of California
 © 1994 Sun Microsystems, Inc
 © 2002 Red Hat, Inc.
License: GPL-2+ or AFL-2.1, and Tcl-BSDish
Comment:
 The Tcl license appears to be compatible with either the GPL-2+
 or the AFL-2.1, so the effective license is "GPL-2+ or AFL-2.1".

Files: dbus/versioninfo.rc.in
Copyright: © 2005 g10 Code GmbH
License: g10-permissive
 This file is free software; as a special exception the author gives
 unlimited permission to copy and/or distribute it, with or without
 modifications, as long as this notice is preserved.
 .
 This program is distributed in the hope that it will be useful, but
 WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
 implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

License: GPL-2+
 This program is free software; you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation; either version 2 of the License, or
 (at your option) any later version.
 .
 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.
 .
 You should have received a copy of the GNU General Public License
 along with this program; if not, write to the Free Software
 Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
Comment:
 On Debian systems, see /usr/share/common-licenses/GPL-2 for the full
 text of the GPL version 2.

License: Expat
 Permission is hereby granted, free of charge, to any person
 obtaining a copy of this software and associated documentation
 files (the "Software"), to deal in the Software without
 restriction, including without limitation the rights to use, copy,
 modify, merge, publish, distribute, sublicense, and/or sell copies
 of the Software, and to permit persons to whom the Software is
 furnished to do so, subject to the following conditions:
 .
 The above copyright notice and this permission notice shall be
 included in all copies or substantial portions of the Software.
 .
 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 DEALINGS IN THE SOFTWARE.

License: Tcl-BSDish
 This software is copyrighted by the Regents of the University of
 California, Sun Microsystems, Inc., Scriptics Corporation, and
 other parties.  The following terms apply to all files associated
 with the software unless explicitly disclaimed in individual files.
 .
 The authors hereby grant permission to use, copy, modify,
 distribute, and license this software and its documentation for any
 purpose, provided that existing copyright notices are retained in
 all copies and that this notice is included verbatim in any
 distributions. No written agreement, license, or royalty fee is
 required for any of the authorized uses.  Modifications to this
 software may be copyrighted by their authors and need not follow
 the licensing terms described here, provided that the new terms are
 clearly indicated on the first page of each file where they apply.
 .
 IN NO EVENT SHALL THE AUTHORS OR DISTRIBUTORS BE LIABLE TO ANY
 PARTY FOR DIRECT, INDIRECT, SPECIAL, INCIDENTAL, OR CONSEQUENTIAL
 DAMAGES ARISING OUT OF THE USE OF THIS SOFTWARE, ITS DOCUMENTATION,
 OR ANY DERIVATIVES THEREOF, EVEN IF THE AUTHORS HAVE BEEN ADVISED
 OF THE POSSIBILITY OF SUCH DAMAGE.
 .
 THE AUTHORS AND DISTRIBUTORS SPECIFICALLY DISCLAIM ANY WARRANTIES,
 INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND
 NON-INFRINGEMENT.  THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS,
 AND THE AUTHORS AND DISTRIBUTORS HAVE NO OBLIGATION TO PROVIDE
 MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS, OR MODIFICATIONS.
 .
 GOVERNMENT USE: If you are acquiring this software on behalf of the
 U.S. government, the Government shall have only "Restricted Rights"
 in the software and related documentation as defined in the Federal
 Acquisition Regulations (FARs) in Clause 52.227.19 (c) (2).  If you
 are acquiring the software on behalf of the Department of Defense,
 the software shall be classified as "Commercial Computer Software"
 and the Government shall have only "Restricted Rights" as defined
 in Clause 252.227-7013 (c) (1) of DFARs.  Notwithstanding the
 foregoing, the authors grant the U.S. Government and others acting
 in its behalf permission to use and distribute the software in
 accordance with the terms specified in this license.

License: BSD-3-clause
 Redistribution and use in source and binary forms, with or without
 modification, are permitted provided that the following conditions
 are met:
 1. Redistributions of source code must retain the above copyright
    notice, this list of conditions and the following disclaimer.
 2. Redistributions in binary form must reproduce the above copyright
    notice, this list of conditions and the following disclaimer in the
    documentation and/or other materials provided with the distribution.
 4. Neither the name of the University nor the names of its contributors
    may be used to endorse or promote products derived from this software
    without specific prior written permission.
 .
 THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 SUCH DAMAGE.

License: BSD-3-clause-generic
 Redistribution and use in source and binary forms, with or without
 modification, are permitted provided that the following conditions
 are met:
 .
 1. Redistributions of source code must retain the copyright
    notice, this list of conditions and the following disclaimer.
 2. Redistributions in binary form must reproduce the copyright
    notice, this list of conditions and the following disclaimer in the
    documentation and/or other materials provided with the distribution.
 3. The name of the author may not be used to endorse or promote products
    derived from this software without specific prior written permission.
 .
 THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

License: AFL-2.1
 The Academic Free License
 v. 2.1
 .
 This Academic Free License (the "License") applies to any original
 work of authorship (the "Original Work") whose owner (the "Licensor")
 has placed the following notice immediately following the copyright
 notice for the Original Work:
 .
 Licensed under the Academic Free License version 2.1
 .
 1) Grant of Copyright License. Licensor hereby grants You a
 world-wide, royalty-free, non-exclusive, perpetual, sublicenseable
 license to do the following:
 .
 a) to reproduce the Original Work in copies;
 .
 b) to prepare derivative works ("Derivative Works") based upon the
 Original Work;
 .
 c) to distribute copies of the Original Work and Derivative Works to
 the public;
 .
 d) to perform the Original Work publicly; and
 .
 e) to display the Original Work publicly.
 .
 2) Grant of Patent License. Licensor hereby grants You a world-wide,
 royalty-free, non-exclusive, perpetual, sublicenseable license, under
 patent claims owned or controlled by the Licensor that are embodied in
 the Original Work as furnished by the Licensor, to make, use, sell and
 offer for sale the Original Work and Derivative Works.
 .
 3) Grant of Source Code License. The term "Source Code" means the
 preferred form of the Original Work for making modifications to it and
 all available documentation describing how to modify the Original
 Work. Licensor hereby agrees to provide a machine-readable copy of the
 Source Code of the Original Work along with each copy of the Original
 Work that Licensor distributes. Licensor reserves the right to satisfy
 this obligation by placing a machine-readable copy of the Source Code
 in an information repository reasonably calculated to permit
 inexpensive and convenient access by You for as long as Licensor
 continues to distribute the Original Work, and by publishing the
 address of that information repository in a notice immediately
 following the copyright notice that applies to the Original Work.
 .
 4) Exclusions From License Grant. Neither the names of Licensor, nor
 the names of any contributors to the Original Work, nor any of their
 trademarks or service marks, may be used to endorse or promote
 products derived from this Original Work without express prior written
 permission of the Licensor. Nothing in this License shall be deemed to
 grant any rights to trademarks, copyrights, patents, trade secrets or
 any other intellectual property of Licensor except as expressly stated
 herein. No patent license is granted to make, use, sell or offer to
 sell embodiments of any patent claims other than the licensed claims
 defined in Section 2. No right is granted to the trademarks of
 Licensor even if such marks are included in the Original Work. Nothing
 in this License shall be interpreted to prohibit Licensor from
 licensing under different terms from this License any Original Work
 that Licensor otherwise would have a right to license.
 .
 5) This section intentionally omitted.
 .
 6) Attribution Rights. You must retain, in the Source Code of any
 Derivative Works that You create, all copyright, patent or trademark
 notices from the Source Code of the Original Work, as well as any
 notices of licensing and any descriptive text identified therein as an
 "Attribution Notice." You must cause the Source Code for any
 Derivative Works that You create to carry a prominent Attribution
 Notice reasonably calculated to inform recipients that You have
 modified the Original Work.
 .
 7) Warranty of Provenance and Disclaimer of Warranty. Licensor
 warrants that the copyright in and to the Original Work and the patent
 rights granted herein by Licensor are owned by the Licensor or are
 sublicensed to You under the terms of this License with the permission
 of the contributor(s) of those copyrights and patent rights. Except as
 expressly stated in the immediately proceeding sentence, the Original
 Work is provided under this License on an "AS IS" BASIS and WITHOUT
 WARRANTY, either express or implied, including, without limitation,
 the warranties of NON-INFRINGEMENT, MERCHANTABILITY or FITNESS FOR A
 PARTICULAR PURPOSE. THE ENTIRE RISK AS TO THE QUALITY OF THE ORIGINAL
 WORK IS WITH YOU. This DISCLAIMER OF WARRANTY constitutes an essential
 part of this License. No license to Original Work is granted hereunder
 except under this disclaimer.
 .
 8) Limitation of Liability. Under no circumstances and under no legal
 theory, whether in tort (including negligence), contract, or
 otherwise, shall the Licensor be liable to any person for any direct,
 indirect, special, incidental, or consequential damages of any
 character arising as a result of this License or the use of the
 Original Work including, without limitation, damages for loss of
 goodwill, work stoppage, computer failure or malfunction, or any and
 all other commercial damages or losses. This limitation of liability
 shall not apply to liability for death or personal injury resulting
 from Licensor's negligence to the extent applicable law prohibits such
 limitation. Some jurisdictions do not allow the exclusion or
 limitation of incidental or consequential damages, so this exclusion
 and limitation may not apply to You.
 .
 9) Acceptance and Termination. If You distribute copies of the
 Original Work or a Derivative Work, You must make a reasonable effort
 under the circumstances to obtain the express assent of recipients to
 the terms of this License. Nothing else but this License (or another
 written agreement between Licensor and You) grants You permission to
 create Derivative Works based upon the Original Work or to exercise
 any of the rights granted in Section 1 herein, and any attempt to do
 so except under the terms of this License (or another written
 agreement between Licensor and You) is expressly prohibited by
 U.S. copyright law, the equivalent laws of other countries, and by
 international treaty. Therefore, by exercising any of the rights
 granted to You in Section 1 herein, You indicate Your acceptance of
 this License and all of its terms and conditions.
 .
 10) Termination for Patent Action. This License shall terminate
 automatically and You may no longer exercise any of the rights granted
 to You by this License as of the date You commence an action,
 including a cross-claim or counterclaim, against Licensor or any
 licensee alleging that the Original Work infringes a patent. This
 termination provision shall not apply for an action alleging patent
 infringement by combinations of the Original Work with other software
 or hardware.
 .
 11) Jurisdiction, Venue and Governing Law. Any action or suit relating
 to this License may be brought only in the courts of a jurisdiction
 wherein the Licensor resides or in which Licensor conducts its primary
 business, and under the laws of that jurisdiction excluding its
 conflict-of-law provisions. The application of the United Nations
 Convention on Contracts for the International Sale of Goods is
 expressly excluded. Any use of the Original Work outside the scope of
 this License or after its termination shall be subject to the
 requirements and penalties of the U.S. Copyright Act, 17 U.S.C. Â§ 101
 et seq., the equivalent laws of other countries, and international
 treaty. This section shall survive the termination of this License.
 .
 12) Attorneys Fees. In any action to enforce the terms of this License
 or seeking damages relating thereto, the prevailing party shall be
 entitled to recover its costs and expenses, including, without
 limitation, reasonable attorneys' fees and costs incurred in
 connection with such action, including any appeal of such action. This
 section shall survive the termination of this License.
 .
 13) Miscellaneous. This License represents the complete agreement
 concerning the subject matter hereof. If any provision of this License
 is held to be unenforceable, such provision shall be reformed only to
 the extent necessary to make it enforceable.
 .
 14) Definition of "You" in This License. "You" throughout this
 License, whether in upper or lower case, means an individual or a
 legal entity exercising rights under, and complying with all of the
 terms of, this License. For legal entities, "You" includes any entity
 that controls, is controlled by, or is under common control with
 you. For purposes of this definition, "control" means (i) the power,
 direct or indirect, to cause the direction or management of such
 entity, whether by contract or otherwise, or (ii) ownership of fifty
 percent (50%) or more of the outstanding shares, or (iii) beneficial
 ownership of such entity.
 .
 15) Right to Use. You may use the Original Work in all ways not
 otherwise restricted or conditioned by this License or by law, and
 Licensor promises not to interfere with or be responsible for such
 uses by You.
 .
 This license is Copyright (C) 2003-2004 Lawrence E. Rosen. All rights
 reserved. Permission is hereby granted to copy and distribute this
 license without modification. This license may not be modified without
 the express written permission of its copyright owner.
```

## libsystemd0 249.11-0ubuntu3.22 — bundled: libsystemd.so.0

Copyright/license source (verbatim): `/usr/share/doc/libsystemd0/copyright` in the libsystemd0 package.

```text
Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
Upstream-Name: systemd
Upstream-Contact: systemd-devel@lists.freedesktop.org
Source: https://www.freedesktop.org/wiki/Software/systemd/

Files: *
Copyright: 2008-2015 Kay Sievers <kay@vrfy.org>
           2010-2015 Lennart Poettering
           2012-2015 Zbigniew Jędrzejewski-Szmek <zbyszek@in.waw.pl>
           2013-2015 Tom Gundersen <teg@jklm.no>
           2013-2015 Daniel Mack
           2010-2015 Harald Hoyer
           2013-2015 David Herrmann
           2013, 2014 Thomas H.P. Andersen
           2013, 2014 Daniel Buch
           2014 Susant Sahani
           2009-2015 Intel Corporation
           2000, 2005 Red Hat, Inc.
           2009 Alan Jenkins <alan-jenkins@tuffmail.co.uk>
           2010 ProFUSION embedded systems
           2010 Maarten Lankhorst
           1995-2004 Miquel van Smoorenburg
           1999 Tom Tromey
           2011 Michal Schmidt
           2012 B. Poettering
           2012 Holger Hans Peter Freyther
           2012 Dan Walsh
           2012 Roberto Sassu
           2013 David Strauss
           2013 Marius Vollmer
           2013 Jan Janssen
           2013 Simon Peeters
License: LGPL-2.1+

Files: src/basic/siphash24.h
       src/basic/siphash24.c
Copyright: 2012 Jean-Philippe Aumasson <jeanphilippe.aumasson@gmail.com>
           2012 Daniel J. Bernstein <djb@cr.yp.to>
License: CC0-1.0

Files: src/basic/ioprio.h
Copyright: Jens Axboe <axboe@suse.de>
License: GPL-2

Files: src/shared/linux/*
       src/basic/linux/*
Copyright: 2004-2009 Red Hat, Inc.
           2011-2014 PLUMgrid
           2001-2003 Sistina Software (UK) Limited.
           2008 Ian Kent <raven@themaw.net>
           1998 David S. Miller >davem@redhat.com>
           2001 Jeff Garzik <jgarzik@pobox.com>
           2006-2010 Johannes Berg <johannes@sipsolutions.net
           2008 Michael Wu <flamingice@sourmilk.net>
           2008 Luis Carlos Cobo <luisca@cozybit.com>
           2008 Michael Buesch <m@bues.ch>
           2008, 2009 Luis R. Rodriguez <lrodriguez@atheros.com>
           2008 Jouni Malinen <jouni.malinen@atheros.com>
           2008 Colin McCabe <colin@cozybit.com>
           2018-2019 Intel Corporation
           2007 Oracle.
           2009 Wolfgang Grandegger <wg@grandegger.com>
           1999 Thomas Davis <tadavis@lbl.gov>
           2015 Sabrina Dubroca <sd@queasysnail.net>
           1999-2000 Maxim Krasnyansky <max_mk@yahoo.com>
           2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>
License: GPL-2 with Linux-syscall-note exception

Files: src/basic/sparse-endian.h
Copyright: 2012 Josh Triplett <josh@joshtriplett.org>
License: Expat

Files: src/libsystemd/sd-journal/lookup3.c
       src/libsystemd/sd-journal/lookup3.h
Copyright: none
License: public-domain
 You can use this free for any purpose. It's in the public domain. It has no
 warranty.

Files: src/udev/ata_id/ata_id.c
       src/udev/cdrom_id/cdrom_id.c
       src/udev/mtd_probe/mtd_probe.c
       src/udev/mtd_probe/mtd_probe.h
       src/udev/mtd_probe/probe_smartmedia.c
       src/udev/scsi_id/scsi.h
       src/udev/scsi_id/scsi_id.c
       src/udev/scsi_id/scsi_id.h
       src/udev/scsi_id/scsi_serial.c
       src/udev/udevadm.c
       src/udev/udevadm-control.c
       src/udev/udevadm.h
       src/udev/udevadm-info.c
       src/udev/udevadm-monitor.c
       src/udev/udevadm-settle.c
       src/udev/udevadm-test-builtin.c
       src/udev/udevadm-test.c
       src/udev/udevadm-trigger.c
       src/udev/udevadm-util.c
       src/udev/udevadm-util.h
       src/udev/udev-builtin-blkid.c
       src/udev/udev-builtin.h
       src/udev/udev-builtin-input_id.c
       src/udev/udev-builtin-kmod.c
       src/udev/udev-builtin-path_id.c
       src/udev/udev-builtin-uaccess.c
       src/udev/udev-builtin-usb_id.c
       src/udev/udev-ctrl.h
       src/udev/udevd.c
       src/udev/udev-event.c
       src/udev/udev-event.h
       src/udev/udev-node.c
       src/udev/udev-node.h
       src/udev/udev-rules.c
       src/udev/udev-rules.h
       src/udev/udev-watch.c
       src/udev/udev-watch.h
       src/udev/v4l_id/v4l_id.c
Copyright: 2003-2012 Kay Sievers <kay@vrfy.org>
           2003-2004 Greg Kroah-Hartman <greg@kroah.com>
           2004 Chris Friesen <chris_friesen@sympatico.ca>
           2004, 2009, 2010 David Zeuthen <david@fubar.dk>
           2005, 2006 SUSE Linux Products GmbH
           2003 IBM Corp.
           2007 Hannes Reinecke <hare@suse.de>
           2009 Canonical Ltd.
           2009 Scott James Remnant <scott@netsplit.com>
           2009 Martin Pitt <martin.pitt@ubuntu.com>
           2009 Piter Punk <piterpunk@slackware.com>
           2009, 2010 Lennart Poettering
           2009 Filippo Argiolas <filippo.argiolas@gmail.com>
           2010 Maxim Levitsky
           2011 ProFUSION embedded systems
           2011 Karel Zak <kzak@redhat.com>
           2014 Zbigniew Jędrzejewski-Szmek <zbyszek@in.waw.pl>
           2014 David Herrmann <dh.herrmann@gmail.com>
           2014 Carlos Garnacho <carlosg@gnome.org>
License: GPL-2+

Files: debian/*
Copyright: 2010-2013 Tollef Fog Heen <tfheen@debian.org>
           2013-2018 Michael Biebl <biebl@debian.org>
           2013 Michael Stapelberg <stapelberg@debian.org>
License: LGPL-2.1+

License: Expat
 Permission is hereby granted, free of charge, to any person obtaining a copy
 of this software and associated documentation files (the "Software"), to
 deal in the Software without restriction, including without limitation the
 rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 sell copies of the Software, and to permit persons to whom the Software is
 furnished to do so, subject to the following conditions:
 .
 The above copyright notice and this permission notice shall be included in
 all copies or substantial portions of the Software.
 .
 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 IN THE SOFTWARE.

License: GPL-2
 This program is free software; you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation; version 2 of the License.
 .
 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.
 .
 You should have received a copy of the GNU General Public License
 along with this program; if not, write to the Free Software Foundation, Inc.,
 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA.
 .
 On Debian and systems the full text of the GNU General Public
 License version 2 can be found in the file
 `/usr/share/common-licenses/GPL-2`

License: GPL-2 with Linux-syscall-note exception
 NOTE! This copyright does *not* cover user programs that use kernel services
 by normal system calls - this is merely considered normal use of the kernel,
 and does *not* fall under the heading of "derived work". Also note that the
 GPL below is copyrighted by the Free Software Foundation, but the instance of
 code that it refers to (the Linux kernel) is copyrighted by me and others who
 actually wrote it.
 .
 Also note that the only valid version of the GPL as far as the kernel is
 concerned is _this_ particular version of the license (ie v2, not v2.2 or v3.x
 or whatever), unless explicitly otherwise stated.
 .
 Linus Torvalds
 .
 This program is free software; you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation; version 2 of the License.
 .
 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.
 .
 You should have received a copy of the GNU General Public License
 along with this program; if not, write to the Free Software Foundation, Inc.,
 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA.
 .
 On Debian and systems the full text of the GNU General Public
 License version 2 can be found in the file
 `/usr/share/common-licenses/GPL-2`

License: GPL-2+
 This program is free software; you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation; either version 2, or (at your option)
 any later version.
 .
 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.
 .
 You should have received a copy of the GNU General Public License along
 with this program; if not, write to the Free Software Foundation,
 Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 .
 On Debian systems, the complete text of the GNU General Public License
 version 2 can be found in ‘/usr/share/common-licenses/GPL-2’.

License: LGPL-2.1+
 This program is free software; you can redistribute it and/or modify
 it under the terms of the GNU Lesser General Public License as published by
 the Free Software Foundation; either version 2.1, or (at your option)
 any later version.
 .
 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU Lesser General Public License for more details.
 .
 You should have received a copy of the GNU Lesser General Public License along
 with this program; if not, write to the Free Software Foundation,
 Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 .
 On Debian systems, the complete text of the GNU Lesser General Public
 License version 2.1 can be found in ‘/usr/share/common-licenses/LGPL-2.1’.

License: CC0-1.0
 To the extent possible under law, the author(s) have dedicated all copyright
 and related and neighboring rights to this software to the public domain
 worldwide. This software is distributed without any warranty.
 .
 You should have received a copy of the CC0 Public Domain Dedication along with
 this software. If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
 .
 On Debian systems, the complete text of the CC0 1.0 Universal license can be
 found in ‘/usr/share/common-licenses/CC0-1.0’.
```

## liblzma5 5.2.5-2ubuntu1.1 — bundled: liblzma.so.5

Copyright/license source (verbatim): `/usr/share/doc/liblzma5/copyright` in the liblzma5 package.

```text
Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
Upstream-Name: XZ Utils
Upstream-Contact:
 Lasse Collin <lasse.collin@tukaani.org>
 https://tukaani.org/xz/lists.html
Source:
 https://tukaani.org/xz
 https://git.tukaani.org/xz.git
Comment:
 XZ Utils is developed and maintained upstream by Lasse Collin.  Major
 portions are based on code by other authors; see AUTHORS for details.
 Most of the source has been put into the public domain, but some files
 have not (details below).
 .
 This file describes the source package.  The binary packages contain
 some files derived from other works: for example, images in the API
 documentation come from Doxygen.
License:
 Different licenses apply to different files in this package. Here
 is a rough summary of which licenses apply to which parts of this
 package (but check the individual files to be sure!):
 .
   - liblzma is in the public domain.
 .
   - xz, xzdec, and lzmadec command line tools are in the public
     domain unless GNU getopt_long had to be compiled and linked
     in from the lib directory. The getopt_long code is under
     GNU LGPLv2.1+.
 .
   - The scripts to grep, diff, and view compressed files have been
     adapted from gzip. These scripts and their documentation are
     under GNU GPLv2+.
 .
   - All the documentation in the doc directory and most of the
     XZ Utils specific documentation files in other directories
     are in the public domain.
 .
   - Translated messages are in the public domain.
 .
   - The build system contains public domain files, and files that
     are under GNU GPLv2+ or GNU GPLv3+. None of these files end up
     in the binaries being built.
 .
   - Test files and test code in the tests directory, and debugging
     utilities in the debug directory are in the public domain.
 .
   - The extra directory may contain public domain files, and files
     that are under various free software licenses.
 .
 You can do whatever you want with the files that have been put into
 the public domain. If you find public domain legally problematic,
 take the previous sentence as a license grant. If you still find
 the lack of copyright legally problematic, you have too many
 lawyers.
 .
 As usual, this software is provided "as is", without any warranty.
 .
 If you copy significant amounts of public domain code from XZ Utils
 into your project, acknowledging this somewhere in your software is
 polite (especially if it is proprietary, non-free software), but
 naturally it is not legally required. Here is an example of a good
 notice to put into "about box" or into documentation:
 .
     This software includes code from XZ Utils <http://tukaani.org/xz/>.
 .
 The following license texts are included in the following files:
   - COPYING.LGPLv2.1: GNU Lesser General Public License version 2.1
   - COPYING.GPLv2: GNU General Public License version 2
   - COPYING.GPLv3: GNU General Public License version 3
 .
 Note that the toolchain (compiler, linker etc.) may add some code
 pieces that are copyrighted. Thus, it is possible that e.g. liblzma
 binary wouldn't actually be in the public domain in its entirety
 even though it contains no copyrighted code from the XZ Utils source
 package.
 .
 If you have questions, don't hesitate to ask the author(s) for more
 information.

Files: *
Copyright: 2006-2018, Lasse Collin
           1999-2008, Igor Pavlov
           2006, Ville Koskinen
           1998, Steve Reid
           2000, Wei Dai
           2003, Kevin Springle
           2009, Jonathan Nieder
           2010, Anders F Björklund
License: PD
 This file has been put in the public domain.
 You can do whatever you want with this file.
Comment:
  From: Lasse Collin <lasse.collin@tukaani.org>
  To: Jonathan Nieder <jrnieder@gmail.com>
  Subject: Re: XZ utils for Debian
  Date: Sun, 19 Jul 2009 13:28:23 +0300
  Message-Id: <200907191328.23816.lasse.collin@tukaani.org>
 .
 [...]
 .
  > AUTHORS, ChangeLog, COPYING, README, THANKS, TODO,
  > dos/README, windows/README
 .
  COPYING says that most docs are in the public domain. Maybe that's not
  clear enough, but on the other hand it looks a bit stupid to put
  copyright information in tiny and relatively small docs like README.
 .
  I don't dare to say that _all_ XZ Utils specific docs are in the public
  domain unless otherwise mentioned in the file. I'm including PDF files
  generated by groff + ps2pdf, and some day I might include Doxygen-
  generated HTML docs too. Those don't include any copyright notices, but
  it seems likely that groff + ps2pdf or at least Doxygen put some
  copyrighted content into the generated files.

Files: INSTALL NEWS PACKAGERS
 windows/README-Windows.txt
 windows/INSTALL-MinGW.txt
Copyright: 2009-2010, Lasse Collin
License: probably-PD
 See the note on AUTHORS, README, and so on above.

Files: src/scripts/* lib/* extra/scanlzma/scanlzma.c
Copyright: © 1993, Jean-loup Gailly
           © 1989-1994, 1996-1999, 2001-2007, Free Software Foundation, Inc.
           © 2006 Timo Lindfors
           2005, Charles Levert
           2005, 2009, Lasse Collin
           2009, Andrew Dudman
Other-Authors: Paul Eggert, Ulrich Drepper
License: GPL-2+

Files: src/scripts/Makefile.am src/scripts/xzless.1
Copyright: 2009, Andrew Dudman
           2009, Lasse Collin
License: PD
 This file has been put in the public domain.
 You can do whatever you want with this file.

Files: doc/examples/xz_pipe_comp.c doc/examples/xz_pipe_decomp.c
Copyright: 2010, Daniel Mealha Cabrita
License: PD
 Not copyrighted -- provided to the public domain.

Files: lib/getopt.c lib/getopt1.c lib/getopt.in.h
Copyright: © 1987-2007 Free Software Foundation, Inc.
Other-Authors: Ulrich Drepper
License: LGPL-2.1+

Files: m4/getopt.m4 m4/posix-shell.m4
Copyright: © 2002-2006, 2008 Free Software Foundation, Inc.
           © 2007-2008 Free Software Foundation, Inc.
Other-Authors: Bruno Haible, Paul Eggert
License: permissive-fsf

Files: m4/acx_pthread.m4
Copyright: © 2008, Steven G. Johnson <stevenj@alum.mit.edu>
License: Autoconf

files: m4/ax_check_capsicum.m4
Copyright: © 2014, Google Inc.
           © 2015, Lasse Collin <lasse.collin@tukaani.org>
License: permissive-nowarranty

Files: Doxyfile.in
Copyright: © 1997-2007 by Dimitri van Heesch
Origin: Doxygen 1.4.7
License: GPL-2

Files: src/liblzma/check/crc32_table_?e.h
 src/liblzma/check/crc64_table_?e.h
 src/liblzma/lzma/fastpos_table.c
 src/liblzma/rangecoder/price_table.c
Copyright: none, automatically generated data
Generated-With:
 src/liblzma/check/crc32_tablegen.c
 src/liblzma/check/crc64_tablegen.c
 src/liblzma/lzma/fastpos_tablegen.c
 src/liblzma/rangecoder/price_tablegen.c
License: none
 No copyright to license.

Files: .gitignore m4/.gitignore po/.gitignore po/LINGUAS po/POTFILES.in
Copyright: none; these are just short lists.
License: none
 No copyright to license.

Files: tests/compress_prepared_bcj_*
Copyright: 2008-2009, Lasse Collin
Source-Code: tests/bcj_test.c
License: PD
 This file has been put into the public domain.
 You can do whatever you want with this file.
Comment:
 changelog.gz (commit 975d8fd) explains:
 .
 Recreated the BCJ test files for x86 and SPARC. The old files
 were linked with crt*.o, which are copyrighted, and thus the
 old test files were not in the public domain as a whole. They
 are freely distributable though, but it is better to be careful
 and avoid including any copyrighted pieces in the test files.
 The new files are just compiled and assembled object files,
 and thus don't contain any copyrighted code.

Files: po/cs.po po/de.po po/fr.po
Copyright: 2010, Marek Černocký
           2010, Andre Noll
           2011, Adrien Nader
License: PD
 This file is put in the public domain.

Files: po/it.po po/pl.po
Copyright: 2009, 2010, Gruppo traduzione italiano di Ubuntu-it
           2010, Lorenzo De Liso
           2009, 2010, 2011, Milo Casagrande
           2011, Jakub Bogusz
License: PD
 This file is in the public domain

Files: INSTALL.generic
Copyright: © 1994, 1995, 1996, 1999, 2000, 2001, 2002, 2004, 2005,
             2006, 2007, 2008, 2009, 2010 Free Software Foundation, Inc.
License: permissive-nowarranty

Files: dos/config.h
Copyright: © 1992, 1993, 1994, 1999, 2000, 2001, 2002, 2005
             Free Software Foundation, Inc.
           2007-2010, Lasse Collin
Other-Authors: Roland McGrath, Akim Demaille, Paul Eggert,
               David Mackenzie, Bruno Haible, and many others.
Origin: configure.ac from XZ Utils,
        visibility.m4 serial 1 (gettext-0.15),
        Autoconf 2.52g
License: config-h
 configure.ac:
 .
  # Author: Lasse Collin
  #
  # This file has been put into the public domain.
  # You can do whatever you want with this file.
 .
 visibility.m4:
 .
  dnl Copyright (C) 2005 Free Software Foundation, Inc.
  dnl This file is free software; the Free Software Foundation
  dnl gives unlimited permission to copy and/or distribute it,
  dnl with or without modifications, as long as this notice is preserved.
 .
 dnl From Bruno Haible.
 .
 comments from Autoconf 2.52g:
 .
  # Copyright 1992, 1993, 1994, 1999, 2000, 2001, 2002
  # Free Software Foundation, Inc.
 .
 [...]
 .
  # As a special exception, the Free Software Foundation gives unlimited
  # permission to copy, distribute and modify the configure scripts that
  # are the output of Autoconf.  You need not follow the terms of the GNU
  # General Public License when using or distributing such scripts, even
  # though portions of the text of Autoconf appear in them.  The GNU
  # General Public License (GPL) does govern all other use of the material
  # that constitutes the Autoconf program.
 .
 On Debian systems, the complete text of the GNU General Public
 License version 2 can be found in ‘/usr/share/common-licenses/GPL-2’.
 dos/config.h was generated with autoheader, which tells Autoconf to
 output a script to generate a config.h file and then runs it.

Files: po/Makevars
Origin: gettext-runtime/po/Makevars (gettext-0.12)
Copyright: © 2003 Free Software Foundation, Inc.
Authors: Bruno Haible
License: LGPL-2.1+
 The gettext-runtime package is under the LGPL, see files intl/COPYING.LIB-2.0
 and intl/COPYING.LIB-2.1.
 .
 On Debian systems, the complete text of intl/COPYING.LIB-2.0 from
 gettext-runtime 0.12 can be found in ‘/usr/share/common-licenses/LGPL-2’
 and the text of intl/COPYING.LIB-2.1 can be found in
 ‘/usr/share/common-licenses/LGPL-2.1’.
 .
 po/Makevars consists mostly of helpful comments and does not contain a
 copyright and license notice.

Files: COPYING.GPLv2 COPYING.GPLv3 COPYING.LGPLv2.1
Copyright: © 1989, 1991, 1999, 2007 Free Software Foundation, Inc.
License: noderivs
 Everyone is permitted to copy and distribute verbatim copies
 of this license document, but changing it is not allowed.

Files: debian/*
Copyright: 2009-2012, Jonathan Nieder
License: PD-debian
 The Debian packaging files are in the public domain.
 You may freely use, modify, distribute, and relicense them.

License: LGPL-2.1+
 This program is free software; you can redistribute it and/or modify
 it under the terms of the GNU Lesser General Public License as published by
 the Free Software Foundation; either version 2.1, or (at your option)
 any later version.
 .
 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU Lesser General Public License for more details.
 .
 You should have received a copy of the GNU Lesser General Public License along
 with this program; if not, write to the Free Software Foundation,
 Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 .
 On Debian systems, the complete text of the GNU Lesser General Public
 License version 2.1 can be found in ‘/usr/share/common-licenses/LGPL-2.1’.

License: GPL-2
 Permission to use, copy, modify, and distribute this software and its
 documentation under the terms of the GNU General Public License is
 hereby granted. No representations are made about the suitability of
 this software for any purpose. It is provided "as is" without express
 or implied warranty. See the GNU General Public License for more
 details.
 .
 Documents produced by doxygen are derivative works derived from the
 input used in their production; they are not affected by this license.
 .
 On Debian systems, the complete text of the version of the GNU General
 Public License distributed with Doxygen can be found in
 ‘/usr/share/common-licenses/GPL-2’.

License: GPL-2+
 This program is free software; you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation; either version 2, or (at your option)
 any later version.
 .
 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.
 .
 You should have received a copy of the GNU General Public License along
 with this program; if not, write to the Free Software Foundation,
 Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 .
 On Debian systems, the complete text of the GNU General Public License
 version 2 can be found in ‘/usr/share/common-licenses/GPL-2’.

License: Autoconf
 This program is free software: you can redistribute it and/or modify it
 under the terms of the GNU General Public License as published by the
 Free Software Foundation, either version 3 of the License, or (at your
 option) any later version.
 .
 This program is distributed in the hope that it will be useful, but
 WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General
 Public License for more details.
 .
 You should have received a copy of the GNU General Public License along
 with this program. If not, see <http://www.gnu.org/licenses/>.
 .
 As a special exception, the respective Autoconf Macro's copyright owner
 gives unlimited permission to copy, distribute and modify the configure
 scripts that are the output of Autoconf when processing the Macro. You
 need not follow the terms of the GNU General Public License when using
 or distributing such scripts, even though portions of the text of the
 Macro appear in them. The GNU General Public License (GPL) does govern
 all other use of the material that constitutes the Autoconf Macro.
 .
 This special exception to the GPL applies to versions of the Autoconf
 Macro released by the Autoconf Archive. When you make and distribute a
 modified version of the Autoconf Macro, you may extend this special
 exception to the GPL to apply to your modified version as well.
 .
 On Debian systems, the complete text of the GNU General Public
 License version 3 can be found in ‘/usr/share/common-licenses/GPL-3’.

License: permissive-fsf
 This file is free software; the Free Software Foundation
 gives unlimited permission to copy and/or distribute it,
 with or without modifications, as long as this notice is preserved.

License: permissive-nowarranty
 Copying and distribution of this file, with or without modification,
 are permitted in any medium without royalty provided the copyright
 notice and this notice are preserved.  This file is offered as-is,
 without warranty of any kind.
```

## libzstd1 1.4.8+dfsg-3build1 — bundled: libzstd.so.1

Copyright/license source (verbatim): `/usr/share/doc/libzstd1/copyright` in the libzstd1 package.

```text
Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
Upstream-Name: Zstd
Source: https://github.com/facebook/zstd
Files-Excluded: appveyor.yml
                build/*
                programs/windres/*
                .travis.yml
                .buckversion
                .buckconfig
                .circleci/*
                .cirrus.yml

Files: *
Copyright: 2013-2018, Yann Collet
	       2016, Przemyslaw Skibinski
	       2016-2018, Facebook, Inc.
License: BSD-3-clause and GPL-2
Comment: Starting from 1.3.1 zstd's patent claim is removed
 see: https://github.com/facebook/zstd/pull/801

Files: zlibWrapper/examples/*.c
Copyright: 1995-2006, 2011 Jean-loup Gailly
License: zlib

Files: zlibWrapper/gz*.c
Copyright: (C) 2004, 2005, 2010, 2011, 2012, 2013 Mark Adler
License: zlib

License: zlib
 This software is provided 'as-is', without any express or implied
 warranty. In no event will the authors be held liable for any damages
 arising from the use of this software.
 .
 Permission is granted to anyone to use this software for any purpose,
 including commercial applications, and to alter it and redistribute it
 freely, subject to the following restrictions:
 .
 1. The origin of this software must not be misrepresented; you must not
    claim that you wrote the original software. If you use this software
    in a product, an acknowledgement in the product documentation would be
    appreciated but is not required.
 2. Altered source versions must be plainly marked as such, and must not be
    misrepresented as being the original software.
 3. This notice may not be removed or altered from any source distribution.

Files: lib/dictBuilder/divsufsort.*
Copyright: 2003-2008, Yuta Mori
License: Expat

Files: examples/*
Copyright: 2016-present, Yann Collet, Facebook, Inc.
License: BSD-3-clause and GPL-2

Files: debian/*
Copyright: 2015-2016 Kevin Murray <spam@kdmurray.id.au>
License: Expat

License: Expat
 Permission is hereby granted, free of charge, to any person obtaining
 a copy of this software and associated documentation files (the
 "Software"), to deal in the Software without restriction, including
 without limitation the rights to use, copy, modify, merge, publish,
 distribute, sublicense, and/or sell copies of the Software, and to
 permit persons to whom the Software is furnished to do so, subject to
 the following conditions:
 .
 The above copyright notice and this permission notice shall be
 included in all copies or substantial portions of the Software.
 .
 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 SOFTWARE.

License: GPL-2
 This program is free software; you can redistribute it and/or modify
 it under the terms of the GNU General Public License, v2, as
 published by the Free Software Foundation
 .
 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.
 .
 You should have received a copy of the GNU General Public License along
 with this program; if not, write to the Free Software Foundation, Inc.,
 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 .
 On Debian systems, the complete text of the GNU General Public
 License version 2 can be found in `/usr/share/common-licenses/GPL-2'.

License: BSD-3-clause
 Redistribution and use in source and binary forms, with or without
 modification, are permitted provided that the following conditions are met:
     * Redistributions of source code must retain the above copyright
       notice, this list of conditions and the following disclaimer.
     * Redistributions in binary form must reproduce the above copyright
       notice, this list of conditions and the following disclaimer in the
       documentation and/or other materials provided with the distribution.
     * Neither the name of cereal nor the
       names of its contributors may be used to endorse or promote products
       derived from this software without specific prior written permission.
 .
 THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 DISCLAIMED. IN NO EVENT SHALL RANDOLPH VOORHIES OR SHANE GRANT BE LIABLE FOR ANY
 DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```

## liblz4-1 1.9.3-2build2 — bundled: liblz4.so.1

Copyright/license source (verbatim): `/usr/share/doc/liblz4-1/copyright` in the liblz4-1 package.

```text
Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
Upstream-Name: lz4
Source: https://github.com/Cyan4973/lz4

Files: *
Copyright: Copyright (C) 2011-2017, Yann Collet.
License: BSD-2-clause

Files: lib/*
Copyright: Copyright (C) 2011-2017, Yann Collet.
License: BSD-2-clause

Files: lib/liblz4.pc.in
Copyright: Copyright (C) 2011-2014, Yann Collet.
License: BSD-2-clause

Files: lib/lz4frame.c
       lib/lz4frame_static.h
       lib/xxhash.c
       lib/xxhash.h
Copyright: Copyright (C) 2011-2016, Yann Collet.
License: BSD-2-clause

Files: programs/*
Copyright: Copyright (C) 2011-2016, Yann Collet.
License: GPL-2+

Files: programs/lz4io.c
Copyright: Copyright (C) 2011-2017, Yann Collet.
License: GPL-2+

Files: programs/platform.h
Copyright: Copyright (C) 2016 -present, Przemyslaw Skibinski, Yann Collet
License: GPL-2+

Files: programs/util.h
Copyright: Copyright (C) 2016 -present, Przemyslaw Skibinski, Yann Collet
License: GPL-2+

Files: ./examples/printVersion.c
Copyright: Takayuki Matsuoka & Yann Collet
License: GPL-2

Files: ./examples/blockStreaming_lineByLine.c
       ./examples/blockStreaming_doubleBuffer.c
Copyright: Takayuki Matsuoka
License: GPL-2

Files: ./examples/HCStreaming_ringBuffer.c
       ./examples/blockStreaming_ringBuffer.c
Copyright: Yann Collet
License: GPL-2

Files: ./examples/compress_functions.c
       ./examples/simple_buffer.c
Copyright: Kyle Harper
License: BSD-2-clause


Files: debian/*
Copyright: 2013 Nobuhiro Iwamatsu <iwamatsu@debian.org>
License: GPL-2+

License: GPL-2
 This program is free software; you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation; version 2 dated June, 1991.
 .
 On Debian systems, the complete text of version 2 of the GNU General
 Public License can be found in '/usr/share/common-licenses/GPL-2'.

License: GPL-2+
 This program is free software; you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation; version 2 dated June, 1991, or (at
 your option) any later version.
 .
 On Debian systems, the complete text of version 2 of the GNU General
 Public License can be found in '/usr/share/common-licenses/GPL-2'.

License: BSD-2-clause
 Redistribution and use in source and binary forms, with or without
 modification, are permitted provided that the following conditions are 
 met:
 .
 * Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.
 .
 THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" 
 AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, 
 THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS
 BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT 
 OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```

## libgcrypt20 1.9.4-3ubuntu3.3 — bundled: libgcrypt.so.20

Copyright/license source (verbatim): `/usr/share/doc/libgcrypt20/copyright` in the libgcrypt20 package.

```text
This package was debianized by Ivo Timmermans <ivo@debian.org> on
Fri,  3 Aug 2001 10:02:38 +0200.
It was taken over by Matthias Urlichs <smurf@debian.org>, and is now
maintained by Andreas Metzler <ametzler@debian.org> Eric Dorland
<eric@debian.org>, James Westby <jw+debian@jameswestby.net>


It was downloaded from https://ftp.gnupg.org/gcrypt/libgcrypt/.

Up to end of 2012 libgcrypt copyright was owned solely by FSF, since then
contributions without copyright assignment to the FSF have been integrated.

Upstream Authors (from AUTHORS)
8X---------------------------------------------------
List of Copyright holders
=========================

  Copyright (C) 1989,1991-2018 Free Software Foundation, Inc.
  Copyright (C) 1994 X Consortium
  Copyright (C) 1996 L. Peter Deutsch
  Copyright (C) 1997 Werner Koch
  Copyright (C) 1998 The Internet Society
  Copyright (C) 1996-1999 Peter Gutmann, Paul Kendall, and Chris Wedgwood
  Copyright (C) 1996-2006 Peter Gutmann, Matt Thomlinson and Blake Coverett
  Copyright (C) 2003 Nikos Mavroyanopoulos
  Copyright (c) 2006 CRYPTOGAMS
  Copyright (C) 2006-2007 NTT (Nippon Telegraph and Telephone Corporation)
  Copyright (C) 2012-2021 g10 Code GmbH
  Copyright (C) 2012 Simon Josefsson, Niels Möller
  Copyright (c) 2012 Intel Corporation
  Copyright (C) 2013 Christian Grothoff
  Copyright (C) 2013-2021 Jussi Kivilinna
  Copyright (C) 2013-2014 Dmitry Eremin-Solenikov
  Copyright (C) 2014 Stephan Mueller
  Copyright (C) 2017 Jia Zhang
  Copyright (C) 2018 Bundesamt für Sicherheit in der Informationstechnik
  Copyright (C) 2020 Alibaba Group.
  Copyright (C) 2020 Tianjia Zhang



Library: Libgcrypt
Homepage: https://www.gnupg.org/related_software/libgcrypt/
Download: https://ftp.gnupg.org/ftp/gcrypt/libgcrypt/
          ftp://ftp.gnupg.org/gcrypt/libgcrypt/
Repository: git://git.gnupg.org/libgcrypt.git
Maintainer: Werner Koch <wk@gnupg.org>
Bug reports: https://bugs.gnupg.org
Security related bug reports: <security@gnupg.org>
End-of-life: TBD
License (library): LGPLv2.1+
License (manual and tools): GPLv2+


Libgcrypt is free software.  See the files COPYING.LIB and COPYING for
copying conditions, and LICENSES for notices about a few contributions
that require these additional notices to be distributed.  License
copyright years may be listed using range notation, e.g., 2000-2013,
indicating that every year in the range, inclusive, is a copyrightable
year that would otherwise be listed individually.

Authors with a FSF copyright assignment
=======================================

LIBGCRYPT       Werner Koch    2001-06-07
Assigns past and future changes.
Assignment for future changes terminated on 2012-12-04.
wk@gnupg.org
Designed and implemented Libgcrypt.

GNUPG	Matthew Skala		   1998-08-10
Disclaims changes.
mskala@ansuz.sooke.bc.ca
Wrote cipher/twofish.c.

GNUPG	Natural Resources Canada    1998-08-11
Disclaims changes by Matthew Skala.

GNUPG	Michael Roth	Germany     1998-09-17
Assigns changes.
mroth@nessie.de
Wrote cipher/des.c.
Changes and bug fixes all over the place.

GNUPG	Niklas Hernaeus 	1998-09-18
Disclaims changes.
nh@df.lth.se
Weak key patches.

GNUPG	Rémi Guyomarch		1999-05-25
Assigns past and future changes. (g10/compress.c, g10/encr-data.c,
g10/free-packet.c, g10/mdfilter.c, g10/plaintext.c, util/iobuf.c)
rguyom@mail.dotcom.fr

ANY     g10 Code GmbH           2001-06-07
Assignment for future changes terminated on 2012-12-04.
Code marked with ChangeLog entries of g10 Code employees.

LIBGCRYPT Timo Schulz           2001-08-31
Assigns past and future changes.
twoaday@freakmail.de

LIBGCRYPT Simon Josefsson       2002-10-25
Assigns past and future changes to FSF (cipher/{md4,crc}.c, CTR mode,
CTS/MAC flags, self test improvements)
simon@josefsson.org

LIBGCRYPT Moritz Schulte	2003-04-17
Assigns past and future changes.
moritz@g10code.com

GNUTLS  Nikolaos Mavrogiannopoulos  2003-11-22
nmav@gnutls.org
Original code for cipher/rfc2268.c.

LIBGCRYPT	The Written Word	2005-04-15
Assigns past and future changes. (new: src/libgcrypt.pc.in,
src/Makefile.am, src/secmem.c, mpi/hppa1.1/mpih-mul3.S,
mpi/hppa1.1/udiv-qrnnd.S, mpi/hppa1.1/mpih-mul2.S,
mpi/hppa1.1/mpih-mul1.S, mpi/Makefile.am, tests/prime.c,
tests/register.c, tests/ac.c, tests/basic.c, tests/tsexp.c,
tests/keygen.c, tests/pubkey.c, configure.ac, acinclude.m4)

LIBGCRYPT       Brad Hards       2006-02-09
Assigns Past and Future Changes
bradh@frogmouth.net
(Added OFB mode. Changed cipher/cipher.c, test/basic.c doc/gcrypt.tex.
 added SHA-224, changed cipher/sha256.c, added HMAC tests.)

LIBGCRYPT       Hye-Shik Chang   2006-09-07
Assigns Past and Future Changes
perky@freebsd.org
(SEED cipher)

LIBGCRYPT       Werner Dittmann  2009-05-20
Assigns Past and Future Changes
werner.dittmann@t-online.de
(mpi/amd64, tests/mpitests.c)

GNUPG           David Shaw
Assigns past and future changes.
dshaw@jabberwocky.com
(cipher/camellia-glue.c and related stuff)

LIBGCRYPT       Andrey Jivsov    2010-12-09
Assigns Past and Future Changes
openpgp@brainhub.org
(cipher/ecc.c and related files)

LIBGCRYPT       Ulrich Müller    2012-02-15
Assigns Past and Future Changes
ulm@gentoo.org
(Changes to cipher/idea.c and related files)

LIBGCRYPT       Vladimir Serbinenko  2012-04-26
Assigns Past and Future Changes
phcoder@gmail.com
(cipher/serpent.c)


Authors with a DCO
==================

Andrei Scherer <andsch@inbox.com>
2014-08-22:BF7CEF794F9.000003F0andsch@inbox.com:

Christian Aistleitner <christian@quelltextlich.at>
2013-02-26:20130226110144.GA12678@quelltextlich.at:

Christian Grothoff <christian@grothoff.org>
2013-03-21:514B5D8A.6040705@grothoff.org:

Dmitry Baryshkov <dbaryshkov@gmail.com>
Dmitry Eremin-Solenikov <dbaryshkov@gmail.com>
2013-07-13:20130713144407.GA27334@fangorn.rup.mentorg.com:

Dmitry Kasatkin <dmitry.kasatkin@intel.com>
2012-12-14:50CAE2DB.80302@intel.com:

H.J. Lu <hjl.tools@gmail.com>
2020-01-19:20200119135241.GA4970@gmail.com:

Jia Zhang <qianyue.zj@alibaba-inc.com>
2017-10-17:59E56E30.9060503@alibaba-inc.com:

Jérémie Courrèges-Anglas <jca@wxcvbn.org>
2016-05-26:87bn3ssqg0.fsf@ritchie.wxcvbn.org:

Jussi Kivilinna <jussi.kivilinna@mbnet.fi>
2012-11-15:20121115172331.150537dzb5i6jmy8@www.dalek.fi:

Jussi Kivilinna <jussi.kivilinna@iki.fi>
2013-05-06:5186720A.4090101@iki.fi:

Markus Teich <markus dot teich at stusta dot mhn dot de>
2014-10-08:20141008180509.GA2770@trolle:

Martin Storsjö <martin@martin.st>
2018-03-28:dc1605ce-a47d-34c5-8851-d9569f9ea5d3@martin.st:

Mathias L. Baumann <mathias.baumann at sociomantic.com>
2017-01-30:07c06d79-0828-b564-d604-fd16c7c86ebe@sociomantic.com:

Milan Broz <gmazyland@gmail.com>
2014-01-13:52D44CC6.4050707@gmail.com:

Paul Wolneykien <manowar@altlinux.org>
2019-11-19:20191119204459.312927aa@rigel.localdomain:

Peter Wu <peter@lekensteyn.nl>
2015-07-22:20150722191325.GA8113@al:

Rafaël Carré <funman@videolan.org>
2012-04-20:4F91988B.1080502@videolan.org:

Sergey V. <sftp.mtuci@gmail.com>
2013-11-07:2066221.5IYa7Yq760@darkstar:

Shawn Landden <shawn@git.icu>
2019-07-09:2794651562684255@iva4-64850291ca1c.qloud-c.yandex.net:

Stephan Mueller <smueller@chronox.de>
2014-08-22:2008899.25OeoelVVA@myon.chronox.de:

Tianjia Zhang <tianjia.zhang@linux.alibaba.com>
2020-01-08:dcda0127-2f45-93a3-0736-27259a33bffa@linux.alibaba.com:

Tomáš Mráz <tm@t8m.info>
2012-04-16:1334571250.5056.52.camel@vespa.frost.loc:

Vitezslav Cizek <vcizek@suse.com>
2015-11-05:20151105131424.GA32700@kolac.suse.cz:

Werner Koch <wk@gnupg.org> (g10 Code GmbH)
2012-12-05:87obi8u4h2.fsf@vigenere.g10code.de:


More credits
============

Libgcrypt used to be part of GnuPG but has been taken out into its own
package on 2000-12-21.

Most of the stuff in mpi has been taken from an old GMP library
version by Torbjorn Granlund <tege@noisy.tmg.se>.

The files cipher/rndunix.c and cipher/rndw32.c are based on those
files from Cryptlib.  Copyright Peter Gutmann, Paul Kendall, and Chris
Wedgwood 1996-1999.

The ECC code cipher/ecc.c was based on code by Sergi Blanch i Torne,
sergi at calcurco dot org.

The implementation of the Camellia cipher has been been taken from the
original NTT provided GPL source.

The CAVS testing program tests/cavs_driver.pl is not to be considered
a part of libgcrypt proper.  We distribute it merely for convenience.
It has a permissive license and is copyrighted by atsec information
security corporation.  See the file for details.

The file salsa20.c is based on D.J. Bernstein's public domain code and
taken from Nettle.  Copyright 2012 Simon Josefsson and Niels Möller.


 This file is free software; as a special exception the author gives
 unlimited permission to copy and/or distribute it, with or without
 modifications, as long as this notice is preserved.

 This file is distributed in the hope that it will be useful, but
 WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
 implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
8X---------------------------------------------------

License:

Most of the package is licensed under the GNU Lesser General Public
License (LGPL) version 2.1 (or later), except for helper and debugging
binaries. See below for details. The documentation is licensed under
the GPLv2 (or later), see below.

Excerpt from upstream's README:

    The library is distributed under the terms of the GNU Lesser
    General Public License (LGPL); see the file COPYING.LIB for the
    actual terms.

    The helper programs as well as the documentation are distributed
    under the terms of the GNU General Public License (GPL); see the
    file COPYING for the actual terms.

    The file LICENSES has notices about contributions that require
    that these additional notices are distributed.

An example of the license headers of the LGPL is

-------------
   Copyright (C) 1998, 1999, 2000, 2001, 2002, 2003, 2004, 2006
                 2007, 2008, 2009, 2010, 2011  Free Software Foundation, Inc.

   This file is part of Libgcrypt.

   Libgcrypt is free software; you can redistribute it and/or modify
   it under the terms of the GNU Lesser General Public License as
   published by the Free Software Foundation; either version 2.1 of
   the License, or (at your option) any later version.

   Libgcrypt is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this program; if not, see <http://www.gnu.org/licenses/>.
-------------

On Debian GNU/Linux systems, the complete text of the GNU Lesser
General Public License can be found in
`/usr/share/common-licenses/LGPL';

The documentation licensed under the GPL
-------------
Copyright @copyright{} 2000, 2002, 2003, 2004, 2006, 2007, 2008, 2009, 2011, 2012 Free Software Foundation, Inc. @*
Copyright @copyright{} 2012, 2013, 2016 2017 g10 Code GmbH

@quotation
Permission is granted to copy, distribute and/or modify this document
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 2 of the License, or (at your
option) any later version. The text of the license can be found in the
section entitled ``GNU General Public License''.
-------------

Further details on licensing:
From upstream's LICENSES file
8X---------------------------------------------------
Additional license notices for Libgcrypt.                    -*- org -*-

This file contains the copying permission notices for various files in
the Libgcrypt distribution which are not covered by the GNU Lesser
General Public License (LGPL) or the GNU General Public License (GPL).

These notices all require that a copy of the notice be included
in the accompanying documentation and be distributed with binary
distributions of the code, so be sure to include this file along
with any binary distributions derived from the GNU C Library.

* BSD_3Clause

  For files:
  - cipher/sha256-avx-amd64.S
  - cipher/sha256-avx2-bmi2-amd64.S
  - cipher/sha256-ssse3-amd64.S
  - cipher/sha512-avx-amd64.S
  - cipher/sha512-avx2-bmi2-amd64.S
  - cipher/sha512-ssse3-amd64.S

#+begin_quote
  Copyright (c) 2012, Intel Corporation

  All rights reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are
  met:

  * Redistributions of source code must retain the above copyright
    notice, this list of conditions and the following disclaimer.

  * Redistributions in binary form must reproduce the above copyright
    notice, this list of conditions and the following disclaimer in the
    documentation and/or other materials provided with the
    distribution.

  * Neither the name of the Intel Corporation nor the names of its
    contributors may be used to endorse or promote products derived from
    this software without specific prior written permission.


  THIS SOFTWARE IS PROVIDED BY INTEL CORPORATION "AS IS" AND ANY
  EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
  PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL INTEL CORPORATION OR
  CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
  EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
  PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
  PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
  LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
  NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#+end_quote


  For files:
  - random/jitterentropy-base.c
  - random/jitterentropy.h
  - random/rndjent.c (plus common Libgcrypt copyright holders)

#+begin_quote
 * Copyright Stephan Mueller <smueller@chronox.de>, 2013
 *
 * License
 * =======
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, and the entire permission notice in its entirety,
 *    including the disclaimer of warranties.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote
 *    products derived from this software without specific prior
 *    written permission.
 *
 * ALTERNATIVELY, this product may be distributed under the terms of
 * the GNU General Public License, in which case the provisions of the GPL are
 * required INSTEAD OF the above restrictions.  (This clause is
 * necessary due to a potential bad interaction between the GPL and
 * the restrictions contained in a BSD-style copyright.)
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, ALL OF
 * WHICH ARE HEREBY DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OF THIS SOFTWARE, EVEN IF NOT ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
#+end_quote

  For files:
  - cipher/cipher-gcm-ppc.c

#+begin_quote
 Copyright (c) 2006, CRYPTOGAMS by <appro@openssl.org>
 All rights reserved.

 Redistribution and use in source and binary forms, with or without
 modification, are permitted provided that the following conditions
 are met:

       * Redistributions of source code must retain copyright notices,
         this list of conditions and the following disclaimer.

       * Redistributions in binary form must reproduce the above
         copyright notice, this list of conditions and the following
         disclaimer in the documentation and/or other materials
         provided with the distribution.

       * Neither the name of the CRYPTOGAMS nor the names of its
         copyright holder and contributors may be used to endorse or
         promote products derived from this software without specific
         prior written permission.

 ALTERNATIVELY, provided that this notice is retained in full, this
 product may be distributed under the terms of the GNU General Public
 License (GPL), in which case the provisions of the GPL apply INSTEAD OF
 those given above.

 THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDER AND CONTRIBUTORS
 "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#+end_quote

* X License

  For files:
  - install.sh

#+begin_quote
  Copyright (C) 1994 X Consortium

  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to
  deal in the Software without restriction, including without limitation the
  rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
  sell copies of the Software, and to permit persons to whom the Software is
  furnished to do so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in
  all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
  X CONSORTIUM BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN
  AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNEC-
  TION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

  Except as contained in this notice, the name of the X Consortium shall not
  be used in advertising or otherwise to promote the sale, use or other deal-
  ings in this Software without prior written authorization from the X Consor-
  tium.
#+end_quote

* Public domain

  For files:
  - cipher/arcfour-amd64.S

#+begin_quote
 Author: Marc Bevand <bevand_m (at) epita.fr>
 Licence: I hereby disclaim the copyright on this code and place it
 in the public domain.
#+end_quote

* OCB license 1

  For files:
  - cipher/cipher-ocb.c

#+begin_quote
  OCB is covered by several patents but may be used freely by most
  software.  See http://web.cs.ucdavis.edu/~rogaway/ocb/license.htm .
  In particular license 1 is suitable for Libgcrypt: See
  http://web.cs.ucdavis.edu/~rogaway/ocb/license1.pdf for the full
  license document; it basically says:

    License 1 — License for Open-Source Software Implementations of OCB
                (Jan 9, 2013)

    Under this license, you are authorized to make, use, and
    distribute open-source software implementations of OCB. This
    license terminates for you if you sue someone over their
    open-source software implementation of OCB claiming that you have
    a patent covering their implementation.



 License for Open Source Software Implementations of OCB
 January 9, 2013

 1 Definitions

 1.1 “Licensor” means Phillip Rogaway.

 1.2 “Licensed Patents” means any patent that claims priority to United
 States Patent Application No. 09/918,615 entitled “Method and Apparatus
 for Facilitating Efficient Authenticated Encryption,” and any utility,
 divisional, provisional, continuation, continuations-in-part, reexamination,
 reissue, or foreign counterpart patents that may issue with respect to the
 aforesaid patent application. This includes, but is not limited to, United
 States Patent No. 7,046,802; United States Patent No. 7,200,227; United
 States Patent No. 7,949,129; United States Patent No. 8,321,675 ; and any
 patent that issues out of United States Patent Application No. 13/669,114.

 1.3 “Use” means any practice of any invention claimed in the Licensed Patents.

 1.4 “Software Implementation” means any practice of any invention
 claimed in the Licensed Patents that takes the form of software executing on
 a user-programmable, general-purpose computer or that takes the form of a
 computer-readable medium storing such software. Software Implementation does
 not include, for example, application-specific integrated circuits (ASICs),
 field-programmable gate arrays (FPGAs), embedded systems, or IP cores.

 1.5 “Open Source Software” means software whose source code is published
 and made available for inspection and use by anyone because either (a) the
 source code is subject to a license that permits recipients to copy, modify,
 and distribute the source code without payment of fees or royalties, or
 (b) the source code is in the public domain, including code released for
 public use through a CC0 waiver. All licenses certified by the Open Source
 Initiative at opensource.org as of January 9, 2013 and all Creative Commons
 licenses identified on the creativecommons.org website as of January 9,
 2013, including the Public License Fallback of the CC0 waiver, satisfy these
 requirements for the purposes of this license.

 1.6 “Open Source Software Implementation” means a Software
 Implementation in which the software implicating the Licensed Patents is
 Open Source Software. Open Source Software Implementation does not include
 any Software Implementation in which the software implicating the Licensed
 Patents is combined, so as to form a larger program, with software that is
 not Open Source Software.

 2 License Grant

 2.1 License. Subject to your compliance with the term s of this license,
 including the restriction set forth in Section 2.2, Licensor hereby
 grants to you a perpetual, worldwide, non-exclusive, non-transferable,
 non-sublicenseable, no-charge, royalty-free, irrevocable license to practice
 any invention claimed in the Licensed Patents in any Open Source Software
 Implementation.

 2.2 Restriction. If you or your affiliates institute patent litigation
 (including, but not limited to, a cross-claim or counterclaim in a lawsuit)
 against any entity alleging that any Use authorized by this license
 infringes another patent, then any rights granted to you under this license
 automatically terminate as of the date such litigation is filed.

 3 Disclaimer
 YOUR USE OF THE LICENSED PATENTS IS AT YOUR OWN RISK AND UNLESS REQUIRED
 BY APPLICABLE LAW, LICENSOR MAKES NO REPRESENTATIONS OR WARRANTIES OF ANY
 KIND CONCERNING THE LICENSED PATENTS OR ANY PRODUCT EMBODYING ANY LICENSED
 PATENT, EXPRESS OR IMPLIED, STATUT ORY OR OTHERWISE, INCLUDING, WITHOUT
 LIMITATION, WARRANTIES OF TITLE, MERCHANTIBILITY, FITNESS FOR A PARTICULAR
 PURPOSE, OR NONINFRINGEMENT. IN NO EVENT WILL LICENSOR BE LIABLE FOR ANY
 CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN CONTRACT, TORT OR OTHERWISE,
 ARISING FROM OR RELATED TO ANY USE OF THE LICENSED PATENTS, INCLUDING,
 WITHOUT LIMITATION, DIRECT, INDIRECT, INCIDENTAL, CONSEQUENTIAL, PUNITIVE
 OR SPECIAL DAMAGES, EVEN IF LICENSOR HAS BEEN ADVISED OF THE POSSIBILITY OF
 SUCH DAMAGES PRIOR TO SUCH AN OCCURRENCE.
#+end_quote
8X---------------------------------------------------


On Debian GNU/Linux systems, the text of the GNU General Public License,
version 2 can be found in `/usr/share/common-licenses/GPL-2'.
```

## libgpg-error0 1.43-3 — bundled: libgpg-error.so.0

Copyright/license source (verbatim): `/usr/share/doc/libgpg-error0/copyright` in the libgpg-error0 package.

```text
Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
Upstream-Name: libgpg-error
Upstream-Contact: gnupg-devel@gnupg.org
Source: https://gnupg.org/ftp/gcrypt/libgpg-error/

Files: *
Copyright: 2001-2004, 2010, 2012-2018, g10 Code GmbH
License: LGPL-2.1+

Files: src/b64dec.c
Copyright: 2008, 2011 Free Software Foundation, Inc.
 2008, 2011, 2016 g10 Code GmbH
License: LGPL-2.1+

Files: src/estream-printf.h src/estream-printf.c src/estream.c
Copyright: 2004-2012, 2014-2017 g10 Code GmbH
License: LGPL-2.1+ or BSD-3-clause

Files: src/w32-estream.c
Copyright: 2000 Werner Koch (dd9jn)
 2001, 2002, 2003, 2004, 2007, 2010, 2016 g10 Code GmbH
License: LGPL-2.1+

Files: src/gettext.h
Copyright: 1995-1998, 2000-2002 Free Software Foundation, Inc.
License: LGPL-2.1+

Files: src/gpg-error-config.in
Copyright: 1999, 2002, 2003 Free Software Foundation, Inc.
License: g10-permissive

Files: src/mkheader.c
Copyright: 2010 Free Software Foundation, Inc.
 2014 g10 Code GmbH
License: g10-permissive

Files: src/posix-lock.c
Copyright: 2005-2009 Free Software Foundation, Inc.
 2014 g10 Code GmbH
License: LGPL-2.1+

Files: src/w32-gettext.c
Copyright: 1995, 1996, 1997, 1999, 2005, 2007, 2008, 2010 Free Software Foundation, Inc.
License: LGPL-2.1+

Files: doc/yat2m.c
Copyright: 2005, 2013, 2015, 2016 g10 Code GmbH
 2006, 2008, 2011 Free Software Foundation, Inc.
License: GPL-3+

Files: potomo
Copyright: 2008 g10 Code GmbH
 2010 Free Software Foundation, Inc.
License: g10-permissive

License: g10-permissive
 This file is free software; as a special exception the author gives
 unlimited permission to copy and/or distribute it, with or without
 modifications, as long as this notice is preserved.
 .
 This file is distributed in the hope that it will be useful, but
 WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
 implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

License: LGPL-2.1+
 This program is free software; you can redistribute it and/or modify
 it under the terms of the GNU Lesser General Public License as
 published by the Free Software Foundation; either version 2.1
 of the License, or (at your option) any later version.
 .
 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU Lesser General Public License for more details.
 .
 You should have received a copy of the GNU Lesser General Public
 License along with this program; if not, write to the Free Software
 Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA.
 .
 On Debian systems, the complete text of the GNU Lesser General Public License
 version 2.1 can be found in /usr/share/common-licenses/LGPL-2.1.

License: GPL-3+
 This program is free software; you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation; either version 3 of the License, or
 (at your option) any later version.
 .
 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.
 .
 You should have received a copy of the GNU General Public License
 along with this program; if not, see <https://www.gnu.org/licenses/>.
 .
 On Debian systems, the complete text of the GNU General Public License
 version 3 can be found in /usr/share/common-licenses/GPL-3.

License: BSD-3-clause
 Redistribution and use in source and binary forms, with or without
 modification, are permitted provided that the following conditions
 are met:
 1. Redistributions of source code must retain the above copyright
    notice, and the entire permission notice in its entirety,
    including the disclaimer of warranties.
 2. Redistributions in binary form must reproduce the above copyright
    notice, this list of conditions and the following disclaimer in the
    documentation and/or other materials provided with the distribution.
 3. The name of the author may not be used to endorse or promote
    products derived from this software without specific prior
    written permission.
 .
 THIS SOFTWARE IS PROVIDED "AS IS" AND ANY EXPRESS OR IMPLIED
 WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 OF THE POSSIBILITY OF SUCH DAMAGE.
```

## libcap2 1:2.44-1ubuntu0.22.04.3 — bundled: libcap.so.2

Copyright/license source (verbatim): `/usr/share/doc/libcap2/copyright` in the libcap2 package.

```text
Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
Upstream-Name: libcap
Upstream-Contact: Andrew G. Morgan <morgan@kernel.org>
Source: https://www.kernel.org/pub/linux/libs/security/linux-privs/libcap2/

Files: *
Copyright: 1997-2016 Andrew G. Morgan <morgan@linux.kernel.org>
License: BSD-3-clause or GPL-2

Files: libcap/cap_text.c
Copyright: 1997-2008 Andrew G. Morgan <morgan@linux.kernel.org>
           1997 Andrew Main <zefram@dcs.warwick.ac.uk>
License: BSD-3-clause or GPL-2

Files: libcap/include/sys/capability.h
Copyright: 1997-2008 Andrew G. Morgan <morgan@kernel.org>
           1997 Aleph One
License: BSD-3-clause or GPL-2

Files: libcap/include/sys/securebits.h
Copyright: 2010 Serge Hallyn <serue@us.ibm.com>
License: BSD-3-clause or GPL-2

Files: progs/old/sucap.c
Copyright: 1998 Finn Arne Gangstad <finnag@guardian.no>
License: BSD-3-clause or GPL-2

Files: contrib/*
Copyright: 2006, Matt Kern <matt.kern@undue.org>
           2008, Andrew G. Morgan <morgan@linux.kernel.org>
	   2008, Chris Friedhoff <chris@friedhoff.org>
License: BSD-3-clause or GPL-2

Files: debian/*
Copyright: 2014, Daniel Baumann <mail@daniel-baumann.ch>
           2014-2019, Christian Kastner <ckk@debian.org>
License: BSD-3-clause or GPL-2+

Files: debian/manpages/*
Copyright: 1997-2014 Andrew G. Morgan <morgan@linux.kernel.org>
           2011 Scott Schaefer <saschaefer@neurodiverse.org>
License: BSD-3-clause or GPL-2

Files: debian/patches/*
Copyright: 2011, Andrew Straw <strawman@astraw.com>
           2011, Zhi Li <lizhi1215@gmail.com>
           2014-2016, Christian Kastner <ckk@debian.org>
           2015, Helmut Grohne <helmut@subdivi.de>
License: BSD-3-clause or GPL-2+

License: BSD-3-clause
 Redistribution and use in source and binary forms of libcap, with
 or without modification, are permitted provided that the following
 conditions are met:
 .
 1. Redistributions of source code must retain any existing copyright
    notice, and this entire permission notice in its entirety,
    including the disclaimer of warranties.
 .
 2. Redistributions in binary form must reproduce all prior and current
    copyright notices, this list of conditions, and the following
    disclaimer in the documentation and/or other materials provided
    with the distribution.
 .
 3. The name of any author may not be used to endorse or promote
    products derived from this software without their specific prior
    written permission.
 .
 THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 IN NO EVENT SHALL THE AUTHOR(S) BE LIABLE FOR ANY DIRECT, INDIRECT,
 INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
 TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 DAMAGE.

License: GPL-2
 This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, version 2 of the License.
 .
 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 GNU General Public License for more details.
 .
 You should have received a copy of the GNU General Public License
 along with this program. If not, see <http://www.gnu.org/licenses/>.
 .
 The complete text of the GNU General Public License
 can be found in /usr/share/common-licenses/GPL-2 file.

License: GPL-2+
 This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 2 of the License, or
 (at your option) any later version.
 .
 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 GNU General Public License for more details.
 .
 You should have received a copy of the GNU General Public License
 along with this program. If not, see <http://www.gnu.org/licenses/>.
 .
 The complete text of the GNU General Public License
 can be found in /usr/share/common-licenses/GPL-2 file.
```

## libxau6 1:1.0.9-1build5 — bundled: libXau.so.6

Copyright/license source (verbatim): `/usr/share/doc/libxau6/copyright` in the libxau6 package.

```text
This package was downloaded from
https://xorg.freedesktop.org/releases/individual/lib/

Copyright 1988, 1998  The Open Group

Permission to use, copy, modify, distribute, and sell this software and its
documentation for any purpose is hereby granted without fee, provided that
the above copyright notice appear in all copies and that both that
copyright notice and this permission notice appear in supporting
documentation.

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
OPEN GROUP BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN
AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

Except as contained in this notice, the name of The Open Group shall not be
used in advertising or otherwise to promote the sale, use or other dealings
in this Software without prior written authorization from The Open Group.
```

## libxdmcp6 1:1.1.3-0ubuntu5 — bundled: libXdmcp.so.6

Copyright/license source (verbatim): `/usr/share/doc/libxdmcp6/copyright` in the libxdmcp6 package.

```text
This package was downloaded from
http://xorg.freedesktop.org/releases/individual/lib/

Copyright 1989, 1998  The Open Group

Permission to use, copy, modify, distribute, and sell this software and its
documentation for any purpose is hereby granted without fee, provided that
the above copyright notice appear in all copies and that both that
copyright notice and this permission notice appear in supporting
documentation.

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
OPEN GROUP BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN
AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

Except as contained in this notice, the name of The Open Group shall not be
used in advertising or otherwise to promote the sale, use or other dealings
in this Software without prior written authorization from The Open Group.

Author:  Keith Packard, MIT X Consortium
```

## libbsd0 0.11.5-1 — bundled: libbsd.so.0

Copyright/license source (verbatim): `/usr/share/doc/libbsd0/copyright` in the libbsd0 package.

```text
Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/

Files:
 *
Copyright:
 Copyright © 2004-2006, 2008-2021 Guillem Jover <guillem@hadrons.org>
License: BSD-3-clause

Files:
 man/arc4random.3bsd
Copyright:
 Copyright 1997 Niels Provos <provos@physnet.uni-hamburg.de>
 All rights reserved.
License: BSD-4-clause-Niels-Provos
 Redistribution and use in source and binary forms, with or without
 modification, are permitted provided that the following conditions
 are met:
 1. Redistributions of source code must retain the above copyright
    notice, this list of conditions and the following disclaimer.
 2. Redistributions in binary form must reproduce the above copyright
    notice, this list of conditions and the following disclaimer in the
    documentation and/or other materials provided with the distribution.
 3. All advertising materials mentioning features or use of this software
    must display the following acknowledgement:
      This product includes software developed by Niels Provos.
 4. The name of the author may not be used to endorse or promote products
    derived from this software without specific prior written permission.
 .
 THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

Files:
 man/getprogname.3bsd
Copyright:
 Copyright © 2001 Christopher G. Demetriou
 All rights reserved.
License: BSD-4-clause-Christopher-G-Demetriou
 Redistribution and use in source and binary forms, with or without
 modification, are permitted provided that the following conditions
 are met:
 1. Redistributions of source code must retain the above copyright
    notice, this list of conditions and the following disclaimer.
 2. Redistributions in binary form must reproduce the above copyright
    notice, this list of conditions and the following disclaimer in the
    documentation and/or other materials provided with the distribution.
 3. All advertising materials mentioning features or use of this software
    must display the following acknowledgement:
          This product includes software developed for the
          NetBSD Project.  See http://www.netbsd.org/ for
          information about NetBSD.
 4. The name of the author may not be used to endorse or promote products
    derived from this software without specific prior written permission.
 .
 THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

Files:
 include/bsd/err.h
 include/bsd/stdlib.h
 include/bsd/sys/param.h
 include/bsd/unistd.h
 src/bsd_getopt.c
 src/err.c
 src/fgetln.c
 src/progname.c
Copyright:
 Copyright © 2005, 2008-2012, 2019 Guillem Jover <guillem@hadrons.org>
 Copyright © 2005 Hector Garcia Alvarez
 Copyright © 2005 Aurelien Jarno
 Copyright © 2006 Robert Millan
 Copyright © 2018 Facebook, Inc.
License: BSD-3-clause

Files:
 include/bsd/netinet/ip_icmp.h
 include/bsd/sys/bitstring.h
 include/bsd/sys/queue.h
 include/bsd/sys/time.h
 include/bsd/timeconv.h
 include/bsd/vis.h
 man/bitstring.3bsd
 man/errc.3bsd
 man/explicit_bzero.3bsd
 man/fgetln.3bsd
 man/fgetwln.3bsd
 man/fpurge.3bsd
 man/funopen.3bsd
 man/getbsize.3bsd
 man/heapsort.3bsd
 man/nlist.3bsd
 man/pwcache.3bsd
 man/queue.3bsd
 man/radixsort.3bsd
 man/reallocarray.3bsd
 man/reallocf.3bsd
 man/setmode.3bsd
 man/strmode.3bsd
 man/strnstr.3bsd
 man/strtoi.3bsd
 man/strtou.3bsd
 man/unvis.3bsd
 man/vis.3bsd
 man/wcslcpy.3bsd
 src/getbsize.c
 src/heapsort.c
 src/merge.c
 src/nlist.c
 src/pwcache.c
 src/radixsort.c
 src/setmode.c
 src/strmode.c
 src/strnstr.c
 src/strtoi.c
 src/strtou.c
 src/unvis.c
Copyright:
 Copyright © 1980, 1982, 1986, 1989-1994
     The Regents of the University of California.  All rights reserved.
 Copyright © 1992 Keith Muller.
 Copyright © 2001 Mike Barcroft <mike@FreeBSD.org>
 .
 Some code is derived from software contributed to Berkeley by
 the American National Standards Committee X3, on Information
 Processing Systems.
 .
 Some code is derived from software contributed to Berkeley by
 Peter McIlroy.
 .
 Some code is derived from software contributed to Berkeley by
 Ronnie Kon at Mindcraft Inc., Kevin Lew and Elmer Yglesias.
 .
 Some code is derived from software contributed to Berkeley by
 Dave Borman at Cray Research, Inc.
 .
 Some code is derived from software contributed to Berkeley by
 Paul Vixie.
 .
 Some code is derived from software contributed to Berkeley by
 Chris Torek.
 .
 Copyright © UNIX System Laboratories, Inc.
 All or some portions of this file are derived from material licensed
 to the University of California by American Telephone and Telegraph
 Co. or Unix System Laboratories, Inc. and are reproduced herein with
 the permission of UNIX System Laboratories, Inc.
License: BSD-3-clause-Regents

Files:
 src/vis.c
Copyright:
 Copyright © 1989, 1993
     The Regents of the University of California.  All rights reserved.
 .
 Copyright © 1999, 2005 The NetBSD Foundation, Inc.
 All rights reserved.
License: BSD-3-clause-Regents and BSD-2-clause-NetBSD

Files:
 include/bsd/libutil.h
Copyright:
 Copyright © 1996  Peter Wemm <peter@FreeBSD.org>.
 All rights reserved.
 Copyright © 2002 Networks Associates Technology, Inc.
 All rights reserved.
License: BSD-3-clause-author

Files:
 man/timeradd.3bsd
Copyright:
 Copyright © 2009 Jukka Ruohonen <jruohonen@iki.fi>
 Copyright © 1999 Kelly Yancey <kbyanc@posi.net>
 All rights reserved.
License: BSD-3-clause-John-Birrell
 Redistribution and use in source and binary forms, with or without
 modification, are permitted provided that the following conditions
 are met:
 1. Redistributions of source code must retain the above copyright
    notice, this list of conditions and the following disclaimer.
 2. Redistributions in binary form must reproduce the above copyright
    notice, this list of conditions and the following disclaimer in the
    documentation and/or other materials provided with the distribution.
 3. Neither the name of the author nor the names of any co-contributors
    may be used to endorse or promote products derived from this software
    without specific prior written permission.
 .
 THIS SOFTWARE IS PROVIDED BY JOHN BIRRELL AND CONTRIBUTORS ``AS IS'' AND
 ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 SUCH DAMAGE.

Files:
 man/setproctitle.3bsd
Copyright:
 Copyright © 1995 Peter Wemm <peter@FreeBSD.org>
 All rights reserved.
License: BSD-5-clause-Peter-Wemm
 Redistribution and use in source and binary forms, with or without
 modification, is permitted provided that the following conditions
 are met:
 1. Redistributions of source code must retain the above copyright
    notice immediately at the beginning of the file, without modification,
    this list of conditions, and the following disclaimer.
 2. Redistributions in binary form must reproduce the above copyright
    notice, this list of conditions and the following disclaimer in the
    documentation and/or other materials provided with the distribution.
 3. This work was done expressly for inclusion into FreeBSD.  Other use
    is permitted provided this notation is included.
 4. Absolutely no warranty of function or purpose is made by the author
    Peter Wemm.
 5. Modifications may be freely made to this file providing the above
    conditions are met.

Files:
 include/bsd/stringlist.h
 man/fmtcheck.3bsd
 man/humanize_number.3bsd
 man/stringlist.3bsd
 man/timeval.3bsd
 src/fmtcheck.c
 src/humanize_number.c
 src/stringlist.c
 src/strtonum.c
Copyright:
 Copyright © 1994, 1997-2000, 2002, 2008, 2010, 2014
     The NetBSD Foundation, Inc.
 Copyright © 2013 John-Mark Gurney <jmg@FreeBSD.org>
 All rights reserved.
 .
 Some code was contributed to The NetBSD Foundation by Allen Briggs.
 .
 Some code was contributed to The NetBSD Foundation by Luke Mewburn.
 .
 Some code is derived from software contributed to The NetBSD Foundation
 by Jason R. Thorpe of the Numerical Aerospace Simulation Facility,
 NASA Ames Research Center, by Luke Mewburn and by Tomas Svensson.
 .
 Some code is derived from software contributed to The NetBSD Foundation
 by Julio M. Merino Vidal, developed as part of Google's Summer of Code
 2005 program.
 .
 Some code is derived from software contributed to The NetBSD Foundation
 by Christos Zoulas.
 .
 Some code is derived from software contributed to The NetBSD Foundation
 by Jukka Ruohonen.
License: BSD-2-clause-NetBSD

Files:
 include/bsd/sys/endian.h
 man/byteorder.3bsd
 man/closefrom.3bsd
 man/expand_number.3bsd
 man/flopen.3bsd
 man/getpeereid.3bsd
 man/pidfile.3bsd
 src/expand_number.c
 src/pidfile.c
 src/reallocf.c
 src/timeconv.c
Copyright:
 Copyright © 1998, M. Warner Losh <imp@freebsd.org>
 All rights reserved.
 .
 Copyright © 2001 Dima Dorfman.
 All rights reserved.
 .
 Copyright © 2001 FreeBSD Inc.
 All rights reserved.
 .
 Copyright © 2002 Thomas Moestl <tmm@FreeBSD.org>
 All rights reserved.
 .
 Copyright © 2002 Mike Barcroft <mike@FreeBSD.org>
 All rights reserved.
 .
 Copyright © 2005 Pawel Jakub Dawidek <pjd@FreeBSD.org>
 All rights reserved.
 .
 Copyright © 2005 Colin Percival
 All rights reserved.
 .
 Copyright © 2007 Eric Anderson <anderson@FreeBSD.org>
 Copyright © 2007 Pawel Jakub Dawidek <pjd@FreeBSD.org>
 All rights reserved.
 .
 Copyright © 2007 Dag-Erling Coïdan Smørgrav
 All rights reserved.
 .
 Copyright © 2009 Advanced Computing Technologies LLC
 Written by: John H. Baldwin <jhb@FreeBSD.org>
 All rights reserved.
 .
 Copyright © 2011 Guillem Jover <guillem@hadrons.org>
License: BSD-2-clause

Files:
 src/flopen.c
Copyright:
 Copyright © 2007-2009 Dag-Erling Coïdan Smørgrav
 All rights reserved.
License: BSD-2-clause-verbatim
 Redistribution and use in source and binary forms, with or without
 modification, are permitted provided that the following conditions
 are met:
 1. Redistributions of source code must retain the above copyright
    notice, this list of conditions and the following disclaimer
    in this position and unchanged.
 2. Redistributions in binary form must reproduce the above copyright
    notice, this list of conditions and the following disclaimer in the
    documentation and/or other materials provided with the distribution.
 .
 THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 SUCH DAMAGE.

Files:
 include/bsd/sys/tree.h
 man/fparseln.3bsd
 man/tree.3bsd
 src/fparseln.c
Copyright:
 Copyright © 1997 Christos Zoulas.
 All rights reserved.
 .
 Copyright © 2002 Niels Provos <provos@citi.umich.edu>
 All rights reserved.
License: BSD-2-clause-author

Files:
 include/bsd/readpassphrase.h
 man/readpassphrase.3bsd
 man/strlcpy.3bsd
 man/strtonum.3bsd
 src/arc4random.c
 src/arc4random_linux.h
 src/arc4random_openbsd.h
 src/arc4random_uniform.c
 src/arc4random_unix.h
 src/arc4random_win.h
 src/closefrom.c
 src/freezero.c
 src/getentropy_aix.c
 src/getentropy_bsd.c
 src/getentropy_hpux.c
 src/getentropy_hurd.c
 src/getentropy_linux.c
 src/getentropy_osx.c
 src/getentropy_solaris.c
 src/getentropy_win.c
 src/readpassphrase.c
 src/reallocarray.c
 src/recallocarray.c
 src/strlcat.c
 src/strlcpy.c
Copyright:
 Copyright © 2004 Ted Unangst and Todd Miller
 All rights reserved.
 .
 Copyright © 1996 David Mazieres <dm@uun.org>
 Copyright © 1998, 2000-2002, 2004-2005, 2007, 2010, 2012-2015
     Todd C. Miller <Todd.Miller@courtesan.com>
 Copyright © 2004 Ted Unangst
 Copyright © 2008 Damien Miller <djm@openbsd.org>
 Copyright © 2008, 2010-2011, 2016-2017 Otto Moerbeek <otto@drijf.net>
 Copyright © 2013 Markus Friedl <markus@openbsd.org>
 Copyright © 2014 Bob Beck <beck@obtuse.com>
 Copyright © 2014 Brent Cook <bcook@openbsd.org>
 Copyright © 2014 Pawel Jakub Dawidek <pjd@FreeBSD.org>
 Copyright © 2014 Theo de Raadt <deraadt@openbsd.org>
 Copyright © 2015 Michael Felt <aixtools@gmail.com>
 Copyright © 2015 Guillem Jover <guillem@hadrons.org>
License: ISC
 Permission to use, copy, modify, and distribute this software for any
 purpose with or without fee is hereby granted, provided that the above
 copyright notice and this permission notice appear in all copies.
 .
 THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

Files:
 src/inet_net_pton.c
Copyright:
 Copyright © 1996 by Internet Software Consortium.
License: ISC-Original
 Permission to use, copy, modify, and distribute this software for any
 purpose with or without fee is hereby granted, provided that the above
 copyright notice and this permission notice appear in all copies.
 .
 THE SOFTWARE IS PROVIDED "AS IS" AND INTERNET SOFTWARE CONSORTIUM DISCLAIMS
 ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES
 OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL INTERNET SOFTWARE
 CONSORTIUM BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
 ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 SOFTWARE.

Files:
 src/setproctitle.c
Copyright:
 Copyright © 2010 William Ahern
 Copyright © 2012 Guillem Jover <guillem@hadrons.org>
License: Expat
 Permission is hereby granted, free of charge, to any person obtaining a
 copy of this software and associated documentation files (the
 "Software"), to deal in the Software without restriction, including
 without limitation the rights to use, copy, modify, merge, publish,
 distribute, sublicense, and/or sell copies of the Software, and to permit
 persons to whom the Software is furnished to do so, subject to the
 following conditions:
 .
 The above copyright notice and this permission notice shall be included
 in all copies or substantial portions of the Software.
 .
 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
 NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
 DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
 OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
 USE OR OTHER DEALINGS IN THE SOFTWARE.

Files:
 src/explicit_bzero.c
 src/chacha_private.h
Copyright:
 None
License: public-domain
 Public domain.

Files:
 man/mdX.3bsd
Copyright:
 None
License: Beerware
 "THE BEER-WARE LICENSE" (Revision 42):
 <phk@login.dkuug.dk> wrote this file.  As long as you retain this notice you
 can do whatever you want with this stuff. If we meet some day, and you think
 this stuff is worth it, you can buy me a beer in return.   Poul-Henning Kamp

License: BSD-3-clause-Regents
 Redistribution and use in source and binary forms, with or without
 modification, are permitted provided that the following conditions
 are met:
 1. Redistributions of source code must retain the above copyright
    notice, this list of conditions and the following disclaimer.
 2. Redistributions in binary form must reproduce the above copyright
    notice, this list of conditions and the following disclaimer in the
    documentation and/or other materials provided with the distribution.
 3. Neither the name of the University nor the names of its contributors
    may be used to endorse or promote products derived from this software
    without specific prior written permission.
 .
 THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 SUCH DAMAGE.

License: BSD-3-clause-author
 Redistribution and use in source and binary forms, with or without
 modification, is permitted provided that the following conditions
 are met:
 1. Redistributions of source code must retain the above copyright
    notice, this list of conditions and the following disclaimer.
 2. Redistributions in binary form must reproduce the above copyright
    notice, this list of conditions and the following disclaimer in the
    documentation and/or other materials provided with the distribution.
 3. The name of the author may not be used to endorse or promote
    products derived from this software without specific prior written
    permission.
 .
 THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 SUCH DAMAGE.

License: BSD-3-clause
 Redistribution and use in source and binary forms, with or without
 modification, are permitted provided that the following conditions
 are met:
 1. Redistributions of source code must retain the above copyright
    notice, this list of conditions and the following disclaimer.
 2. Redistributions in binary form must reproduce the above copyright
    notice, this list of conditions and the following disclaimer in the
    documentation and/or other materials provided with the distribution.
 3. The name of the author may not be used to endorse or promote products
    derived from this software without specific prior written permission.
 .
 THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL
 THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

License: BSD-2-clause-NetBSD
 Redistribution and use in source and binary forms, with or without
 modification, are permitted provided that the following conditions
 are met:
 1. Redistributions of source code must retain the above copyright
    notice, this list of conditions and the following disclaimer.
 2. Redistributions in binary form must reproduce the above copyright
    notice, this list of conditions and the following disclaimer in the
    documentation and/or other materials provided with the distribution.
 .
 THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 POSSIBILITY OF SUCH DAMAGE.

License: BSD-2-clause-author
 Redistribution and use in source and binary forms, with or without
 modification, are permitted provided that the following conditions
 are met:
 1. Redistributions of source code must retain the above copyright
    notice, this list of conditions and the following disclaimer.
 2. Redistributions in binary form must reproduce the above copyright
    notice, this list of conditions and the following disclaimer in the
    documentation and/or other materials provided with the distribution.
 .
 THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

License: BSD-2-clause
 Redistribution and use in source and binary forms, with or without
 modification, are permitted provided that the following conditions
 are met:
 1. Redistributions of source code must retain the above copyright
    notice, this list of conditions and the following disclaimer.
 2. Redistributions in binary form must reproduce the above copyright
    notice, this list of conditions and the following disclaimer in the
    documentation and/or other materials provided with the distribution.
 .
 THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 SUCH DAMAGE.
```

## libmd0 1.0.4-1build1 — bundled: libmd.so.0

Copyright/license source (verbatim): `/usr/share/doc/libmd0/copyright` in the libmd0 package.

```text
Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/

Files:
 *
Copyright:
 Copyright © 2009, 2011, 2016 Guillem Jover <guillem@hadrons.org>
License: BSD-3-clause
 Redistribution and use in source and binary forms, with or without
 modification, are permitted provided that the following conditions
 are met:
 1. Redistributions of source code must retain the above copyright
    notice, this list of conditions and the following disclaimer.
 2. Redistributions in binary form must reproduce the above copyright
    notice, this list of conditions and the following disclaimer in the
    documentation and/or other materials provided with the distribution.
 3. The name of the author may not be used to endorse or promote products
    derived from this software without specific prior written permission.
 .
 THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL
 THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

Files:
 include/sha2.h
 src/sha2.c
Copyright:
 Copyright © 2000-2001, Aaron D. Gifford
 All rights reserved.
License: BSD-3-clause-Aaron-D-Gifford
 Redistribution and use in source and binary forms, with or without
 modification, are permitted provided that the following conditions
 are met:
 1. Redistributions of source code must retain the above copyright
    notice, this list of conditions and the following disclaimer.
 2. Redistributions in binary form must reproduce the above copyright
    notice, this list of conditions and the following disclaimer in the
    documentation and/or other materials provided with the distribution.
 3. Neither the name of the copyright holder nor the names of contributors
    may be used to endorse or promote products derived from this software
    without specific prior written permission.
 .
 THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTOR(S) ``AS IS'' AND
 ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTOR(S) BE LIABLE
 FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 SUCH DAMAGE.

Files:
 include/rmd160.h
 src/rmd160.c
Copyright:
 Copyright © 2001 Markus Friedl.  All rights reserved.
License: BSD-2-clause
 Redistribution and use in source and binary forms, with or without
 modification, are permitted provided that the following conditions
 are met:
 1. Redistributions of source code must retain the above copyright
    notice, this list of conditions and the following disclaimer.
 2. Redistributions in binary form must reproduce the above copyright
    notice, this list of conditions and the following disclaimer in the
    documentation and/or other materials provided with the distribution.
 .
 THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

Files:
 src/md2.c
Copyright:
 Copyright (c) 2001 The NetBSD Foundation, Inc.
 All rights reserved.
 .
 This code is derived from software contributed to The NetBSD Foundation
 by Andrew Brown.
License: BSD-2-clause-NetBSD
 Redistribution and use in source and binary forms, with or without
 modification, are permitted provided that the following conditions
 are met:
 1. Redistributions of source code must retain the above copyright
    notice, this list of conditions and the following disclaimer.
 2. Redistributions in binary form must reproduce the above copyright
    notice, this list of conditions and the following disclaimer in the
    documentation and/or other materials provided with the distribution.
 .
 THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 POSSIBILITY OF SUCH DAMAGE.

Files:
 man/rmd160.3
 man/sha1.3
 man/sha2.3
Copyright:
 Copyright © 1997, 2003, 2004 Todd C. Miller <Todd.Miller@courtesan.com>
License: ISC
 Permission to use, copy, modify, and distribute this software for any
 purpose with or without fee is hereby granted, provided that the above
 copyright notice and this permission notice appear in all copies.
 .
 THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

Files:
 man/mdX.3
 src/helper.c
Copyright:
 Poul-Henning Kamp <phk@login.dkuug.dk>
License: Beerware
 "THE BEER-WARE LICENSE" (Revision 42):
 <phk@login.dkuug.dk> wrote this file.  As long as you retain this notice you
 can do whatever you want with this stuff. If we meet some day, and you think
 this stuff is worth it, you can buy me a beer in return.   Poul-Henning Kamp

Files:
 include/md4.h
 src/md4.c
Copyright:
 Colin Plumb
 Todd C. Miller
License: public-domain-md4
 This code implements the MD4 message-digest algorithm.
 The algorithm is due to Ron Rivest.  This code was
 written by Colin Plumb in 1993, no copyright is claimed.
 This code is in the public domain; do with it what you wish.
 Todd C. Miller modified the MD5 code to do MD4 based on RFC 1186.

Files:
 include/md5.h
 src/md5.c
Copyright:
 Colin Plumb
License: public-domain-md5
 This code implements the MD5 message-digest algorithm.
 The algorithm is due to Ron Rivest.  This code was
 written by Colin Plumb in 1993, no copyright is claimed.
 This code is in the public domain; do with it what you wish.

Files:
 include/sha1.h
 src/sha1.c
Copyright:
 Steve Reid <steve@edmweb.com>
License: public-domain-sha1
 100% Public Domain
```

## libxtst6 2:1.2.3-1build4 — bundled: libXtst.so.6

Copyright/license source (verbatim): `/usr/share/doc/libxtst6/copyright` in the libxtst6 package.

```text
This package was downloaded from
https://xorg.freedesktop.org/releases/individual/lib/

Copyright 1990, 1991 by UniSoft Group Limited
Copyright 1992, 1993, 1995, 1998  The Open Group

Permission to use, copy, modify, distribute, and sell this software and its
documentation for any purpose is hereby granted without fee, provided that
the above copyright notice appear in all copies and that both that
copyright notice and this permission notice appear in supporting
documentation.

The above copyright notice and this permission notice shall be included
in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE OPEN GROUP BE LIABLE FOR ANY CLAIM, DAMAGES OR
OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
OTHER DEALINGS IN THE SOFTWARE.

Except as contained in this notice, the name of The Open Group shall
not be used in advertising or otherwise to promote the sale, use or
other dealings in this Software without prior written authorization
from The Open Group.

***************************************************************************

Copyright 1995 Network Computing Devices

Permission to use, copy, modify, distribute, and sell this software and
its documentation for any purpose is hereby granted without fee, provided
that the above copyright notice appear in all copies and that both that
copyright notice and this permission notice appear in supporting
documentation, and that the name of Network Computing Devices
not be used in advertising or publicity pertaining to distribution
of the software without specific, written prior permission.

NETWORK COMPUTING DEVICES DISCLAIMs ALL WARRANTIES WITH REGARD TO
THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
AND FITNESS, IN NO EVENT SHALL NETWORK COMPUTING DEVICES BE LIABLE
FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

***************************************************************************

Copyright 2005  Red Hat, Inc.

Permission to use, copy, modify, distribute, and sell this software and its
documentation for any purpose is hereby granted without fee, provided that
the above copyright notice appear in all copies and that both that
copyright notice and this permission notice appear in supporting
documentation, and that the name of Red Hat not be used in
advertising or publicity pertaining to distribution of the software without
specific, written prior permission.  Red Hat makes no
representations about the suitability of this software for any purpose.  It
is provided "as is" without express or implied warranty.

RED HAT DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE,
INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO
EVENT SHALL RED HAT BE LIABLE FOR ANY SPECIAL, INDIRECT OR
CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE,
DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER
TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
PERFORMANCE OF THIS SOFTWARE.

***************************************************************************

Copyright © 1992 by UniSoft Group Ltd.

Permission to use, copy, modify, and distribute this documentation for
any purpose and without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.
UniSoft makes no representations about the suitability for any purpose of
the information in this document.  This documentation is provided "as is"
without express or implied warranty.

***************************************************************************

Copyright © 1992, 1994, 1995 X Consortium

Permission is hereby granted, free of charge, to any person obtaining a
copy of this software and associated documentation files (the "Software"),
to deal in the Software without restriction, including without limitation
the rights to use, copy, modify, merge, publish, distribute, sublicense,
and/or sell copies of the Software, and to permit persons to whom the
Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
THE X CONSORTIUM BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF
OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

Except as contained in this notice, the name of the X Consortium shall not
be used in advertising or otherwise to promote the sale, use or other
dealings in this Software without prior written authorization from the
X Consortium.

***************************************************************************

Copyright 1994 Network Computing Devices, Inc.

Permission to use, copy, modify, distribute, and sell this
documentation for any purpose is hereby granted without fee,
provided that the above copyright notice and this permission
notice appear in all copies.  Network Computing Devices, Inc.
makes no representations about the suitability for any purpose
of the information in this document.  This documentation is
provided "as is" without express or implied warranty.
```
