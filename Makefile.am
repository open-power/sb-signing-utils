# IBM_PROLOG_BEGIN_TAG
# This is an automatically generated prolog.
#
# $Source: src/signtool/Makefile.am $
#
# OpenPOWER sb-signing-utils Project
#
# Contributors Listed Below - COPYRIGHT 2017
# [+] International Business Machines Corp.
#
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied. See the License for the specific language governing
# permissions and limitations under the License.
#
# IBM_PROLOG_END_TAG

ACLOCAL_AMFLAGS = -I m4

bin_PROGRAMS = create-container print-container hashkeys
if ADD_DILITHIUM
bin_PROGRAMS += gendilkey gendilsig verifydilsig extractdilkey
endif

dist_bin_SCRIPTS = bulkSign.sh crtSignedContainer.sh sign-with-local-keys.sh

EXTRA_DIST = ccan container.c

create_container_SOURCES = \
	container.h \
	create-container.c

create_container_CPPFLAGS = $(AM_CPPFLAGS) -I. -g3 -std=gnu99
create_container_LDFLAGS =
create_container_LDADD = -lssl -lcrypto

print_container_SOURCES = \
	print-container.c

print_container_CPPFLAGS = $(AM_CPPFLAGS) -I. -g3 -std=gnu99 ${DIL_CPPFLAGS}

print_container_LDFLAGS =
print_container_LDADD = -lssl -lcrypto ${DIL_LDADD}

hashkeys_SOURCES = \
	hashkeys.c

hashkeys_CPPFLAGS = $(AM_CPPFLAGS) -I. -g3 -std=gnu99
hashkeys_LDFLAGS =
hashkeys_LDADD = -lssl -lcrypto


if ADD_DILITHIUM
gendilkey_SOURCES = gendilkey.c
gendilkey_CPPFLAGS = $(AM_CPPFLAGS) -I. ${DIL_CPPFLAGS} -g3 -std=gnu99
gendilkey_LDFLAGS =
gendilkey_LDADD = ${DIL_LDADD}

gendilsig_SOURCES = gendilsig.c
gendilsig_CPPFLAGS = $(AM_CPPFLAGS) -I. ${DIL_CPPFLAGS} -g3 -std=gnu99
gendilsig_LDFLAGS =
gendilsig_LDADD = ${DIL_LDADD}

verifydilsig_SOURCES = verifydilsig.c
verifydilsig_CPPFLAGS = $(AM_CPPFLAGS) -I. ${DIL_CPPFLAGS} -g3 -std=gnu99
verifydilsig_LDFLAGS =
verifydilsig_LDADD = ${DIL_LDADD}

extractdilkey_SOURCES = extractdilkey.c
extractdilkey_CPPFLAGS = $(AM_CPPFLAGS) -I. ${DIL_CPPFLAGS} -g3 -std=gnu99
extractdilkey_LDFLAGS =
extractdilkey_LDADD = ${DIL_LDADD}
endif
