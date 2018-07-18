# SPDX-License-Identifier: LGPL-2.1-or-later
# Copyright © 2007-2018 ANSSI. All Rights Reserved.

CC := gcc
CFLAGS := -fPIC -O2 -Wall -Werror 

PAM := pam_exec_pwd.so
MAKEFILE := pam_exec_pwd.8

all: ${PAM} ${MAKEFILE}

%.so: %.o 
	gcc -shared -o $@ $< -lc -lpam -ldl

%.8: %.pod
	pod2man -c="CLIP Services" -s=8 -r=CLIP $< > $@

clean:
	rm -f *.o ${PAM} ${MAKEFILE}

MANDIR ?= /usr/share/man

install: ${OUT}
	install -D -o0 -g0 -m755 ${PAM} ${DESTDIR}/lib/security/${PAM}
	install -D -o0 -g0 -m755 ${MAKEFILE} ${DESTDIR}/${MANDIR}/man8/${MAKEFILE}
