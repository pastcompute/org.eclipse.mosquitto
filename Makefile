include config.mk

DIRS=lib client src
DOCDIRS=man
DISTDIRS=man

.PHONY : all eecloud docs binary clean reallyclean test install uninstall dist sign copy

all : $(MAKE_ALL)

docs :
	set -e; for d in ${DOCDIRS}; do $(MAKE) -C $${d}; done

binary : eecloud

eecloud :
ifeq ($(UNAME),Darwin)
	$(error Please compile using CMake on Mac OS X)
endif

	set -e; for d in ${DIRS}; do $(MAKE) -C $${d}; done

clean :
	set -e; for d in ${DIRS}; do $(MAKE) -C $${d} clean; done
	set -e; for d in ${DOCDIRS}; do $(MAKE) -C $${d} clean; done
	$(MAKE) -C test clean

reallyclean : 
	set -e; for d in ${DIRS}; do $(MAKE) -C $${d} reallyclean; done
	set -e; for d in ${DOCDIRS}; do $(MAKE) -C $${d} reallyclean; done
	$(MAKE) -C test reallyclean
	-rm -f *.orig

test : eecloud
	$(MAKE) -C test test

install : eecloud
	set -e; for d in ${DIRS}; do $(MAKE) -C $${d} install; done
	set -e; for d in ${DOCDIRS}; do $(MAKE) -C $${d} install; done
	$(INSTALL) -d ${DESTDIR}/etc/eecloud
	$(INSTALL) -m 644 eecloud.conf ${DESTDIR}/etc/eecloud/eecloud.conf.example
	$(INSTALL) -m 644 aclfile.example ${DESTDIR}/etc/eecloud/aclfile.example
	$(INSTALL) -m 644 pwfile.example ${DESTDIR}/etc/eecloud/pwfile.example
	$(INSTALL) -m 644 pskfile.example ${DESTDIR}/etc/eecloud/pskfile.example

uninstall :
	set -e; for d in ${DIRS}; do $(MAKE) -C $${d} uninstall; done
	rm -f ${DESTDIR}/etc/eecloud/eecloud.conf
	rm -f ${DESTDIR}/etc/eecloud/aclfile.example
	rm -f ${DESTDIR}/etc/eecloud/pwfile.example
	rm -f ${DESTDIR}/etc/eecloud/pskfile.example

dist : reallyclean
	set -e; for d in ${DISTDIRS}; do $(MAKE) -C $${d} dist; done
	
	mkdir -p dist/eecloud-${VERSION}
	cp -r client examples installer lib logo man misc security service src test about.html aclfile.example ChangeLog.txt CMakeLists.txt compiling.txt config.h config.mk CONTRIBUTING.md edl-v10 epl-v10 LICENSE.txt Makefile eecloud.conf notice.html pskfile.example pwfile.example readme.txt readme-windows.txt dist/eecloud-${VERSION}/
	cd dist; tar -zcf eecloud-${VERSION}.tar.gz eecloud-${VERSION}/
	set -e; for m in man/*.xml; \
		do \
		hfile=$$(echo $${m} | sed -e 's#man/\(.*\)\.xml#\1#' | sed -e 's/\./-/g'); \
		$(XSLTPROC) $(DB_HTML_XSL) $${m} > dist/$${hfile}.html; \
	done


sign : dist
	cd dist; gpg --detach-sign -a eecloud-${VERSION}.tar.gz

copy : sign
	cd dist; scp eecloud-${VERSION}.tar.gz eecloud-${VERSION}.tar.gz.asc eecloud:site/eecloud.org/files/source/
	cd dist; scp *.html eecloud:site/eecloud.org/man/
	scp ChangeLog.txt eecloud:site/eecloud.org/

