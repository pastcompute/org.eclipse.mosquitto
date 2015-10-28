include ../config.mk

.PHONY : all clean install uninstall dist 

all :  eecloud.8 eecloud-tls.7 eecloud.conf.5 eecloud_passwd.1 eecloud_pub.1 eecloud_sub.1 mqtt.7 libeecloud.3

clean :

reallyclean : clean
	-rm -f *.orig

dist : eecloud.8 eecloud-tls.7 eecloud.conf.5 eecloud_passwd.1 eecloud_pub.1 eecloud_sub.1 mqtt.7 libeecloud.3

install :
	$(INSTALL) -d ${DESTDIR}$(mandir)/man8
	$(INSTALL) -m 644 eecloud.8 ${DESTDIR}${mandir}/man8/eecloud.8
	$(INSTALL) -d ${DESTDIR}$(mandir)/man5
	$(INSTALL) -m 644 eecloud.conf.5 ${DESTDIR}${mandir}/man5/eecloud.conf.5
	$(INSTALL) -d ${DESTDIR}$(mandir)/man1
	$(INSTALL) -m 644 eecloud_passwd.1 ${DESTDIR}${mandir}/man1/eecloud_passwd.1
	$(INSTALL) -m 644 eecloud_pub.1 ${DESTDIR}${mandir}/man1/eecloud_pub.1
	$(INSTALL) -m 644 eecloud_sub.1 ${DESTDIR}${mandir}/man1/eecloud_sub.1
	$(INSTALL) -d ${DESTDIR}$(mandir)/man7
	$(INSTALL) -m 644 mqtt.7 ${DESTDIR}${mandir}/man7/mqtt.7
	$(INSTALL) -m 644 eecloud-tls.7 ${DESTDIR}${mandir}/man7/eecloud-tls.7
	$(INSTALL) -d ${DESTDIR}$(mandir)/man3
	$(INSTALL) -m 644 libeecloud.3 ${DESTDIR}${mandir}/man3/libeecloud.3

uninstall :
	-rm -f ${DESTDIR}${mandir}/man8/eecloud.8
	-rm -f ${DESTDIR}${mandir}/man5/eecloud.conf.5
	-rm -f ${DESTDIR}${mandir}/man1/eecloud_passwd.1
	-rm -f ${DESTDIR}${mandir}/man1/eecloud_pub.1
	-rm -f ${DESTDIR}${mandir}/man1/eecloud_sub.1
	-rm -f ${DESTDIR}${mandir}/man7/mqtt.7
	-rm -f ${DESTDIR}${mandir}/man7/eecloud-tls.7
	-rm -f ${DESTDIR}${mandir}/man3/libeecloud.3

eecloud.8 : eecloud.8.xml
	$(XSLTPROC) $^

eecloud.conf.5 : eecloud.conf.5.xml manpage.xsl
	$(XSLTPROC) $<

eecloud_passwd.1 : eecloud_passwd.1.xml
	$(XSLTPROC) $^

eecloud_pub.1 : eecloud_pub.1.xml
	$(XSLTPROC) $^

eecloud_sub.1 : eecloud_sub.1.xml
	$(XSLTPROC) $^

mqtt.7 : mqtt.7.xml
	$(XSLTPROC) $^

eecloud-tls.7 : eecloud-tls.7.xml
	$(XSLTPROC) $^

libeecloud.3 : libeecloud.3.xml
	$(XSLTPROC) $^

html : *.xml
	set -e; for m in *.xml; \
		do \
		hfile=$$(echo $${m} | sed -e 's#\(.*\)\.xml#\1#' | sed -e 's/\./-/g'); \
		$(XSLTPROC) html.xsl $${m} > $${hfile}.php; \
	done

potgen :
	 xml2po -o po/eecloud/eecloud.8.pot eecloud.8.xml
	 xml2po -o po/eecloud.conf/eecloud.conf.5.pot eecloud.conf.5.xml
	 xml2po -o po/eecloud_passwd/eecloud_passwd.1.pot eecloud_passwd.1.xml
	 xml2po -o po/eecloud_pub/eecloud_pub.1.pot eecloud_pub.1.xml
	 xml2po -o po/eecloud_sub/eecloud_sub.1.pot eecloud_sub.1.xml
	 xml2po -o po/mqtt/mqtt.7.pot mqtt.7.xml
	 xml2po -o po/eecloud-tls/eecloud-tls.7.pot eecloud-tls.7.xml
	 xml2po -o po/libeecloud/libeecloud.3.pot libeecloud.3.xml

# To merge new translations do:
# /usr/bin/xml2po -p de.po chapter1.xml > chapter1.de.xml
