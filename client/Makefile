include ../config.mk

.PHONY: all install uninstall reallyclean clean

all : eecloud_pub eecloud_sub

eecloud_pub : pub_client.o client_shared.o
	${CROSS_COMPILE}${CC} $^ -o $@ ${CLIENT_LDFLAGS}

eecloud_sub : sub_client.o client_shared.o
	${CROSS_COMPILE}${CC} $^ -o $@ ${CLIENT_LDFLAGS}

pub_client.o : pub_client.c ../lib/libeecloud.so.${SOVERSION}
	${CROSS_COMPILE}${CC} -c $< -o $@ ${CLIENT_CFLAGS}

sub_client.o : sub_client.c ../lib/libeecloud.so.${SOVERSION}
	${CROSS_COMPILE}${CC} -c $< -o $@ ${CLIENT_CFLAGS}

client_shared.o : client_shared.c client_shared.h
	${CROSS_COMPILE}${CC} -c $< -o $@ ${CLIENT_CFLAGS}

../lib/libeecloud.so.${SOVERSION} :
	$(MAKE) -C ../lib

install : all
	$(INSTALL) -d ${DESTDIR}$(prefix)/bin
	$(INSTALL) -s --strip-program=${CROSS_COMPILE}${STRIP} eecloud_pub ${DESTDIR}${prefix}/bin/eecloud_pub
	$(INSTALL) -s --strip-program=${CROSS_COMPILE}${STRIP} eecloud_sub ${DESTDIR}${prefix}/bin/eecloud_sub

uninstall :
	-rm -f ${DESTDIR}${prefix}/bin/eecloud_pub
	-rm -f ${DESTDIR}${prefix}/bin/eecloud_sub

reallyclean : clean

clean : 
	-rm -f *.o eecloud_pub eecloud_sub
