include ../config.mk

.PHONY: all install uninstall clean reallyclean

ifeq ($(WITH_TLS),yes)
all : eecloud eecloud_passwd
else
all : eecloud
endif

eecloud : eecloud.o bridge.o conf.o context.o database.o logging.o loop.o memory_ecld.o persist.o net.o net_ecld.o read_handle.o read_handle_client.o read_handle_server.o read_handle_shared.o security.o security_default.o send_client_ecld.o send_ecld.o send_server.o service.o subs.o sys_tree.o time_ecld.o tls_ecld.o util_ecld.o websockets.o will_ecld.o
	${CROSS_COMPILE}${CC} $^ -o $@ ${LDFLAGS} $(BROKER_LIBS)

eecloud.o : eecloud.c eecloud_broker.h
	${CROSS_COMPILE}${CC} $(BROKER_CFLAGS) -c $< -o $@

bridge.o : bridge.c eecloud_broker.h
	${CROSS_COMPILE}${CC} $(BROKER_CFLAGS) -c $< -o $@
	
conf.o : conf.c eecloud_broker.h
	${CROSS_COMPILE}${CC} $(BROKER_CFLAGS) -c $< -o $@
	
context.o : context.c eecloud_broker.h
	${CROSS_COMPILE}${CC} $(BROKER_CFLAGS) -c $< -o $@

database.o : database.c eecloud_broker.h
	${CROSS_COMPILE}${CC} $(BROKER_CFLAGS) -c $< -o $@

logging.o : logging.c eecloud_broker.h
	${CROSS_COMPILE}${CC} $(BROKER_CFLAGS) -c $< -o $@

loop.o : loop.c eecloud_broker.h
	${CROSS_COMPILE}${CC} $(BROKER_CFLAGS) -c $< -o $@

memory_ecld.o : ../lib/memory_ecld.c ../lib/memory_ecld.h
	${CROSS_COMPILE}${CC} $(BROKER_CFLAGS) -c $< -o $@

net.o : net.c eecloud_broker.h
	${CROSS_COMPILE}${CC} $(BROKER_CFLAGS) -c $< -o $@

net_ecld.o : ../lib/net_ecld.c ../lib/net_ecld.h
	${CROSS_COMPILE}${CC} $(BROKER_CFLAGS) -c $< -o $@
	
persist.o : persist.c persist.h eecloud_broker.h
	${CROSS_COMPILE}${CC} $(BROKER_CFLAGS) -c $< -o $@
	
read_handle.o : read_handle.c eecloud_broker.h
	${CROSS_COMPILE}${CC} $(BROKER_CFLAGS) -c $< -o $@

read_handle_client.o : read_handle_client.c eecloud_broker.h
	${CROSS_COMPILE}${CC} $(BROKER_CFLAGS) -c $< -o $@

read_handle_server.o : read_handle_server.c eecloud_broker.h
	${CROSS_COMPILE}${CC} $(BROKER_CFLAGS) -c $< -o $@

read_handle_shared.o : ../lib/read_handle_shared.c ../lib/read_handle.h
	${CROSS_COMPILE}${CC} $(BROKER_CFLAGS) -c $< -o $@

security.o : security.c eecloud_broker.h
	${CROSS_COMPILE}${CC} $(BROKER_CFLAGS) -c $< -o $@

security_default.o : security_default.c eecloud_broker.h
	${CROSS_COMPILE}${CC} $(BROKER_CFLAGS) -c $< -o $@

send_client_ecld.o : ../lib/send_client_ecld.c ../lib/send_ecld.h
	${CROSS_COMPILE}${CC} $(BROKER_CFLAGS) -c $< -o $@

send_ecld.o : ../lib/send_ecld.c ../lib/send_ecld.h
	${CROSS_COMPILE}${CC} $(BROKER_CFLAGS) -c $< -o $@

send_server.o : send_server.c eecloud_broker.h
	${CROSS_COMPILE}${CC} $(BROKER_CFLAGS) -c $< -o $@

service.o : service.c eecloud_broker.h
	${CROSS_COMPILE}${CC} $(BROKER_CFLAGS) -c $< -o $@

subs.o : subs.c eecloud_broker.h
	${CROSS_COMPILE}${CC} $(BROKER_CFLAGS) -c $< -o $@

sys_tree.o : sys_tree.c eecloud_broker.h
	${CROSS_COMPILE}${CC} $(BROKER_CFLAGS) -c $< -o $@

time_ecld.o : ../lib/time_ecld.c ../lib/time_ecld.h
	${CROSS_COMPILE}${CC} $(BROKER_CFLAGS) -c $< -o $@

tls_ecld.o : ../lib/tls_ecld.c
	${CROSS_COMPILE}${CC} $(BROKER_CFLAGS) -c $< -o $@

util_ecld.o : ../lib/util_ecld.c ../lib/util_ecld.h
	${CROSS_COMPILE}${CC} $(BROKER_CFLAGS) -c $< -o $@

websockets.o : websockets.c eecloud_broker.h
	${CC} $(BROKER_CFLAGS) -c $< -o $@

will_ecld.o : ../lib/will_ecld.c ../lib/will_ecld.h
	${CROSS_COMPILE}${CC} $(BROKER_CFLAGS) -c $< -o $@

eecloud_passwd : eecloud_passwd.o
	${CROSS_COMPILE}${CC} $^ -o $@ ${LDFLAGS} $(PASSWD_LIBS)

eecloud_passwd.o : eecloud_passwd.c
	${CROSS_COMPILE}${CC} $(CFLAGS) ${CPPFLAGS} -c $< -o $@

install : all
	$(INSTALL) -d ${DESTDIR}$(prefix)/sbin
	$(INSTALL) -s --strip-program=${CROSS_COMPILE}${STRIP} eecloud ${DESTDIR}${prefix}/sbin/eecloud
	$(INSTALL) eecloud_plugin.h ${DESTDIR}${prefix}/include/eecloud_plugin.h
ifeq ($(WITH_TLS),yes)
	$(INSTALL) -s --strip-program=${CROSS_COMPILE}${STRIP} eecloud_passwd ${DESTDIR}${prefix}/bin/eecloud_passwd
endif

uninstall :
	-rm -f ${DESTDIR}${prefix}/sbin/eecloud
	-rm -f ${DESTDIR}${prefix}/include/eecloud_plugin.h
	-rm -f ${DESTDIR}${prefix}/bin/eecloud_passwd

clean : 
	-rm -f *.o eecloud eecloud_passwd

reallyclean : clean
	-rm -rf *.orig *.db
