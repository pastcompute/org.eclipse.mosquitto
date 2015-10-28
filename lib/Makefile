include ../config.mk

.PHONY : really clean install

ECLD_OBJS=eecloud.o \
		  logging_ecld.o \
		  memory_ecld.o \
		  messages_ecld.o \
		  net_ecld.o \
		  read_handle.o \
		  read_handle_client.o \
		  read_handle_shared.o \
		  send_ecld.o \
		  send_client_ecld.o \
		  socks_ecld.o \
		  srv_ecld.o \
		  thread_ecld.o \
		  time_ecld.o \
		  tls_ecld.o \
		  util_ecld.o \
		  will_ecld.o

all : libeecloud.so.${SOVERSION} libeecloud.a
	$(MAKE) -C cpp

install : all
	$(INSTALL) -d ${DESTDIR}$(prefix)/lib${LIB_SUFFIX}/
	$(INSTALL) -s --strip-program=${CROSS_COMPILE}${STRIP} libeecloud.so.${SOVERSION} ${DESTDIR}${prefix}/lib${LIB_SUFFIX}/libeecloud.so.${SOVERSION}
	ln -sf libeecloud.so.${SOVERSION} ${DESTDIR}${prefix}/lib${LIB_SUFFIX}/libeecloud.so
	$(INSTALL) -d ${DESTDIR}${prefix}/include/
	$(INSTALL) eecloud.h ${DESTDIR}${prefix}/include/eecloud.h
	$(MAKE) -C cpp install

uninstall :
	-rm -f ${DESTDIR}${prefix}/lib${LIB_SUFFIX}/libeecloud.so.${SOVERSION}
	-rm -f ${DESTDIR}${prefix}/lib${LIB_SUFFIX}/libeecloud.so
	-rm -f ${DESTDIR}${prefix}/include/eecloud.h

reallyclean : clean

clean :
	-rm -f *.o libeecloud.so.${SOVERSION} libeecloud.so libeecloud.a
	$(MAKE) -C cpp clean

libeecloud.so.${SOVERSION} : ${ECLD_OBJS}
	${CROSS_COMPILE}$(CC) -shared $(LIB_LDFLAGS) $^ -o $@ ${LIB_LIBS}

libeecloud.a : ${ECLD_OBJS}
	${CROSS_COMPILE}$(AR) cr $@ $^
eecloud.o : eecloud.c eecloud.h
	${CROSS_COMPILE}$(CC) $(LIB_CFLAGS) -c $< -o $@

logging_ecld.o : logging_ecld.c logging_ecld.h
	${CROSS_COMPILE}$(CC) $(LIB_CFLAGS) -c $< -o $@

messages_ecld.o : messages_ecld.c messages_ecld.h
	${CROSS_COMPILE}$(CC) $(LIB_CFLAGS) -c $< -o $@

memory_ecld.o : memory_ecld.c memory_ecld.h
	${CROSS_COMPILE}$(CC) $(LIB_CFLAGS) -c $< -o $@

net_ecld.o : net_ecld.c net_ecld.h
	${CROSS_COMPILE}$(CC) $(LIB_CFLAGS) -c $< -o $@

read_handle.o : read_handle.c read_handle.h
	${CROSS_COMPILE}$(CC) $(LIB_CFLAGS) -c $< -o $@

read_handle_client.o : read_handle_client.c read_handle.h
	${CROSS_COMPILE}$(CC) $(LIB_CFLAGS) -c $< -o $@

read_handle_shared.o : read_handle_shared.c read_handle.h
	${CROSS_COMPILE}$(CC) $(LIB_CFLAGS) -c $< -o $@

send_ecld.o : send_ecld.c send_ecld.h
	${CROSS_COMPILE}$(CC) $(LIB_CFLAGS) -c $< -o $@

send_client_ecld.o : send_client_ecld.c send_ecld.h
	${CROSS_COMPILE}$(CC) $(LIB_CFLAGS) -c $< -o $@

socks_ecld.o : socks_ecld.c
	${CROSS_COMPILE}$(CC) $(LIB_CFLAGS) -c $< -o $@

srv_ecld.o : srv_ecld.c
	${CROSS_COMPILE}$(CC) $(LIB_CFLAGS) -c $< -o $@

thread_ecld.o : thread_ecld.c
	${CROSS_COMPILE}$(CC) $(LIB_CFLAGS) -c $< -o $@

time_ecld.o : time_ecld.c
	${CROSS_COMPILE}$(CC) $(LIB_CFLAGS) -c $< -o $@

tls_ecld.o : tls_ecld.c
	${CROSS_COMPILE}$(CC) $(LIB_CFLAGS) -c $< -o $@

util_ecld.o : util_ecld.c util_ecld.h
	${CROSS_COMPILE}$(CC) $(LIB_CFLAGS) -c $< -o $@

will_ecld.o : will_ecld.c will_ecld.h
	${CROSS_COMPILE}$(CC) $(LIB_CFLAGS) -c $< -o $@

