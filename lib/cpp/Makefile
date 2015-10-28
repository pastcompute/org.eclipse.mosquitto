include ../../config.mk

ifneq ($(UNAME),SunOS)
	LIB_LDFLAGS:=$(LDFLAGS) -Wl,-soname,libeecloudpp.so.${SOVERSION}
endif

.PHONY : clean install

all : libeecloudpp.so.${SOVERSION}

install : all
	$(INSTALL) -d ${DESTDIR}$(prefix)/lib${LIB_SUFFIX}/
	$(INSTALL) -s --strip-program=${CROSS_COMPILE}${STRIP} libeecloudpp.so.${SOVERSION} ${DESTDIR}${prefix}/lib${LIB_SUFFIX}/libeecloudpp.so.${SOVERSION}
	ln -sf libeecloudpp.so.${SOVERSION} ${DESTDIR}${prefix}/lib${LIB_SUFFIX}/libeecloudpp.so
	$(INSTALL) -d ${DESTDIR}${prefix}/include/
	$(INSTALL) eecloudpp.h ${DESTDIR}${prefix}/include/eecloudpp.h
	
uninstall :
	-rm -f ${DESTDIR}${prefix}/lib${LIB_SUFFIX}/libeecloudpp.so.${SOVERSION}
	-rm -f ${DESTDIR}${prefix}/lib${LIB_SUFFIX}/libeecloudpp.so
	-rm -f ${DESTDIR}${prefix}/include/eecloudpp.h

clean :
	-rm -f *.o libeecloudpp.so.${SOVERSION}

libeecloudpp.so.${SOVERSION} : eecloudpp.o
	${CROSS_COMPILE}$(CXX) -shared $(LIB_LDFLAGS) $< -o $@ ../libeecloud.so.${SOVERSION}

eecloudpp.o : eecloudpp.cpp eecloudpp.h
	${CROSS_COMPILE}$(CXX) $(LIB_CXXFLAGS) -c $< -o $@

