add_subdirectory(cpp)

option(WITH_THREADING "Include client library threading support?" ON)
if (${WITH_THREADING} STREQUAL ON)
	add_definitions("-DWITH_THREADING")
	if (WIN32)
		set (PTHREAD_LIBRARIES C:\\pthreads\\Pre-built.2\\lib\\x86\\pthreadVC2.lib)
		set (PTHREAD_INCLUDE_DIR C:\\pthreads\\Pre-built.2\\include)
	else (WIN32)
		set (PTHREAD_LIBRARIES pthread)
		set (PTHREAD_INCLUDE_DIR "")
	endif (WIN32)
else (${WITH_THREADING} STREQUAL ON)
	set (PTHREAD_LIBRARIES "")
	set (PTHREAD_INCLUDE_DIR "")
endif (${WITH_THREADING} STREQUAL ON)

include_directories(${eecloud_SOURCE_DIR} ${eecloud_SOURCE_DIR}/lib
			${STDBOOL_H_PATH} ${STDINT_H_PATH}
			${OPENSSL_INCLUDE_DIR} ${PTHREAD_INCLUDE_DIR})
link_directories(${eecloud_SOURCE_DIR}/lib)

add_library(libeecloud SHARED
	logging_ecld.c logging_ecld.h
	memory_ecld.c memory_ecld.h
	messages_ecld.c messages_ecld.h
	eecloud.c eecloud.h
	eecloud_internal.h
	mqtt3_protocol.h
	net_ecld.c net_ecld.h
	read_handle.c read_handle.h
	read_handle_client.c
	read_handle_shared.c
	send_client_ecld.c
	send_ecld.c send_ecld.h
	socks_ecld.c
	srv_ecld.c
	thread_ecld.c
	time_ecld.c
	tls_ecld.c
	util_ecld.c util_ecld.h
	will_ecld.c will_ecld.h)

set (LIBRARIES ${OPENSSL_LIBRARIES} ${PTHREAD_LIBRARIES})

if (UNIX AND NOT APPLE)
	set (LIBRARIES ${LIBRARIES} rt)
endif (UNIX AND NOT APPLE)

if (WIN32)
	set (LIBRARIES ${LIBRARIES} ws2_32)
endif (WIN32)

if (${WITH_SRV} STREQUAL ON)
	# Simple detect c-ares
	find_path(ARES_HEADER ares.h)
	if (ARES_HEADER)
		add_definitions("-DWITH_SRV")
		set (LIBRARIES ${LIBRARIES} cares)
	else (ARES_HEADER)
		message(WARNING "c-ares library not found.")
	endif (ARES_HEADER)
endif (${WITH_SRV} STREQUAL ON)

target_link_libraries(libeecloud ${LIBRARIES})

set_target_properties(libeecloud PROPERTIES
	OUTPUT_NAME eecloud
	VERSION ${VERSION}
	SOVERSION 1
)

install(TARGETS libeecloud RUNTIME DESTINATION ${BINDIR} LIBRARY DESTINATION ${LIBDIR})
install(FILES eecloud.h DESTINATION ${INCLUDEDIR})

if (UNIX)
	install(CODE "EXEC_PROGRAM(/sbin/ldconfig)")
endif (UNIX)
