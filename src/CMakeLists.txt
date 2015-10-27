include_directories(${eecloud_SOURCE_DIR} ${eecloud_SOURCE_DIR}/src
		${eecloud_SOURCE_DIR}/lib ${OPENSSL_INCLUDE_DIR}
		${STDBOOL_H_PATH} ${STDINT_H_PATH})

set (MOSQ_SRCS
	conf.c
	context.c
	database.c
	lib_load.h
	logging.c
	loop.c
	../lib/memory_ecld.c ../lib/memory_ecld.h
	eecloud.c
	eecloud_broker.h
	net.c
	../lib/net_ecld.c ../lib/net_ecld.h
	persist.c persist.h
	read_handle.c read_handle_client.c read_handle_server.c
	../lib/read_handle_shared.c ../lib/read_handle.h
	subs.c
	security.c security_default.c
	../lib/send_client_ecld.c ../lib/send_ecld.h
	../lib/send_ecld.c ../lib/send_ecld.h
	send_server.c
	sys_tree.c
	../lib/time_ecld.c
	../lib/tls_ecld.c
	../lib/util_ecld.c ../lib/util_ecld.h
	websockets.c
	../lib/will_ecld.c ../lib/will_ecld.h)

option(INC_BRIDGE_SUPPORT
	"Include bridge support for connecting to other brokers?" ON)
if (${INC_BRIDGE_SUPPORT} STREQUAL ON)
	set (MOSQ_SRCS ${MOSQ_SRCS} bridge.c)
	add_definitions("-DWITH_BRIDGE")
endif (${INC_BRIDGE_SUPPORT} STREQUAL ON)


option(USE_LIBWRAP
	"Include tcp-wrappers support?" OFF)

if (${USE_LIBWRAP} STREQUAL ON)
	set (MOSQ_LIBS ${MOSQ_LIBS} wrap)
	add_definitions("-DWITH_WRAP")
endif (${USE_LIBWRAP} STREQUAL ON)

option(INC_DB_UPGRADE
	"Include database upgrade support? (recommended)" ON)

option(INC_MEMTRACK
	"Include memory tracking support?" ON)
if (${INC_MEMTRACK} STREQUAL ON)
	add_definitions("-DWITH_MEMORY_TRACKING")
endif (${INC_MEMTRACK} STREQUAL ON)

option(WITH_PERSISTENCE
	"Include persistence support?" ON)
if (${WITH_PERSISTENCE} STREQUAL ON)
	add_definitions("-DWITH_PERSISTENCE")
endif (${WITH_PERSISTENCE} STREQUAL ON)

option(WITH_SYS_TREE
	"Include $SYS tree support?" ON)
if (${WITH_SYS_TREE} STREQUAL ON)
	add_definitions("-DWITH_SYS_TREE")
endif (${WITH_SYS_TREE} STREQUAL ON)

option(WITH_WEBSOCKETS
	"Include websockets support?" OFF)
if (${WITH_WEBSOCKETS} STREQUAL ON)
	add_definitions("-DWITH_WEBSOCKETS")
endif (${WITH_WEBSOCKETS} STREQUAL ON)

if (WIN32 OR CYGWIN)
	set (MOSQ_SRCS ${MOSQ_SRCS} service.c)
endif (WIN32 OR CYGWIN)

add_definitions (-DWITH_BROKER)

add_executable(eecloud ${MOSQ_SRCS})

set (MOSQ_LIBS ${MOSQ_LIBS} ${OPENSSL_LIBRARIES})

if (UNIX)
	if (APPLE)
		set (MOSQ_LIBS ${MOSQ_LIBS} dl m)
	else (APPLE)
		set (MOSQ_LIBS ${MOSQ_LIBS} rt dl m)
	endif (APPLE)
endif (UNIX)

if (WIN32)
	set (MOSQ_LIBS ${MOSQ_LIBS} ws2_32)
endif (WIN32)

if (${WITH_WEBSOCKETS} STREQUAL ON)
	set (MOSQ_LIBS ${MOSQ_LIBS} websockets)
endif (${WITH_WEBSOCKETS} STREQUAL ON)

# Simple detect libuuid
if(NOT APPLE)
	FIND_PATH(UUID_HEADER uuid/uuid.h)
	if (UUID_HEADER)
		add_definitions(-DWITH_UUID)
		set (MOSQ_LIBS ${MOSQ_LIBS} uuid)
	endif (UUID_HEADER)
endif(NOT APPLE)

target_link_libraries(eecloud ${MOSQ_LIBS})

if (UNIX)
	if (APPLE)
		set_target_properties(eecloud PROPERTIES LINK_FLAGS "-Wl,-exported_symbols_list -Wl,${eecloud_SOURCE_DIR}/src/linker-macosx.syms")
	else (APPLE)
		set_target_properties(eecloud PROPERTIES LINK_FLAGS "-Wl,-dynamic-list=${eecloud_SOURCE_DIR}/src/linker.syms")
	endif (APPLE)
endif (UNIX)

install(TARGETS eecloud RUNTIME DESTINATION ${SBINDIR} LIBRARY DESTINATION ${LIBDIR})
install(FILES eecloud_plugin.h DESTINATION ${INCLUDEDIR})

if (${WITH_TLS} STREQUAL ON)
	add_executable(eecloud_passwd eecloud_passwd.c)
	target_link_libraries(eecloud_passwd ${OPENSSL_LIBRARIES})
	install(TARGETS eecloud_passwd RUNTIME DESTINATION ${BINDIR} LIBRARY DESTINATION ${LIBDIR})
endif (${WITH_TLS} STREQUAL ON)

if (UNIX)
	install(CODE "EXEC_PROGRAM(/sbin/ldconfig)")
endif (UNIX)

