include_directories(${eecloud_SOURCE_DIR}/lib
			${STDBOOL_H_PATH} ${STDINT_H_PATH})
link_directories(${eecloud_BINARY_DIR}/lib)

set(shared_src client_shared.c client_shared.h)

if (${WITH_SRV} STREQUAL ON)
	add_definitions("-DWITH_SRV")
endif (${WITH_SRV} STREQUAL ON)

add_executable(eecloud_pub pub_client.c ${shared_src})
add_executable(eecloud_sub sub_client.c ${shared_src})

target_link_libraries(eecloud_pub libeecloud)
target_link_libraries(eecloud_sub libeecloud)

install(TARGETS eecloud_pub RUNTIME DESTINATION ${BINDIR} LIBRARY DESTINATION ${LIBDIR})
install(TARGETS eecloud_sub RUNTIME DESTINATION ${BINDIR} LIBRARY DESTINATION ${LIBDIR})
