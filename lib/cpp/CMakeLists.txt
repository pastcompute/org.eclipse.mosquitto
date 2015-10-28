include_directories(${eecloud_SOURCE_DIR}/lib ${eecloud_SOURCE_DIR}/lib/cpp
			${STDBOOL_H_PATH} ${STDINT_H_PATH})
link_directories(${eecloud_BINARY_DIR}/lib)

add_library(eecloudpp SHARED
	eecloudpp.cpp eecloudpp.h)

target_link_libraries(eecloudpp libeecloud)
set_target_properties(eecloudpp PROPERTIES
	VERSION ${VERSION}
	SOVERSION 1
)
install(TARGETS eecloudpp RUNTIME DESTINATION ${BINDIR} LIBRARY DESTINATION ${LIBDIR})
install(FILES eecloudpp.h DESTINATION ${INCLUDEDIR})

if (UNIX)
	install(CODE "EXEC_PROGRAM(/sbin/ldconfig)")
endif (UNIX)
