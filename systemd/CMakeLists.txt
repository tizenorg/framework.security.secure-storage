INSTALL(FILES
    ${CMAKE_SOURCE_DIR}/systemd/ss-server.socket
    ${CMAKE_SOURCE_DIR}/systemd/secure-storage.service
    DESTINATION ${SYSTEMD_UNIT_DIR}
    )
