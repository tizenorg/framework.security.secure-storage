CONFIGURE_FILE(config.in config @ONLY)

INSTALL(FILES ${PROJECT_SOURCE_DIR}/res/config
    DESTINATION share/secure-storage/)
INSTALL(FILES ${PROJECT_SOURCE_DIR}/res/salt
    DESTINATION ../opt/share/secure-storage/)
