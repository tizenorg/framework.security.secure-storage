PKG_CHECK_MODULES(SS_SERVER_DEP
    REQUIRED
    capi-base-common
    dlog
    libsystemd-daemon
    sqlite3
    db-util
    security-server
    )

SET(SS_SERVER_PATH   ${CMAKE_CURRENT_SOURCE_DIR}/secure-storage)
SET(PRNG_PATH        ${CMAKE_CURRENT_SOURCE_DIR}/prng)

SET(SS_SERVER_SOURCES
    ${SS_SERVER_PATH}/src/ss_server_ipc.c
    ${SS_SERVER_PATH}/src/ss_server_main.c
    ${PRNG_PATH}/src/ss_prng.c
    )

SET_SOURCE_FILES_PROPERTIES(
    ${SS_SERVER_SOURCES}
    PROPERTIES
        COMPILE_FLAGS "-D_GNU_SOURCE -fvisibility=hidden -fPIE"
    )

INCLUDE_DIRECTORIES(
    SYSTEM
    ${SS_SERVER_DEP_INCLUDE_DIRS}
    ${PROJECT_SOURCE_DIR}/include
    ${SS_SERVER_PATH}/include
    ${PRNG_PATH}/include
    )

ADD_EXECUTABLE(${TARGET_SS_SERVER} ${SS_SERVER_SOURCES})

TARGET_LINK_LIBRARIES(${TARGET_SS_SERVER}
    ${SS_SERVER_DEP_LIBRARIES}
    -ldl
    -pie
    )

INSTALL(TARGETS ${TARGET_SS_SERVER} DESTINATION bin)
