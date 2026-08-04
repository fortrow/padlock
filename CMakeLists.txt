cmake_minimum_required(VERSION 3.20)

project(padlock VERSION 0.1.0 LANGUAGES C)

include(GNUInstallDirs)
include(CTest)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

set(PADLOCK_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR})
set(PADLOCK_INCLUDE_DIR ${PADLOCK_SOURCE_DIR}/include)
set(PADLOCK_TPM_INCLUDE_DIR ${PADLOCK_SOURCE_DIR}/third_party/tpm2-tss/include)
set(PADLOCK_KERNEL_DIR ${PADLOCK_SOURCE_DIR}/kernel/guard)
execute_process(COMMAND uname -r OUTPUT_VARIABLE PADLOCK_KERNEL_RELEASE OUTPUT_STRIP_TRAILING_WHITESPACE)
set(PADLOCK_KERNEL_BUILD /lib/modules/${PADLOCK_KERNEL_RELEASE}/build)
set(TSS2_ESYS_LIB /usr/lib/x86_64-linux-gnu/libtss2-esys.so.0)
set(TSS2_MU_LIB /usr/lib/x86_64-linux-gnu/libtss2-mu.so.0)
set(TSS2_TCTILDR_LIB /usr/lib/x86_64-linux-gnu/libtss2-tctildr.so.0)
set(TSS2_TCTI_DEVICE_LIB /usr/lib/x86_64-linux-gnu/libtss2-tcti-device.so.0)

add_library(padlock_shared SHARED
    src/padlock.c
)
target_compile_definitions(padlock_shared PRIVATE PADLOCK_VERSION="${PROJECT_VERSION}")
target_include_directories(padlock_shared
    PUBLIC
        ${PADLOCK_INCLUDE_DIR}
    PRIVATE
        ${PADLOCK_TPM_INCLUDE_DIR}
)
target_link_libraries(padlock_shared PRIVATE crypto pam ${TSS2_ESYS_LIB} ${TSS2_MU_LIB} ${TSS2_TCTILDR_LIB} ${TSS2_TCTI_DEVICE_LIB})
set_target_properties(padlock_shared PROPERTIES
    OUTPUT_NAME padlock
    SOVERSION ${PROJECT_VERSION_MAJOR}
    VERSION ${PROJECT_VERSION}
)

add_library(padlock_static STATIC
    src/padlock.c
)
target_compile_definitions(padlock_static PRIVATE PADLOCK_VERSION="${PROJECT_VERSION}")
target_include_directories(padlock_static
    PUBLIC
        ${PADLOCK_INCLUDE_DIR}
    PRIVATE
        ${PADLOCK_TPM_INCLUDE_DIR}
)
set_target_properties(padlock_static PROPERTIES OUTPUT_NAME padlock)

add_executable(padlock
    src/padlock_cli.c
)
target_include_directories(padlock PRIVATE ${PADLOCK_INCLUDE_DIR} ${PADLOCK_TPM_INCLUDE_DIR})
target_link_libraries(padlock PRIVATE padlock_shared crypto pam ${TSS2_ESYS_LIB} ${TSS2_MU_LIB} ${TSS2_TCTILDR_LIB} ${TSS2_TCTI_DEVICE_LIB})
set_target_properties(padlock PROPERTIES
    BUILD_RPATH "$ORIGIN"
    INSTALL_RPATH "$ORIGIN"
)

add_executable(padlock_test
    tests/padlock_test.c
)
target_include_directories(padlock_test PRIVATE ${PADLOCK_INCLUDE_DIR} ${PADLOCK_TPM_INCLUDE_DIR})
target_link_libraries(padlock_test PRIVATE padlock_shared crypto pam ${TSS2_ESYS_LIB} ${TSS2_MU_LIB} ${TSS2_TCTILDR_LIB} ${TSS2_TCTI_DEVICE_LIB})
set_target_properties(padlock_test PROPERTIES BUILD_RPATH "$ORIGIN")

enable_testing()
add_test(NAME padlock_test COMMAND padlock_test)

add_custom_target(guard
    COMMAND ${CMAKE_MAKE_PROGRAM} -C ${PADLOCK_KERNEL_BUILD} M=${PADLOCK_KERNEL_DIR} modules
    USES_TERMINAL
)

add_custom_target(guard-clean
    COMMAND ${CMAKE_MAKE_PROGRAM} -C ${PADLOCK_KERNEL_BUILD} M=${PADLOCK_KERNEL_DIR} clean
    USES_TERMINAL
)

install(TARGETS padlock_shared padlock_static padlock
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

install(FILES
    include/hardcode/padlock.h
    include/hardcode/padlock_guard.h
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/hardcode
)
