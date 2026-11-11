cmake_minimum_required(VERSION 3.20)
project(WfsManager LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_compile_definitions(NOMINMAX _CRT_SECURE_NO_WARNINGS)

include_directories(include)

set(COMMON_SOURCES
    src/WfsCrypto.cpp
    src/WfsDiskDevice.cpp
    src/WfsBlockAllocator.cpp
    src/WfsTransaction.cpp
    src/WfsFileSystem.cpp
    src/WfsTitleManager.cpp
    src/WfsSafetyGuard.cpp
    src/WfsDriveHealth.cpp
)

# CLI Management Executable
add_executable(wfsmanager
    ${COMMON_SOURCES}
    src/main.cpp
)

# Unit & Integrity Test Suite
add_executable(test_wfs
    ${COMMON_SOURCES}
    tests/test_wfs.cpp
)

if (MSVC)
    target_compile_options(wfsmanager PRIVATE /W4 /permissive-)
    target_compile_options(test_wfs PRIVATE /W4 /permissive-)
else()
    target_compile_options(wfsmanager PRIVATE -Wall -Wextra -pedantic)
    target_compile_options(test_wfs PRIVATE -Wall -Wextra -pedantic)
endif()

