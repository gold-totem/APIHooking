cmake_minimum_required(VERSION 3.21)

if(DEFINED ENV{VCPKG_ROOT} AND NOT DEFINED CMAKE_TOOLCHAIN_FILE)
    set(CMAKE_TOOLCHAIN_FILE "$ENV{VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake"
        CACHE STRING "Vcpkg toolchain file")
endif()

set(OUTPUT_DIR "${CMAKE_SOURCE_DIR}/build/$<CONFIG>")

project(APIHooking LANGUAGES CXX)

add_definitions(-DUNICODE -D_UNICODE -DSPDLOG_NO_EXCEPTIONS)

set(PHNT_GIT_TAG "53fbbdc")

include(FetchContent)

find_package(spdlog CONFIG REQUIRED)

find_package(nlohmann_json CONFIG REQUIRED )


find_path(DETOURS_INCLUDE_DIRS "detours/detours.h")

find_library(DETOURS_LIBRARY_RELEASE
    NAMES detours
    PATHS "${_VCPKG_INSTALLED_DIR}/${VCPKG_TARGET_TRIPLET}/lib"
    NO_DEFAULT_PATH
)

find_library(DETOURS_LIBRARY_DEBUG
    NAMES detours
    PATHS "${_VCPKG_INSTALLED_DIR}/${VCPKG_TARGET_TRIPLET}/debug/lib"
    NO_DEFAULT_PATH
)

FetchContent_Declare(
    phnt
    GIT_REPOSITORY https://github.com/winsiderss/phnt.git
    GIT_TAG ${PHNT_GIT_TAG}
    GIT_SHALLOW FALSE
)

FetchContent_MakeAvailable(phnt)

if(TARGET phnt)
    target_compile_definitions(phnt INTERFACE
        PHNT_MODE=PHNT_MODE_USER
        PHNT_VERSION=PHNT_WIN11
    )
endif()

add_subdirectory(Sensor)
add_subdirectory(Injector)

