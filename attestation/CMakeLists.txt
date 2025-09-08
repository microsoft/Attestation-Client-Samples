# Copyright (c) Microsoft Corporation. All rights reserved.
# SPDX-License-Identifier: MIT

set(CMAKE_SYSTEM_VERSION 10.0)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED YES)

set(ATTEST_PACKAGE_DIR "${CMAKE_BINARY_DIR}/packages/Microsoft.Attestation.Client" CACHE STRING "")

macro (define_sample samplename)

    project(attestation-${samplename})

    include_directories("${ATTEST_PACKAGE_DIR}/inc")

    add_executable(
        attestation-${samplename}
        ${samplename}.cpp
        attest.cpp 
        utils.cpp)

    target_link_libraries(attestation-${samplename} PRIVATE ncrypt)

    set_property(TARGET attestation-${samplename} PROPERTY CXX_STANDARD 20)

    find_package(azure-identity-cpp CONFIG REQUIRED)
    find_package(azure-security-attestation-cpp CONFIG REQUIRED)
    target_link_libraries(attestation-${samplename} PRIVATE "${ATTEST_PACKAGE_DIR}/lib/azure-attest-manager.lib" Azure::azure-identity Azure::azure-security-attestation)

    install(
        FILES "${ATTEST_PACKAGE_DIR}/bin/azure-attest-manager.dll" "${ATTEST_PACKAGE_DIR}/bin/AzureAttestManager.dll" "${ATTEST_PACKAGE_DIR}/bin/AzureAttestNormal.dll" "${ATTEST_PACKAGE_DIR}/bin/AzureAttest.dll"
        DESTINATION "${CMAKE_CURRENT_BINARY_DIR}"
    )

endmacro()

define_sample(sample_boot_att)
define_sample(sample_tpm_key_att)


if (WIN32)
    set_property(GLOBAL PROPERTY USE_FOLDERS ON)
endif()


find_package(azure-identity-cpp CONFIG REQUIRED)
find_package(azure-security-attestation-cpp CONFIG REQUIRED)


set(
    HostLibs
    kernel32.lib
    bcrypt.lib
    user32.lib
    onecore.lib
    ncrypt
    "${ATTEST_PACKAGE_DIR}/lib/azure-attest-manager.lib"
    Azure::azure-identity
    Azure::azure-security-attestation
)

set(
    HostSources
    "${CMAKE_CURRENT_SOURCE_DIR}/sample_enclave_att.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/attest.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/utils.cpp"
)


set(
    HostIncs
    "${CMAKE_SOURCE_DIR}/wil/include/"
    "${ATTEST_PACKAGE_DIR}/inc"
    "${CMAKE_CURRENT_SOURCE_DIR}"
)

message(STATUS "Include directories: ${HostIncs}")

message(STATUS "CMAKE_CURRENT_SOURCE_DIR: ${CMAKE_CURRENT_SOURCE_DIR}")

set(
    bintarget
    attestation-sample_enclave_att
    )


add_executable(
    ${bintarget}
    ${HostSources}
    )


if (WIN32)
    target_precompile_headers(
        ${bintarget}
        PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/precomp.h"
        )
endif()

target_link_libraries(
    ${bintarget}
    PRIVATE
    ${HostLibs}
    )

target_include_directories(
    ${bintarget}
    PRIVATE
    ${HostIncs}
    )


set_target_properties( ${bintarget} PROPERTIES WIN32_EXECUTABLE OFF)

target_compile_definitions(
    ${bintarget}
    PRIVATE
    ${UCRTSETTINGS_CL_PREPROCESSOR_DEFS_COMMON}
    )



if(WIN32)
    target_compile_options(
        ${bintarget}
        PRIVATE
        "${UCRTSETTINGS_CL_FLAGS_COMMON}"
        "${UCRTSETTINGS_CL_FLAGS_CXX}"
        )
        
    target_link_options(
        ${bintarget}
        PRIVATE /SUBSYSTEM:CONSOLE
        )
endif()

install(
    TARGETS ${bintarget}
    RUNTIME
    DESTINATION "${CMAKE_CURRENT_BINARY_DIR}"
    )
