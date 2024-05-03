# Copyright (c) Microsoft Corporation. All rights reserved.
# SPDX-License-Identifier: MIT

cmake_minimum_required (VERSION 3.12)

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
        FILES "${ATTEST_PACKAGE_DIR}/bin/azure-attest-manager.dll" "${ATTEST_PACKAGE_DIR}/bin/AzureAttestManager.dll" "${ATTEST_PACKAGE_DIR}/bin/AzureAttestNormal.dll"
        DESTINATION "${CMAKE_CURRENT_BINARY_DIR}"
    )

endmacro()

define_sample(sample_boot_att)
define_sample(sample_tpm_key_att)
define_sample(sample_vbs_ncrypt_att)
