# Copyright (c) Microsoft Corporation. All rights reserved.
# SPDX-License-Identifier: MIT

set(ATTEST_PACKAGE_DIR "${CMAKE_BINARY_DIR}/packages/Microsoft.Attestation.Client" CACHE STRING "")

macro (define_sample samplename is_enclave)

    project(attestation-${samplename})

    include_directories("${ATTEST_PACKAGE_DIR}/inc/${ATTEST_PACKAGE_ARCH}")

    add_executable(
        attestation-${samplename}
        ${samplename}.cpp
        attest.cpp 
        utils.cpp)

    target_link_libraries(attestation-${samplename} PRIVATE ncrypt)

    set_property(TARGET attestation-${samplename} PROPERTY CXX_STANDARD 20)

    find_package(azure-identity-cpp CONFIG REQUIRED)
    find_package(azure-security-attestation-cpp CONFIG REQUIRED)
    target_link_libraries(attestation-${samplename} PRIVATE "${ATTEST_PACKAGE_DIR}/lib/${ATTEST_PACKAGE_ARCH}/azure-attest-manager.lib" Azure::azure-identity Azure::azure-security-attestation)

    install(
        FILES "${ATTEST_PACKAGE_DIR}/bin/${ATTEST_PACKAGE_ARCH}/azure-attest-manager.dll" "${ATTEST_PACKAGE_DIR}/bin/${ATTEST_PACKAGE_ARCH}/AzureAttestManager.dll" "${ATTEST_PACKAGE_DIR}/bin/${ATTEST_PACKAGE_ARCH}/AzureAttestNormal.dll"
        DESTINATION "${CMAKE_CURRENT_BINARY_DIR}"
    )

    # Install the runtime dependencies (OpenSSL and TPM2-TSS DLLs) shipped in the package.
    file(GLOB ATTEST_DEP_DLLS "${ATTEST_PACKAGE_DIR}/deps/${ATTEST_PACKAGE_ARCH}/*.dll")
    install(
        FILES ${ATTEST_DEP_DLLS}
        DESTINATION "${CMAKE_CURRENT_BINARY_DIR}"
    )
  
    if("${is_enclave}" STREQUAL "TRUE")
        target_link_libraries(attestation-${samplename} PRIVATE onecore.lib)

        install(
            FILES "${ATTEST_PACKAGE_DIR}/bin/${ATTEST_PACKAGE_ARCH}/AzureAttest.dll"
            DESTINATION "${CMAKE_CURRENT_BINARY_DIR}"
        )
    endif()
endmacro()

define_sample(sample_boot_att FALSE)
define_sample(sample_tpm_key_att FALSE)
define_sample(sample_enclave_att TRUE)