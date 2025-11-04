# Copyright (c) Microsoft Corporation. All rights reserved.
# SPDX-License-Identifier: MIT

set(SOURCE_FILES
    "enclave.c"
    "sample_enclave.cpp"
)

add_library(vbsenclave SHARED ${SOURCE_FILES})

target_include_directories(vbsenclave PRIVATE
    "${ATTEST_PACKAGE_DIR}/inc"
)

target_link_libraries(vbsenclave PRIVATE
        "$ENV{VCToolsInstallDir}lib/$ENV{VSCMD_ARG_TGT_ARCH}/enclave/libcmt.lib"
        "$ENV{VCToolsInstallDir}lib/$ENV{VSCMD_ARG_TGT_ARCH}/enclave/libvcruntime.lib"
        "$ENV{WindowsSdkDir}Lib/$ENV{WindowsSDKLibVersion}um/$ENV{VSCMD_ARG_TGT_ARCH}/bcrypt.lib"
        "$ENV{WindowsSdkDir}Lib/$ENV{WindowsSDKLibVersion}um/$ENV{VSCMD_ARG_TGT_ARCH}/vertdll.lib"
        "$ENV{WindowsSdkDir}Lib/$ENV{WindowsSDKLibVersion}ucrt_enclave/$ENV{VSCMD_ARG_TGT_ARCH}/ucrt.lib"
        "${ATTEST_PACKAGE_DIR}/lib/AzureAttest.lib"
    )

target_link_options(vbsenclave PRIVATE
    /INCREMENTAL:NO
    /NODEFAULTLIB
    /DEF:${CMAKE_CURRENT_SOURCE_DIR}/vbsenclave.def
    /INTEGRITYCHECK
    /ENCLAVE
    /GUARD:MIXED
)

add_custom_command(TARGET vbsenclave POST_BUILD
    COMMAND "$ENV{WindowsSdkVerBinPath}$ENV{VSCMD_ARG_HOST_ARCH}/veiid.exe" "$<TARGET_FILE:vbsenclave>" 
    COMMENT "Applying VEIID Protection"
)

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options(vbsenclave PRIVATE /Zi)

    string(REPLACE "/RTC1" "" CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG}")
    string(REPLACE "/RTC1" "" CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG}")
    set (CMAKE_SHARED_LINKER_FLAGS_DEBUG "/DEBUG /INCREMENTAL:NO" CACHE STRING "Overriding default debug ${flag_type} linker flags." FORCE)
endif()

 install(TARGETS vbsenclave DESTINATION "${CMAKE_BINARY_DIR}/attestation")
 install(FILES $<TARGET_PDB_FILE:vbsenclave> DESTINATION "${CMAKE_BINARY_DIR}/attestation" OPTIONAL)