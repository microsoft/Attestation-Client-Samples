cmake_minimum_required(VERSION 3.15)

project(enclave LANGUAGES C)

set(CMAKE_GENERATOR_TOOLSET v143)

set(CMAKE_GENERATOR_PLATFORM x64)

set(SOURCE_FILES
    "enclave.c"
    "sample_enclave.cpp"
)
set(PRECOMPILED_HEADER precomp.h)

add_library(vbsenclave SHARED ${SOURCE_FILES})

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreadedDebugDLL")
else()
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreadedDLL")
endif()

target_include_directories(vbsenclave PRIVATE
    "$ENV{VCToolsInstallDir}include"
    "$ENV{WindowsSdkDir}Include/$ENV{WindowsSDKVersion}ucrt"
    "$ENV{WindowsSdkDir}Include/$ENV{WindowsSDKVersion}um"
    "$ENV{WindowsSdkDir}Include/$ENV{WindowsSDKVersion}shared"
    "$ENV{WindowsSdkDir}Include/$ENV{WindowsSDKVersion}winrt"
    "$ENV{WindowsSdkDir}Include/$ENV{WindowsSDKVersion}cppwinrt"
    "C:/Attestation-Client-Samples/AzureAttest/inc"
)

target_link_libraries(vbsenclave PRIVATE
        "$ENV{VCToolsInstallDir}lib/$ENV{VSCMD_ARG_TGT_ARCH}/enclave/libcmt.lib"
        "$ENV{VCToolsInstallDir}lib/$ENV{VSCMD_ARG_TGT_ARCH}/enclave/libvcruntime.lib"
        "$ENV{WindowsSdkDir}Lib/$ENV{WindowsSDKLibVersion}um/$ENV{VSCMD_ARG_TGT_ARCH}/bcrypt.lib"
        "$ENV{WindowsSdkDir}Lib/$ENV{WindowsSDKLibVersion}um/$ENV{VSCMD_ARG_TGT_ARCH}/vertdll.lib"
        "$ENV{WindowsSdkDir}Lib/$ENV{WindowsSDKLibVersion}ucrt_enclave/$ENV{VSCMD_ARG_TGT_ARCH}/ucrt.lib"
        "C:/Attestation-Client-Samples/AzureAttest/lib/AzureAttest.lib"
    )

target_link_options(vbsenclave PRIVATE /NODEFAULTLIB)

target_precompile_headers(vbsenclave PRIVATE ${PRECOMPILED_HEADER})

target_compile_options(vbsenclave PRIVATE
    /JMC /permissive- /Zi /Od /sdl
    /D_DEBUG /D_CONSOLE /D_WINDLL /D_UNICODE /DUNICODE
    /W3 /WX- /diagnostics:column /Gm- /EHsc /MDd /GS /fp:precise
    /Zc:wchar_t /Zc:forScope /Zc:inline
)

target_link_options(vbsenclave PRIVATE
    /ERRORREPORT:PROMPT
    #/INCREMENTAL:NO
    /NOLOGO
    /NODEFAULTLIB
    /DEF:${CMAKE_CURRENT_SOURCE_DIR}/vbsenclave.def
    /MANIFEST
    /MANIFESTUAC:"level='asInvoker' uiAccess='false'"
    /MANIFEST:embed
    /DEBUG
    /PDB:${CMAKE_BINARY_DIR}/attestation/vbsenclave.pdb
    /SUBSYSTEM:CONSOLE
    /TLBID:1
    /DYNAMICBASE
    /NXCOMPAT
    /IMPLIB:${CMAKE_BINARY_DIR}/attestation/vbsenclave.lib
    /MACHINE:X64
    /INTEGRITYCHECK
    /ENCLAVE
    /GUARD:MIXED
    /DLL
)

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    set_target_properties(vbsenclave PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/attestation
        LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib
        COMPILE_PDB_NAME vbsenclave
        COMPILE_PCH vbsenclave.pch
    )

else()
    set_target_properties(vbsenclave PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/attestation
        LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib
        COMPILE_PCH vbsenclave.pch
    )
endif()

set_target_properties(vbsenclave PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/attestation
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib
    COMPILE_PDB_NAME vbsenclave
    COMPILE_PCH vbsenclave.pch
)

add_custom_command(TARGET vbsenclave POST_BUILD
    COMMAND "$ENV{WindowsSdkVerBinPath}$ENV{VSCMD_ARG_HOST_ARCH}/veiid.exe" "${CMAKE_BINARY_DIR}/attestation/vbsenclave.dll"
    COMMENT "Applying VEIID Protection"
)

string(REPLACE "/RTC1" "" CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG}")
string(REPLACE "/RTC1" "" CMAKE_CXX_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG}")
set (CMAKE_SHARED_LINKER_FLAGS_DEBUG "/DEBUG /INCREMENTAL:NO" CACHE STRING "Overriding default debug ${flag_type} linker flags." FORCE)