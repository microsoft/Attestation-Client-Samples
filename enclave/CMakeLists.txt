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

set(VS_INSTALL_PATH "$ENV{VSINSTALLDIR}")

# Find the latest MSVC version dynamically
file(GLOB MSVC_VERSIONS LIST_DIRECTORIES true "${VS_INSTALL_PATH}/VC/Tools/MSVC/*")
list(SORT MSVC_VERSIONS COMPARE NATURAL ORDER DESCENDING)
list(GET MSVC_VERSIONS 0 MSVC_LATEST)
get_filename_component(MSVC_VERSION ${MSVC_LATEST} NAME)

set(MSVC_INCLUDE_DIR "${MSVC_LATEST}/include")
set(MSVC_LIB_DIR "${MSVC_LATEST}/lib/x64/enclave")

# Find the latest Windows SDK version dynamically
execute_process(
    COMMAND powershell -Command "
        $path = 'HKLM:\\SOFTWARE\\Microsoft\\Windows Kits\\Installed Roots';
        if (Test-Path $path) {
            Get-ItemProperty -Path $path | Select-Object -ExpandProperty KitsRoot10
        }
    "
    OUTPUT_VARIABLE WINDOWS_KITS_ROOT
    OUTPUT_STRIP_TRAILING_WHITESPACE
)

if (NOT WINDOWS_KITS_ROOT)
    message(FATAL_ERROR "Could not detect Windows Kits root path. Please ensure Windows SDK is installed.")
endif()

file(GLOB WINDOWS_KIT_VERSIONS LIST_DIRECTORIES true "${WINDOWS_KITS_ROOT}/Include/*")

if (WINDOWS_KIT_VERSIONS)
    list(SORT WINDOWS_KIT_VERSIONS COMPARE NATURAL ORDER DESCENDING)
    list(GET WINDOWS_KIT_VERSIONS 0 WINDOWS_KIT_LATEST)
    get_filename_component(WINDOWS_KIT_VERSION ${WINDOWS_KIT_LATEST} NAME)
else()
    message(FATAL_ERROR "No Windows SDK versions found in ${WINDOWS_KITS_ROOT}/Include/. Please check your installation.")
endif()

set(WINDOWS_INCLUDE_DIR "${WINDOWS_KITS_ROOT}/Include/${WINDOWS_KIT_VERSION}")
set(WINDOWS_LIB_DIR "${WINDOWS_KITS_ROOT}/Lib/${WINDOWS_KIT_VERSION}/um/x64")
set(WINDOWS_UCRT_LIB_DIR "${WINDOWS_KITS_ROOT}/Lib/${WINDOWS_KIT_VERSION}/ucrt_enclave/x64")

# Set include directories
target_include_directories(vbsenclave PRIVATE
    "${MSVC_INCLUDE_DIR}"
    "${WINDOWS_INCLUDE_DIR}/ucrt"
    "${WINDOWS_INCLUDE_DIR}/um"
    "${WINDOWS_INCLUDE_DIR}/shared"
    "${WINDOWS_INCLUDE_DIR}/winrt"
    "${WINDOWS_INCLUDE_DIR}/cppwinrt"
    "D:/VBSEnclave/AzureAttest/inc"
)

# Set library directories
target_link_libraries(vbsenclave PRIVATE
    "${MSVC_LIB_DIR}/libcmt.lib"
    "${MSVC_LIB_DIR}/libvcruntime.lib"
    "${WINDOWS_LIB_DIR}/bcrypt.lib"
    "${WINDOWS_LIB_DIR}/vertdll.lib"
    "${WINDOWS_UCRT_LIB_DIR}/ucrt.lib"
    "D:/VBSEnclave/AzureAttest/lib/AzureAttest.lib"
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
    COMMAND "C:/Program Files (x86)/Windows Kits/10/bin/10.0.26100.0/x64/veiid.exe" "${CMAKE_BINARY_DIR}/attestation/vbsenclave.dll"
    COMMENT "Applying VEIID Protection"
)

string(REPLACE "/RTC1" "" CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG}")
string(REPLACE "/RTC1" "" CMAKE_CXX_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG}")
set (CMAKE_SHARED_LINKER_FLAGS_DEBUG "/DEBUG /INCREMENTAL:NO" CACHE STRING "Overriding default debug ${flag_type} linker flags." FORCE)