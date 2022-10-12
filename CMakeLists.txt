# Copyright (c) Microsoft Corporation. All rights reserved.
# SPDX-License-Identifier: MIT

cmake_minimum_required (VERSION 3.12)

set(VCPKG_OVERLAY_PORTS "${CMAKE_CURRENT_LIST_DIR}/cmake-modules/overlay-ports")

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake-modules")
include(AzureVcpkg)
az_vcpkg_integrate()

project(samples)

find_program(NUGET_EXE NAMES nuget)

if(NOT NUGET_EXE)
    message(FATAL "CMake could not find the nuget command line tool. Please install it from https://www.nuget.org/downloads!")
else()
    exec_program(${NUGET_EXE}
        ARGS install "Microsoft.Attestation.Client" -Version 0.1.181 -ExcludeVersion -OutputDirectory ${CMAKE_BINARY_DIR}/packages)
endif()

add_subdirectory(attestation)
