# Copyright (c) Microsoft Corporation. All rights reserved.
# SPDX-License-Identifier: MIT

cmake_minimum_required(VERSION 3.29)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(VCPKG_OVERLAY_PORTS "${CMAKE_CURRENT_LIST_DIR}/cmake-modules/overlay-ports")

set(NUGET_VERSION "latest")

set(DOWNLOAD_NUGET_URL "https://dist.nuget.org/win-x86-commandline/${NUGET_VERSION}/nuget.exe")

unset(NUGET_EXE CACHE)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake-modules")
include(AzureVcpkg)
az_vcpkg_integrate()

project(samples)

find_program(NUGET_EXE NAMES nuget nuget.exe HINTS ${CMAKE_CURRENT_SOURCE_DIR})

if(NOT NUGET_EXE)
    file(DOWNLOAD ${DOWNLOAD_NUGET_URL} "${CMAKE_CURRENT_SOURCE_DIR}/nuget.exe")
    find_program(NUGET_EXE NAMES nuget nuget.exe HINTS ${CMAKE_CURRENT_SOURCE_DIR})
endif()

if(NOT NUGET_EXE)
    message(FATAL_ERROR "CMake could not find the nuget command line tool. Please install it from https://www.nuget.org/downloads and move it to ${CMAKE_CURRENT_SOURCE_DIR}!")
else()
    execute_process(
        COMMAND ${NUGET_EXE} install "Microsoft.Attestation.Client" -Version 0.1.181 -ExcludeVersion -OutputDirectory ${CMAKE_BINARY_DIR}/packages
        RESULT_VARIABLE NUGET_RESULT
        OUTPUT_VARIABLE NUGET_OUTPUT
        ERROR_VARIABLE NUGET_ERROR
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    )

    if(NUGET_RESULT)
        message(FATAL_ERROR "NuGet package installation failed: ${NUGET_ERROR}")
    else()
        message(STATUS "NuGet package installed successfully: ${NUGET_OUTPUT}")
    endif()
endif()

unset(DOTNET_EXE CACHE)
set(DOTNET_VERSION "9.0")
set(DOTNET_INSTALL_URL "https://dotnet.microsoft.com/en-us/download/dotnet/${DOTNET_VERSION}")

# Find dotnet.exe
find_program(DOTNET_EXE NAMES dotnet dotnet.exe)

# If not found, download and install it
if(NOT DOTNET_EXE)
    message(STATUS "Downloading .NET SDK ${DOTNET_VERSION}...")

    set(DOTNET_INSTALLER "${CMAKE_BINARY_DIR}/dotnet-installer.exe")
    
    # Download .NET installer
    file(DOWNLOAD 
        "https://download.visualstudio.microsoft.com/download/pr/50b4d70f-0dd8-4323-8b76-94b23fd32a3a/d6f065ac712214e8d9fa4bb1d0cbf74d/dotnet-sdk-${DOTNET_VERSION}-win-x64.exe" 
        ${DOTNET_INSTALLER}
        SHOW_PROGRESS
    )

    message(STATUS "Installing .NET SDK...")

    # Run the installer silently
    execute_process(
        COMMAND ${DOTNET_INSTALLER} /quiet /norestart
        RESULT_VARIABLE DOTNET_INSTALL_RESULT
        OUTPUT_VARIABLE DOTNET_INSTALL_OUTPUT
        ERROR_VARIABLE DOTNET_INSTALL_ERROR
    )

    if(DOTNET_INSTALL_RESULT)
        message(FATAL_ERROR "Failed to install .NET SDK: ${DOTNET_INSTALL_ERROR}")
    else()
        message(STATUS "Successfully installed .NET SDK.")
    endif()

    # Find dotnet.exe again after installation
    find_program(DOTNET_EXE NAMES dotnet dotnet.exe HINTS "$ENV{ProgramFiles}/dotnet" "$ENV{ProgramFiles(x86)}/dotnet")

    if(NOT DOTNET_EXE)
        message(FATAL_ERROR "dotnet.exe not found after installation. Ensure .NET SDK is installed and in your PATH.")
    else()
        message(STATUS "dotnet.exe found at: ${DOTNET_EXE}")
    endif()
endif()


if(NOT DOTNET_EXE)
    message(FATAL_ERROR "CMake could not find the dotnet command line tool. Please install .NET SDK from https://dotnet.microsoft.com/download and ensure it's in your PATH.")
else()
    # Install AzureSignTool as a .NET Global Tool
    execute_process(
        COMMAND ${DOTNET_EXE} tool install --global AzureSignTool
        RESULT_VARIABLE AZURESIGNTOOL_RESULT
        OUTPUT_VARIABLE AZURESIGNTOOL_OUTPUT
        ERROR_VARIABLE AZURESIGNTOOL_ERROR
    )

    if(AZURESIGNTOOL_RESULT)
        message(FATAL_ERROR "AzureSignTool installation failed: ${AZURESIGNTOOL_ERROR}")
    else()
        message(STATUS "AzureSignTool installed successfully: ${AZURESIGNTOOL_OUTPUT}")
    endif()
endif()

add_subdirectory(attestation)
add_subdirectory(enclave)
