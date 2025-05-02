cmake_minimum_required(VERSION 3.14)
project(nayuki_crypto_module)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# pybind11 (installed or from submodule)
find_package(pybind11 REQUIRED)

# Include project headers
include_directories(${CMAKE_CURRENT_SOURCE_DIR})

# Add Python module
add_library(nayuki_crypto MODULE
    binding.cpp
    Sha256.cpp
    Sha512.cpp
    Sha256Hash.cpp
    Keccak256.cpp
    CurvePoint.cpp
    Uint256.cpp
    FieldInt.cpp
    Utils.cpp
)

# Ensure no "lib" prefix is added
set_target_properties(nayuki_crypto PROPERTIES PREFIX "")

# Link with pybind11
target_link_libraries(nayuki_crypto PRIVATE pybind11::module)
