cmake_minimum_required(VERSION 3.20)

add_library(libSubnetCalculator STATIC libSubnetCalculator.cpp)
target_include_directories(libSubnetCalculator PRIVATE include)
set_target_properties(libSubnetCalculator PROPERTIES
    PREFIX ""
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
)

if(WIN32)
    target_link_libraries(libSubnetCalculator ws2_32)
endif()
