# libSubnetCalculator

Modern C++ 17 library for calculating IPv4 and IPv6 subnetworks. It allows for , , getting 

## Features:
 - Dividing (Both IPv4 and IPv6) networks into separate same-sized subnetworks (eg. 192.168.0.0/24 to 192.168.0.0/25 and 192.168.0.128/25).
 - Calculating number of hosts in a network
 - Getting IPv4's classful architecture class names
 - Coverting CIDR mask to '.' notation mask
 - Simple IP formatted string to decimal conversions
 - Getting n-th host form network
 - Calculating IPv4's network address, broadcast address, mask and host count
 - Calculating IPv6's networking prefix, CIDR mask and host count
 - uint128 to std::string
 - std::string to uint128
 - Converting IPv6 from std::string in format described in section 2.2 of RFC 4291
 - Converting std::string in format described in section 2.2 of RFC 4291 to IPv6 address
 - Converting IPv4 from std::string in '.' notation
 - Converting std::string in '.' notation to IPv4 address

## Requirements
 - CMake 3.20
 - C++ 17
 - GCC 4.1 or later/clang with __uint128_t type (ONLY AVALIABLE ON 64-bit TARGETS; MSVC IS NOT SUPPORTED)