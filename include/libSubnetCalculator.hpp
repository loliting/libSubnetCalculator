// This file is part of libSubnetCalculator.
// Copyright (C) 2024 Karol Maksymowicz
//
// libSubnetCalculator is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; either version 2
// of the License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, If not,
// see <https://www.gnu.org/licenses/>.

#ifndef LIBSUBNETCALCULATOR_HPP
#define LIBSUBNETCALCULATOR_HPP

#include <cstdint>
#include <exception>
#include <string>
#include <vector>
#include <cinttypes>

#ifdef __WIN32
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif


namespace libSubnetCalculator{
    /* 128-bit unsigned int type */
    typedef __uint128_t uint128;

    // "Primitive" IPv4 address type
    typedef uint32_t IPv4Addr; 

    // "Primitive" IPv6 address type
    struct IPv6Addr {
        union {
            uint8_t bytes[16];
            uint16_t words[8];
            uint32_t dWords[4];
            uint64_t qWords[2];
            uint128 addr;
        };
    };
    
    /*
     * Custom function for converting uint128 to std::string as there is none
     * in the standard library
     */
    std::string uint128toStdString(uint128 value);

    /*
     * Custom function for converting std::string to uint128 as there is none
     * in the standard library
    */
    uint128 stdStringToUint128(const std::string &str);

    struct IPv4Network;

    struct IPv4Address{
        friend class IPv4Network;
    public:
        /*
         * This enumeration collects all class names of IPv4 as described by
         * classful network architecture.
         */
        enum Class{
            A, B, C, D, E
        };

        /* Empty Constructor (0.0.0.0) */
        IPv4Address();

        /*
         * Constructor for creating new `IPv4Address` from string. String should
         * be formatted using the '.' notation in following forms:
         * a.b.c.d
         * a.b.c
         * a.b
         * a
         * 
         * See manual for `net_pton` for further information on parsing behavior
         * of '.' notation for your target (it should be exactly the same
         * between platforms; Windows platform uses winsock2 for this).
         */
        IPv4Address(std::string str);

        /* Constructor from plain 32 bit decimal type (IPv4Addr typedef) */
        IPv4Address(IPv4Addr decimalIP) : m_decimal(decimalIP) { }

        /*
         * Converts `IPv4Address` class to string formatted in '.' notation
         * in a.b.c.d form
         */
        std::string toString();

        /*
         * Returns IPv4 address initializated from set bits from left. This can
         * be used for converting mask in CIDR notation to `IPv4Address` class.
         */
        static IPv4Address fromSetBits(uint8_t);

        /*
         * Returns a decimal (IPv4Addr typedef) representation of the
         * `IPv4Address` class.
         */
        inline IPv4Addr decimal() const { return m_decimal; }

        /*
         * Returns `IPv4Address`'s class name descibed by classful network
         * architecture
         */
        Class getClass();
    private:
        union{
            IPv4Addr m_decimal;
            uint8_t m_octets[4];
        };
    };

    struct IPv6Address{
        friend class IPv6Network;
    private:
        IPv6Addr m_address = { 0 };
    public:
        /* Empty constructor (::) */
        IPv6Address();

        /* Constructor from plain 128 bit decimal type */
        IPv6Address(uint128 decimal) { m_address.addr = decimal; }

        /*
         * Constructor for creating new `IPv6Address` from string. String should
         * be formatted as descibed in section 2.2 of RFC 4291
         * (https://www.rfc-editor.org/rfc/rfc4291#section-2.2).
         */
        IPv6Address(std::string str);

        /*
         * Converts `IPv6Address` class to string formatted as descibed in
         * section 2.2 of RFC 4291
         * (https://www.rfc-editor.org/rfc/rfc4291#section-2.2).
         */
        std::string toString();

        // Returns "primitive" IPv6 address. 
        inline IPv6Addr address() const { return m_address; }

        // Returns IPv6 address in decimal representation
        inline uint128 decimal() const { return m_address.addr; }
    };

    struct IPv4Network{
    private:
        /* Address that was used to initializate IPv4Network struct */
        IPv4Address m_initAddress;
        IPv4Address m_networkAddress;
        IPv4Address m_broadcastAddress;
        IPv4Address m_maskAddress;
        uint_fast8_t m_CIDR;
        uint_fast32_t m_hostCount;
    private:
        void recalculate();
    public:
        /* Empty constructor */
        IPv4Network() { };

        /*
        * Constructor for creating a new network based on specified ip address
        * and mask in CIDR format
        * 
        * @param ip IP address for the network to be based on
        * @param CIDR Mask of the network in CIDR format
        * 
        * @throw InvalidCIDRException
        */
        IPv4Network(IPv4Address ip, uint8_t CIDR);

        /*
         * Calculates a vector of unique subnets based on this one.
         *
         * @param subnetCount Number of subnets in the vector, this must be 
         *        a power of 2.
         * 
         * @throw InvalidSubnetCountException
         * 
         * @throw InvalidCIDRException
        */
        std::vector<IPv4Network> getSubnets(uint32_t subnetCount);

        /*
         * Returns address of specified host in the network

         * @param index index (0-based) of the host in this network 
         * 
         * @throws  InvalidAddressException
        */
        IPv4Address host(uint32_t index);
        
        // Returns network's network address
        inline IPv4Address networkAddress() const { return m_networkAddress; }

        // Returns network's broadcast address
        inline IPv4Address broadcastAddress() const { return m_broadcastAddress; }

        // Returns network's mask
        inline IPv4Address subnetMask() const { return m_maskAddress; }

        // Returns network's mask in CIDR format
        inline uint_fast8_t CIDR() const { return m_CIDR; }

        // Returns number of hosts in the network
        inline uint_fast32_t hostCount() const { return m_hostCount; }
    };

    struct IPv6Network{
    private:
        /* Address that was used to initializate IPv6Network struct */
        IPv6Address m_initAddress;
        IPv6Address m_prefix;
        uint_fast8_t m_CIDR;
        uint128 m_hostCount;
    private:
        void recalculate();
    public:
        /* Empty constructor */
        IPv6Network() { };

        /*
         * Constructor for creating a new network based on specified ip address
         * and mask in CIDR format
         * 
         * @param ip IP address for the network to be based on
         * @param CIDR Mask of the network in CIDR format
         * 
         * @throw InvalidCIDRException
         */
        IPv6Network(IPv6Address ip, uint8_t CIDR);

        /*
         * Calculates a vector of unique subnets based on this one.
         *
         * @param subnetCount Number of subnets in the vector, this must be 
         *        a power of 2.
         * 
         * @throw InvalidSubnetCountException
         * 
         * @throw InvalidCIDRException
         */
        std::vector<IPv6Network> getSubnets(uint64_t subnetCount);

        /*
         * Returns address of specified host in the network
         * @param index index (0-based) of the host in this network 
         * @throws InvalidAddressException
         */
        IPv6Address host(uint128 index);

        /*
         * Returns network's routing prefix (IPv6's equivalent of network
         * address)
         */
        inline IPv6Address routingPrefix() const { return m_prefix; }

        // Returns network's mask in CIDR format
        inline uint_fast8_t CIDR() const { return m_CIDR; }

        // Returns number of hosts in the network
        inline uint128 hostCount() const { return m_hostCount; }
    };

    /*
     * This class is an extension of `std::exception`. It is used as a base
     * class for all exceptions thrown by libSubnetCalculator's functions.
     */
    class libSubnetCalculatorException : std::exception {
    public:
        libSubnetCalculatorException(std::string what) noexcept { m_what = what; }

        virtual const char *what() const noexcept { return m_what.c_str(); }; 
        virtual ~libSubnetCalculatorException() noexcept { }
    private:
        std::string m_what;
    };

    /*
     * This exception is thrown when `IPv4Address` and `IPv6Address`
     * constructors are invoked with bad arguments (eg. IP's octet is higher
     * than 255).
     * 
     * `InvalidAddressException` can be also thrown by `host()`
     * members of `IPv4Network` and `IPv6Network` classes when supplied index
     * is higher than network's host count.
     */
    class InvalidAddressException : libSubnetCalculatorException {
    public:
        InvalidAddressException() noexcept : libSubnetCalculatorException(what()) { }

        const char *what() {
            return "Given address is invalid";
        }
    };

    /*
     * This exception is thrown when `IPv4Network` and `IPv6Network`
     * constructors are invoked with CIDR larger than 32 and 128 respectively.
     * 
     * `InvalidCIDRException` can be also theoretically thrown by `getSubnets()`
     * member of `IPv4Network` and `IPv6Network` when CIDR is larger than
     * 32 or 128, but that is impossible to archive because this would trigger
     * earlier exceptions in networks' constructors.
     */
    class InvalidCIDRException : libSubnetCalculatorException {
    public:
        InvalidCIDRException() noexcept : libSubnetCalculatorException(what()) { }

        const char *what(){
            return "Given mask in CIDR notation is invalid";
        }
    };

    // TODO: Implement a function returning maximum possible subnetworks 

    /*
     * This exception is thrown when `getSubnets()` members of `IPv4Network`
     * and `IPv6Network` classes are invoked with number of subnetworks that
     * is bigger than possibly calculable
     */
    class InvalidSubnetCountException : libSubnetCalculatorException {
    public:
        InvalidSubnetCountException() noexcept : libSubnetCalculatorException(what()) { }

        const char *what() const noexcept {
            return "Given subnet count is invalid (Subnet count should be a power of 2)";
        }
    };
}

#endif // LIBSUBNETCALCULATOR_HPP