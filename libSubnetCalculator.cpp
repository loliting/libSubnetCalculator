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

#include <libSubnetCalculator.hpp>

#include <cmath>


using namespace libSubnetCalculator;


IPv4Address::IPv4Address()
{

}

IPv4Address::IPv4Address(std::string str) {
    struct in_addr tmp = { 0 };
    if(inet_pton(AF_INET, str.c_str(), &tmp) < 1)
        throw InvalidAddressException();
    m_decimal = ntohl(tmp.s_addr);
}

std::string IPv4Address::toString() {
    size_t tmp_size = INET_ADDRSTRLEN + 1;
    char tmp[tmp_size];
    tmp[INET_ADDRSTRLEN] = '\0';
    IPv4Addr tmpAddr = htonl(m_decimal);
    inet_ntop(AF_INET, &tmpAddr, tmp, tmp_size);
    return std::string(tmp);
}

IPv4Address::Class IPv4Address::getClass() {
    if(m_decimal < (IPv4Addr)2147483648U) // 128.0.0.0
        return A;
    if(m_decimal < (IPv4Addr)3221225472U) // 192.0.0.0
        return B;
    if(m_decimal < (IPv4Addr)3758096384U) // 224.0.0.0
        return C;
    if(m_decimal < (IPv4Addr)4026531840U) // 240.0.0.0
        return D;
    return E;
}

IPv4Address IPv4Address::fromSetBits(uint8_t bits) {
    if(bits > 32)
        throw InvalidAddressException();
    if(bits == 32)
        return IPv4Address(~(uint32_t)0u);
    return IPv4Address(~(~(IPv4Addr)0 >> bits));
}

IPv6Address::IPv6Address()
{
    
}

IPv6Address::IPv6Address(std::string str) {
    IPv6Addr tmp = { 0 };
    if(inet_pton(AF_INET6, str.c_str(), &tmp) < 1)
        throw InvalidAddressException();

    m_address.dWords[0] = ntohl(tmp.dWords[3]);
    m_address.dWords[1] = ntohl(tmp.dWords[2]);
    m_address.dWords[2] = ntohl(tmp.dWords[1]);
    m_address.dWords[3] = ntohl(tmp.dWords[0]);
}

std::string IPv6Address::toString() {
    size_t tmp_size = INET6_ADDRSTRLEN + 1;
    char tmp[tmp_size];
    tmp[INET6_ADDRSTRLEN] = '\0';
    IPv6Addr tmpAddr = m_address;
    tmpAddr.dWords[0] = htonl(m_address.dWords[3]);
    tmpAddr.dWords[1] = htonl(m_address.dWords[2]);
    tmpAddr.dWords[2] = htonl(m_address.dWords[1]);
    tmpAddr.dWords[3] = htonl(m_address.dWords[0]);
    inet_ntop(AF_INET6, &tmpAddr, tmp, tmp_size);
    return std::string(tmp);
}

void IPv4Network::recalculate() {
    if(m_CIDR > 32)
        throw InvalidCIDRException();
    
    m_maskAddress = IPv4Address::fromSetBits(m_CIDR);
    if(m_CIDR <= 30) {
        m_hostCount = ~m_maskAddress.decimal() - 1;
        m_networkAddress.m_decimal = m_initAddress.decimal() & m_maskAddress.decimal();
        m_broadcastAddress.m_decimal = m_networkAddress.decimal() + ~m_maskAddress.decimal();
    }
    else {
        m_hostCount = (m_CIDR == 31) ? 2 : 1;
        m_broadcastAddress = 0;
        m_networkAddress = 0;
    }
}

IPv4Network::IPv4Network(IPv4Address ip, uint8_t CIDR) : m_initAddress(ip) {
    if(CIDR > 32)
        throw InvalidCIDRException();
    m_CIDR = CIDR;
    recalculate();
}

std::vector<IPv4Network> IPv4Network::getSubnets(uint32_t subnetCount) {
    if(subnetCount == 1)
        return std::vector<IPv4Network>(1, *this);
    if(m_CIDR > 32)
        throw InvalidCIDRException();
    double r = log2(subnetCount);
    
    if(fabs(ceil(r) - r) >= 0x1p-52)
        throw InvalidSubnetCountException();

    uint_fast8_t cidr = m_CIDR + round(r);
    if(cidr > 30)
        throw InvalidSubnetCountException();
    
    IPv4Address subnetMask = IPv4Address::fromSetBits(cidr);
    uint_fast32_t ipCount = pow(2, 32 - cidr);  
    uint_fast32_t hostCount = ipCount - 2;

    std::vector<IPv4Network> ans(subnetCount);

    for(int i = 0; i < subnetCount; ++i) {
        ans[i].m_CIDR = cidr;
        ans[i].m_maskAddress = subnetMask;
        ans[i].m_hostCount = hostCount;
        ans[i].m_networkAddress.m_decimal = m_networkAddress.decimal() + ipCount * i;
        ans[i].m_broadcastAddress.m_decimal = ans[i].m_networkAddress.m_decimal + ipCount - 1;
        ans[i].m_initAddress = ans[i].m_networkAddress;
    }
    return ans;
}

IPv4Address IPv4Network::host(uint32_t index) {
    if(index >= this->hostCount())
        throw InvalidAddressException();
    if(CIDR() <= 30)
        return IPv4Address(networkAddress().decimal() + index + 1);
    if(CIDR() == 31)
        return (m_initAddress.decimal() & subnetMask().decimal()) + index;
    return m_initAddress;
}

IPv6Network::IPv6Network(IPv6Address ip, uint8_t CIDR) {
    if(CIDR > 128)
        throw InvalidCIDRException();
    m_CIDR = CIDR;
    m_initAddress = ip;
    recalculate();
}

void IPv6Network::recalculate() {
    if(m_CIDR > 128)
        throw InvalidCIDRException();

    if(CIDR() == 128) {
        m_hostCount = 1;
        m_prefix.m_address.addr = 0u;
    }
    else {
        m_hostCount = CIDR() == 0 ? ~(uint128)0U : (~(uint128)0 >> CIDR());
        m_prefix.m_address.addr = m_initAddress.m_address.addr & ~m_hostCount;
    }    
}

std::string libSubnetCalculator::uint128toStdString(uint128 value) {
    char buffer[128] = { 0 };
    char* d = std::end(buffer) - 1;
    do {
        --d;
        *d = '0' + (value % 10);
        value /= 10;
    } while (value != 0);
    return std::string(d);
}

std::vector<IPv6Network> IPv6Network::getSubnets(uint64_t subnetCount) {
    if(subnetCount == 1)
        return std::vector<IPv6Network>(1, *this);
    if(m_CIDR > 128)
        throw InvalidCIDRException();
    double r = log2(subnetCount);
    
    if(fabs(ceil(r) - r) >= 0x1p-52)
        throw InvalidSubnetCountException();

    uint_fast8_t cidr = m_CIDR + round(r);
    if(cidr > 126)
        throw InvalidSubnetCountException();
    
    uint128 ipCount = (~(uint128)0 >> cidr) + 1;
    uint128 hostCount = ipCount - 1;

    std::vector<IPv6Network> ans(subnetCount);

    for(int i = 0; i < subnetCount; ++i) {
        ans[i].m_CIDR = cidr;
        ans[i].m_hostCount = hostCount;
        ans[i].m_prefix.m_address.addr = m_prefix.m_address.addr + (ipCount * (uint128)i);
        ans[i].m_initAddress = ans[i].m_prefix;
    }
    return ans;
}

IPv6Address IPv6Network::host(uint128 index){
    if(index >= this->hostCount())
        throw InvalidAddressException();
    if(CIDR() <= 127)
        return IPv6Address(m_prefix.m_address.addr + index + 1);
    return m_initAddress;
}

uint128 libSubnetCalculator::stdStringToUint128(const std::string &str){
    const char *s = str.c_str();
    const char *p = s;

    uint128 val = 0;

    while (*p >= '0' && *p <= '9') {
        val = (10 * val) + (*p - '0');
        p++;
    }
    return val;
}
