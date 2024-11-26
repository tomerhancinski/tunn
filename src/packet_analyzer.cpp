#include "packet_analyzer.h"
#include <iostream>
#include <netinet/ip.h>     // For IPv4 header
#include <netinet/ip6.h>    // For IPv6 header
#include <netinet/tcp.h>    // For TCP header
#include <netinet/udp.h>    // For UDP header
#include <arpa/inet.h>      // For inet_ntop
#include <cstring>          // For memset


void PacketAnalyzer::analyzeAndLog(const uint8_t* packet, size_t length) {
    if (length < 1) {
        std::cout << "Packet is too small to analyze." << std::endl;
        return;
    }

    uint8_t version = (packet[0] >> 4); // Extract IP version
    switch (version) {
        case 4:
            handleIPv4(packet, length);
            break;
        case 6:
            handleIPv6(packet, length);
            break;
        default:
            std::cout << "Unknown IP version: " + std::to_string(version) << std::endl;
    }
}

void PacketAnalyzer::handleIPv4(const uint8_t* packet, size_t length) {
    if (length < sizeof(struct iphdr)) {
        std::cout << "Incomplete IPv4 packet." << std::endl;
        return;
    }

    const struct iphdr* ip_header = reinterpret_cast<const struct iphdr*>(packet);

    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip_header->saddr, src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &ip_header->daddr, dst_ip, INET_ADDRSTRLEN);

    std::string protocol = protocolToString(ip_header->protocol);

    std::cout << "IPv4 Packet:" << std::endl;
    std::cout << "  Source IP: " + std::string(src_ip) << std::endl;
    std::cout << "  Destination IP: " + std::string(dst_ip) << std::endl;
    std::cout << "  Protocol: " + protocol << std::endl;
    std::cout << "  Total Length: " + std::to_string(ntohs(ip_header->tot_len)) << std::endl;

    if (ip_header->protocol == IPPROTO_TCP && length >= ip_header->ihl * 4 + sizeof(struct tcphdr)) {
        const struct tcphdr* tcp_header = reinterpret_cast<const struct tcphdr*>(packet + ip_header->ihl * 4);
        std::cout << "  Source Port: " + std::to_string(ntohs(tcp_header->source)) << std::endl;
        std::cout << "  Destination Port: " + std::to_string(ntohs(tcp_header->dest)) << std::endl;
    } else if (ip_header->protocol == IPPROTO_UDP && length >= ip_header->ihl * 4 + sizeof(struct udphdr)) {
        const struct udphdr* udp_header = reinterpret_cast<const struct udphdr*>(packet + ip_header->ihl * 4);
        std::cout << "  Source Port: " + std::to_string(ntohs(udp_header->source)) << std::endl;
        std::cout << "  Destination Port: " + std::to_string(ntohs(udp_header->dest)) << std::endl;
    }
}

void PacketAnalyzer::handleIPv6(const uint8_t* packet, size_t length) {
    if (length < sizeof(struct ip6_hdr)) {
        std::cout << "Incomplete IPv6 packet." << std::endl;
        return;
    }

    const struct ip6_hdr* ip6_header = reinterpret_cast<const struct ip6_hdr*>(packet);

    char src_ip[INET6_ADDRSTRLEN];
    char dst_ip[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &ip6_header->ip6_src, src_ip, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, &ip6_header->ip6_dst, dst_ip, INET6_ADDRSTRLEN);

    std::cout << "IPv6 Packet:" << std::endl;
    std::cout << "  Source IP: " + std::string(src_ip) << std::endl;
    std::cout << "  Destination IP: " + std::string(dst_ip) << std::endl;
    std::cout << "  Next Header (Protocol): " + std::to_string(ip6_header->ip6_nxt) << std::endl;
    std::cout << "  Payload Length: " + std::to_string(ntohs(ip6_header->ip6_plen)) << std::endl;
}


std::string PacketAnalyzer::protocolToString(uint8_t protocol) {
    switch (protocol) {
        case IPPROTO_TCP: return "TCP";
        case IPPROTO_UDP: return "UDP";
        case IPPROTO_ICMP: return "ICMP";
        case IPPROTO_IPV6: return "IPv6";
        default: return "Unknown";
    }
}
